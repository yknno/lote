import gleam/dynamic/decode
import gleam/erlang/process
import gleam/http
import gleam/int
import gleam/option.{None, Some}
import gleam/time/duration
import gleam/time/timestamp
import gleeunit
import lote
import lote/auth.{Auth, Password}
import lote/auth/session
import lote/auth/user
import lote/db/post_repo
import lote/rate_limit
import lote/realtime/pubsub
import lote/test_helper
import lustre/server_component
import mist
import pog
import wisp
import wisp/simulate

pub fn main() -> Nil {
  gleeunit.main()
}

fn close_and_wait(state: lote.WsState, post_pubsub: pubsub.PubSub(a)) -> Nil {
  let mon = process.monitor(server_component.pid(state.component))
  lote.ws_close(state)
  let down_selector =
    process.new_selector()
    |> process.select_specific_monitor(mon, fn(down) { down })
  let assert Ok(_) = process.selector_receive(down_selector, 500)
  assert test_helper.wait_until(100, 5, fn() {
    pubsub.subscriber_count(post_pubsub) == 0
  })
}

pub fn ws_init_authenticated_subscribes_to_revocations_and_stops_on_revocation_test() {
  use tx <- test_helper.with_db
  let assert Ok(session_revocations) = pubsub.start()
  let assert Ok(post_pubsub) = pubsub.start()
  let assert Ok(created) = user.create(tx, "WsUser")

  let secret = "ws_test_secret_key_base_0123456789abcdefghijklmnopqrstuvwxyz"
  let auth_ctx =
    Auth(
      db: tx,
      secret_key_base: secret,
      methods: [Password],
      session_revocations:,
      rate_limiter: rate_limit.disabled(),
    )

  let login_req = simulate.browser_request(http.Post, "/auth/password/login")
  let assert Ok(login_resp) =
    session.create(wisp.ok(), login_req, tx, secret, created)

  let ws_req =
    simulate.browser_request(http.Get, "/ws")
    |> simulate.session(login_req, login_resp)

  let assert #(state, Some(selector)) =
    lote.ws_init(ws_req, tx, post_pubsub, auth_ctx)
  let assert Some(sid) = state.session_id
  assert pubsub.subscriber_count(session_revocations) == 1

  // Initial mount message is delivered through the selector
  let assert Ok(lote.ComponentMessage(mount_msg)) =
    process.selector_receive(selector, 500)
  let sent_frames = process.new_subject()
  assert lote.ws_handle_message(
      state,
      mist.Custom(lote.ComponentMessage(mount_msg)),
      fn(payload) { process.send(sent_frames, payload) },
    )
    == mist.continue(state)
  let assert Ok(_payload) = process.receive(sent_frames, 100)

  // Revoking a different session ID keeps the connection alive
  assert lote.ws_handle_message(
      state,
      mist.Custom(lote.SessionRevoked("other-session-id")),
      fn(_) { Nil },
    )
    == mist.continue(state)

  // Publishing revocation for this session ID delivers SessionRevoked and stops the WS
  pubsub.publish(session_revocations, sid)
  let assert Ok(revoked_msg) = process.selector_receive(selector, 500)
  assert revoked_msg == lote.SessionRevoked(sid)
  assert lote.ws_handle_message(state, mist.Custom(revoked_msg), fn(_) { Nil })
    == mist.stop()

  close_and_wait(state, post_pubsub)
}

pub fn ws_init_with_deleted_or_expired_session_unsubscribes_revocation_test() {
  use tx <- test_helper.with_db
  let assert Ok(session_revocations) = pubsub.start()
  let assert Ok(post_pubsub) = pubsub.start()
  let assert Ok(created) = user.create(tx, "StaleWsUser")

  let secret = "stale_ws_test_secret_key_base_0123456789abcdefghijklmnopqrstuv"
  let auth_ctx =
    Auth(
      db: tx,
      secret_key_base: secret,
      methods: [Password],
      session_revocations:,
      rate_limiter: rate_limit.disabled(),
    )

  let login_req = simulate.browser_request(http.Post, "/auth/password/login")
  let assert Ok(login_resp) =
    session.create(wisp.ok(), login_req, tx, secret, created)

  let ws_req =
    simulate.browser_request(http.Get, "/ws")
    |> simulate.session(login_req, login_resp)
  let assert Some(sid) = session.session_id(ws_req, secret)

  // Delete the session row in DB while the client still holds the signed cookie
  let assert Ok(_) =
    pog.query("DELETE FROM sessions WHERE id = $1")
    |> pog.parameter(pog.text(sid))
    |> pog.returning(decode.dynamic)
    |> pog.execute(tx)

  let assert #(state, Some(_selector)) =
    lote.ws_init(ws_req, tx, post_pubsub, auth_ctx)
  assert state.session_id == None
  assert test_helper.wait_until(100, 5, fn() {
    pubsub.subscriber_count(session_revocations) == 0
  })

  close_and_wait(state, post_pubsub)
}

pub fn ws_handle_message_ignores_malformed_json_and_stops_on_close_test() {
  use tx <- test_helper.with_db
  let assert Ok(session_revocations) = pubsub.start()
  let assert Ok(post_pubsub) = pubsub.start()

  let secret = "anon_ws_test_secret_key_base_0123456789abcdefghijklmnopqrstuv"
  let auth_ctx =
    Auth(
      db: tx,
      secret_key_base: secret,
      methods: [],
      session_revocations:,
      rate_limiter: rate_limit.disabled(),
    )

  let ws_req = simulate.browser_request(http.Get, "/ws")
  let assert #(state, Some(_selector)) =
    lote.ws_init(ws_req, tx, post_pubsub, auth_ctx)
  assert state.session_id == None
  assert pubsub.subscriber_count(session_revocations) == 0

  // Malformed JSON or binary frames do not crash the handler
  assert lote.ws_handle_message(state, mist.Text("{not valid json"), fn(_) {
      Nil
    })
    != mist.stop()
  assert lote.ws_handle_message(state, mist.Binary(<<1, 2, 3>>), fn(_) { Nil })
    != mist.stop()

  assert lote.ws_handle_message(state, mist.Closed, fn(_) { Nil })
    == mist.stop()
  assert lote.ws_handle_message(state, mist.Shutdown, fn(_) { Nil })
    == mist.stop()

  close_and_wait(state, post_pubsub)
}

pub fn ws_stops_when_session_expires_via_timer_and_blocks_text_frames_after_expiry_test() {
  use tx <- test_helper.with_db
  let assert Ok(session_revocations) = pubsub.start()
  let assert Ok(post_pubsub) = pubsub.start()
  let assert Ok(created) = user.create(tx, "ExpiringWsUser")

  let secret = "expiring_ws_test_secret_key_base_0123456789abcdefghijkl"
  let auth_ctx =
    Auth(
      db: tx,
      secret_key_base: secret,
      methods: [Password],
      session_revocations:,
      rate_limiter: rate_limit.disabled(),
    )

  let login_req = simulate.browser_request(http.Post, "/auth/password/login")
  let assert Ok(login_resp) =
    session.create(wisp.ok(), login_req, tx, secret, created)

  let ws_req =
    simulate.browser_request(http.Get, "/ws")
    |> simulate.session(login_req, login_resp)
  let assert Some(sid) = session.session_id(ws_req, secret)

  // Shorten the session lifetime so the WS expiry timer fires quickly
  let assert Ok(_) =
    pog.query(
      "UPDATE sessions SET expires_at = NOW() + INTERVAL '150 milliseconds' WHERE id = $1",
    )
    |> pog.parameter(pog.text(sid))
    |> pog.returning(decode.dynamic)
    |> pog.execute(tx)

  let assert #(state, Some(selector)) =
    lote.ws_init(ws_req, tx, post_pubsub, auth_ctx)
  assert state.session_id == Some(sid)
  let assert Some(_expires_at) = state.session_expires_at
  let assert Some(_timer) = state.expiry_timer

  // Drain initial mount message
  let assert Ok(lote.ComponentMessage(_)) =
    process.selector_receive(selector, 500)

  // Wait for the expiry timer to fire SessionExpired
  let assert Ok(expired_msg) = process.selector_receive(selector, 1000)
  assert expired_msg == lote.SessionExpired

  // Handling SessionExpired stops the WebSocket
  assert lote.ws_handle_message(state, mist.Custom(lote.SessionExpired), fn(_) {
      Nil
    })
    == mist.stop()

  // Even before SessionExpired is handled, incoming Text frames after expires_at
  // must stop the WebSocket without forwarding to the Lustre component
  let past = timestamp.subtract(timestamp.system_time(), duration.seconds(1))
  let expired_state = lote.WsState(..state, session_expires_at: Some(past))
  assert lote.ws_handle_message(
      expired_state,
      mist.Text(
        "{\"kind\":4,\"path\":\"0\t0\t1\t0\",\"name\":\"submit\",\"event\":{\"body\":\"should not post\"}}",
      ),
      fn(_) { Nil },
    )
    == mist.stop()
  assert post_repo.list_recent(tx, 10) == Ok([])

  // An early SessionExpired tick before expires_at re-arms the timer and continues
  let future = timestamp.add(timestamp.system_time(), duration.hours(2))
  let future_state = lote.WsState(..state, session_expires_at: Some(future))
  let next =
    lote.ws_handle_message(
      future_state,
      mist.Custom(lote.SessionExpired),
      fn(_) { Nil },
    )
  assert next != mist.stop()

  close_and_wait(state, post_pubsub)
}

pub fn ws_connect_and_frame_rate_limits_enforce_burst_and_close_flooding_client_test() {
  use tx <- test_helper.with_db
  let assert Ok(session_revocations) = pubsub.start()
  let assert Ok(post_pubsub) = pubsub.start()
  let secret = "ws_rl_secret_key_base_0123456789abcdefghijklmnopqrstuvwxyz"
  let assert Ok(rate_limiter) = rate_limit.start_memory(secret)

  // 1. WS handshake limit allows burst of 60 per IP, then limits the 61st
  let ip = "203.0.113.55"
  let _ =
    int.range(
      from: 1,
      to: lote.ws_connect_policy.burst + 1,
      with: Nil,
      run: fn(_, _) {
        let assert rate_limit.Allowed(_) =
          lote.check_ws_connect_limit(rate_limiter, ip)
        Nil
      },
    )
  let assert rate_limit.Limited(retry_after) =
    lote.check_ws_connect_limit(rate_limiter, ip)
  assert retry_after >= 1

  // Different IPv4 /32 is unaffected
  let assert rate_limit.Allowed(_) =
    lote.check_ws_connect_limit(rate_limiter, "203.0.113.56")

  // IPv6 handshakes rotating within the same /64 share a bucket; adjacent /64 does not
  let _ =
    int.range(
      from: 1,
      to: lote.ws_connect_policy.burst + 1,
      with: Nil,
      run: fn(_, n) {
        let assert rate_limit.Allowed(_) =
          lote.check_ws_connect_limit(
            rate_limiter,
            "2001:db8:cafe:1::" <> int.to_string(n),
          )
        Nil
      },
    )
  let assert rate_limit.Limited(_) =
    lote.check_ws_connect_limit(rate_limiter, "2001:db8:cafe:1:ffff::99")
  let assert rate_limit.Allowed(_) =
    lote.check_ws_connect_limit(rate_limiter, "2001:db8:cafe:2::1")

  // 2. Per-connection WS frame limit allows burst of 30 frames, then stops on 31st
  let auth_ctx =
    Auth(
      db: tx,
      secret_key_base: secret,
      methods: [],
      session_revocations:,
      rate_limiter:,
    )
  let ws_req = simulate.browser_request(http.Get, "/ws")
  let assert #(state0, Some(_selector)) =
    lote.ws_init(ws_req, tx, post_pubsub, auth_ctx)

  // Simulate 30 frames sent back-to-back (each advances frame_tat_ms)
  let state_at_limit =
    int.range(
      from: 1,
      to: lote.ws_frame_policy.burst + 1,
      with: state0,
      run: fn(st, _) {
        let #(_, next_tat) =
          rate_limit.check_gcra(
            st.frame_tat_ms,
            rate_limit.now_ms(),
            lote.ws_frame_policy,
          )
        lote.WsState(..st, frame_tat_ms: next_tat)
      },
    )

  // Next frame exceeds the per-connection burst and closes the WebSocket
  assert lote.ws_handle_message(
      state_at_limit,
      mist.Text("{not valid json"),
      fn(_) { Nil },
    )
    == mist.stop()
  assert lote.ws_handle_message(state_at_limit, mist.Binary(<<1, 2, 3>>), fn(_) {
      Nil
    })
    == mist.stop()

  close_and_wait(state0, post_pubsub)
  rate_limit.stop_memory(rate_limiter)
}
