import gleam/dynamic/decode
import gleam/erlang/process
import gleam/http
import gleam/option.{None, Some}
import gleeunit
import lote
import lote/auth.{Auth, Password}
import lote/auth/session
import lote/auth/user
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
    Auth(db: tx, secret_key_base: secret, methods: [], session_revocations:)

  let ws_req = simulate.browser_request(http.Get, "/ws")
  let assert #(state, Some(_selector)) =
    lote.ws_init(ws_req, tx, post_pubsub, auth_ctx)
  assert state.session_id == None
  assert pubsub.subscriber_count(session_revocations) == 0

  // Malformed JSON or binary frames do not crash the handler
  assert lote.ws_handle_message(state, mist.Text("{not valid json"), fn(_) {
      Nil
    })
    == mist.continue(state)
  assert lote.ws_handle_message(state, mist.Binary(<<1, 2, 3>>), fn(_) { Nil })
    == mist.continue(state)

  assert lote.ws_handle_message(state, mist.Closed, fn(_) { Nil })
    == mist.stop()
  assert lote.ws_handle_message(state, mist.Shutdown, fn(_) { Nil })
    == mist.stop()

  close_and_wait(state, post_pubsub)
}
