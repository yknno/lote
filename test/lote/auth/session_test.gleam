import gleam/crypto
import gleam/dynamic/decode
import gleam/erlang/process
import gleam/http
import gleam/http/request
import gleam/http/response
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import lote/auth/session
import lote/auth/session_cleanup
import lote/auth/user
import lote/realtime/pubsub
import lote/test_helper
import pog
import wisp
import wisp/simulate

pub fn create_verify_and_destroy_session_with_custom_secret_test() {
  use tx <- test_helper.with_db

  let assert Ok(created) = user.create(tx, "Session User")
  // Use a non-default secret_key_base to verify session.create signs cookies
  // with the provided secret rather than simulate.default_secret_key_base.
  let secret =
    "custom_session_secret_key_base_0123456789abcdefghijklmnopqrstuvwxyz"

  let req = simulate.browser_request(http.Post, "/auth/password/login")
  let assert Ok(resp) = session.create(wisp.ok(), req, tx, secret, created)

  let assert Ok(set_cookie_header) = response.get_header(resp, "set-cookie")
  assert string.starts_with(
    set_cookie_header,
    session.secure_cookie_name <> "=",
  )
  assert string.contains(set_cookie_header, "Secure")
  assert string.contains(set_cookie_header, "HttpOnly")
  assert string.contains(set_cookie_header, "Path=/")
  assert !string.contains(string.lowercase(set_cookie_header), "domain=")

  let authed_req =
    simulate.browser_request(http.Get, "/")
    |> simulate.session(req, resp)

  assert session.current_user(authed_req, tx, secret) == Some(created)
  // Verifying with a different secret must fail
  assert session.current_user(authed_req, tx, simulate.default_secret_key_base)
    == None

  // Subdomain cookie-tossing defense: unprefixed lote_session_id is rejected on HTTPS
  let assert Some(sid) = session.session_id(authed_req, secret)
  let signed_sid =
    crypto.sign_message(<<sid:utf8>>, <<secret:utf8>>, crypto.Sha512)
  let tossed_req =
    simulate.browser_request(http.Get, "/")
    |> request.set_cookie(session.cookie_name, signed_sid)
  assert session.session_id(tossed_req, secret) == None
  assert session.current_user(tossed_req, tx, secret) == None

  let logout_req =
    simulate.browser_request(http.Post, "/auth/logout")
    |> simulate.session(req, resp)
  let logout_resp = session.destroy(wisp.ok(), logout_req, tx, secret)

  // Session row is deleted from DB, so even replaying the old cookie fails
  assert session.current_user(authed_req, tx, secret) == None

  let after_logout_req =
    simulate.browser_request(http.Get, "/")
    |> simulate.session(logout_req, logout_resp)
  assert session.current_user(after_logout_req, tx, secret) == None
  assert session.session_id(after_logout_req, secret) == None
}

pub fn expired_session_is_rejected_test() {
  use tx <- test_helper.with_db

  let assert Ok(created) = user.create(tx, "Expired Session User")
  let secret = "expired_session_secret_key_base_0123456789abcdef"

  let req = simulate.browser_request(http.Post, "/auth/password/login")
  let assert Ok(resp) = session.create(wisp.ok(), req, tx, secret, created)

  let authed_req =
    simulate.browser_request(http.Get, "/")
    |> simulate.session(req, resp)
  let assert Some(sid) = session.session_id(authed_req, secret)

  // Force the session row to be expired in PostgreSQL
  let assert Ok(_) =
    pog.query(
      "UPDATE sessions SET expires_at = NOW() - INTERVAL '1 second' WHERE id = $1",
    )
    |> pog.parameter(pog.text(sid))
    |> pog.returning(decode.dynamic)
    |> pog.execute(tx)

  assert session.current_session(authed_req, tx, secret) == None
  assert session.current_user(authed_req, tx, secret) == None
}

pub fn empty_or_tampered_session_cookie_is_rejected_test() {
  use tx <- test_helper.with_db

  let secret = "tampered_session_secret_key_base_0123456789abcdef"
  let empty_signed =
    crypto.sign_message(<<"":utf8>>, <<secret:utf8>>, crypto.Sha512)

  // A validly signed empty string (e.g. if Max-Age=0 cookie is replayed)
  // must not be treated as a candidate session ID.
  let empty_cookie_req =
    simulate.browser_request(http.Get, "/")
    |> request.set_cookie(session.secure_cookie_name, empty_signed)
  assert session.session_id(empty_cookie_req, secret) == None
  assert session.current_session(empty_cookie_req, tx, secret) == None

  // Tampered signature is rejected
  let tampered_req =
    simulate.browser_request(http.Get, "/")
    |> request.set_cookie(
      session.secure_cookie_name,
      empty_signed <> "tampered",
    )
  assert session.session_id(tampered_req, secret) == None
  assert session.current_session(tampered_req, tx, secret) == None
}

pub fn list_and_revoke_sessions_uses_uuidv4_public_id_and_enforces_ownership_test() {
  use tx <- test_helper.with_db

  let assert Ok(alice) = user.create(tx, "Alice")
  let assert Ok(bob) = user.create(tx, "Bob")
  let secret = "list_revoke_secret_key_base_0123456789abcdefghijklmnop"

  let req1 =
    simulate.browser_request(http.Post, "/auth/password/login")
    |> request.set_header(
      "user-agent",
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/130.0",
    )
  let assert Ok(resp1) = session.create(wisp.ok(), req1, tx, secret, alice)
  let authed1 =
    simulate.browser_request(http.Get, "/")
    |> simulate.session(req1, resp1)
  let assert Some(sid1) = session.session_id(authed1, secret)

  let req2 =
    simulate.browser_request(http.Post, "/auth/password/login")
    |> request.set_header(
      "user-agent",
      "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Firefox/131.0",
    )
  let assert Ok(resp2) = session.create(wisp.ok(), req2, tx, secret, alice)
  let authed2 =
    simulate.browser_request(http.Get, "/")
    |> simulate.session(req2, resp2)
  let assert Some(sid2) = session.session_id(authed2, secret)

  let req3 = simulate.browser_request(http.Post, "/auth/password/login")
  let assert Ok(resp3) = session.create(wisp.ok(), req3, tx, secret, alice)
  let authed3 =
    simulate.browser_request(http.Get, "/")
    |> simulate.session(req3, resp3)
  let assert Some(sid3) = session.session_id(authed3, secret)

  // Expired session must be excluded from active list
  let expired_req = simulate.browser_request(http.Post, "/auth/password/login")
  let assert Ok(expired_resp) =
    session.create(wisp.ok(), expired_req, tx, secret, alice)
  let expired_authed =
    simulate.browser_request(http.Get, "/")
    |> simulate.session(expired_req, expired_resp)
  let assert Some(expired_sid) = session.session_id(expired_authed, secret)
  let assert Ok(_) =
    pog.query(
      "UPDATE sessions SET expires_at = NOW() - INTERVAL '1 minute' WHERE id = $1",
    )
    |> pog.parameter(pog.text(expired_sid))
    |> pog.returning(decode.dynamic)
    |> pog.execute(tx)

  // Bob's session must not appear in Alice's list
  let bob_req = simulate.browser_request(http.Post, "/auth/password/login")
  let assert Ok(_bob_resp) = session.create(wisp.ok(), bob_req, tx, secret, bob)

  let assert Ok(active_list) = session.list_active_for_user(tx, alice.id, sid1)
  assert list.length(active_list) == 3

  // Every public_id is a valid 36-char UUIDv4 (version nibble '4' at index 14)
  // and distinct from the raw internal session IDs
  list.each(active_list, fn(info) {
    assert string.length(info.public_id) == 36
    assert string.slice(info.public_id, at_index: 14, length: 1) == "4"
    assert info.public_id != sid1
    assert info.public_id != sid2
    assert info.public_id != sid3
  })

  assert list.count(active_list, fn(info) { info.is_current }) == 1
  let assert Ok(current_info) =
    list.find(active_list, fn(info) { info.is_current })
  assert string.contains(current_info.user_agent, "Chrome/130.0")

  let assert Ok(firefox_info) =
    list.find(active_list, fn(info) {
      string.contains(info.user_agent, "Firefox/131.0")
    })

  // Bob cannot revoke Alice's session
  assert session.revoke_by_public_id(tx, firefox_info.public_id, bob.id)
    == Ok(None)
  // Invalid UUID returns Ok(None) without DB error
  assert session.revoke_by_public_id(tx, "not-a-uuid", alice.id) == Ok(None)

  // Alice revokes her Firefox session (uppercase UUID normalized cleanly)
  assert session.revoke_by_public_id(
      tx,
      string.uppercase(firefox_info.public_id),
      alice.id,
    )
    == Ok(Some(sid2))
  assert session.current_session(authed2, tx, secret) == None

  // Alice revokes all remaining other sessions (sid3 + expired_sid), keeping sid1 intact
  let assert Ok(revoked_others) = session.revoke_others(tx, alice.id, sid1)
  assert list.length(revoked_others) == 2
  assert list.contains(revoked_others, sid3)
  assert list.contains(revoked_others, expired_sid)
  assert session.current_session(authed3, tx, secret) == None
  assert session.current_user(authed1, tx, secret) == Some(alice)
}

pub fn delete_expired_respects_batch_limit_and_keeps_active_sessions_test() {
  use tx <- test_helper.with_db

  let assert Ok(alice) = user.create(tx, "CleanupAlice")
  let secret = "cleanup_batch_secret_key_base_0123456789abcdefghijklmn"

  // Create 1 active session and 3 expired sessions
  let active_req = simulate.browser_request(http.Post, "/auth/password/login")
  let assert Ok(active_resp) =
    session.create(wisp.ok(), active_req, tx, secret, alice)
  let active_authed =
    simulate.browser_request(http.Get, "/")
    |> simulate.session(active_req, active_resp)

  let expired_ids =
    list.map([1, 2, 3], fn(_) {
      let req = simulate.browser_request(http.Post, "/auth/password/login")
      let assert Ok(resp) = session.create(wisp.ok(), req, tx, secret, alice)
      let authed =
        simulate.browser_request(http.Get, "/")
        |> simulate.session(req, resp)
      let assert Some(sid) = session.session_id(authed, secret)
      let assert Ok(_) =
        pog.query(
          "UPDATE sessions SET expires_at = NOW() - INTERVAL '1 minute' WHERE id = $1",
        )
        |> pog.parameter(pog.text(sid))
        |> pog.returning(decode.dynamic)
        |> pog.execute(tx)
      sid
    })

  // Zero or negative limit deletes nothing
  assert session.delete_expired(tx, 0) == Ok([])

  // Batch limit 2 deletes 2 of the 3 expired rows
  let assert Ok(first_batch) = session.delete_expired(tx, 2)
  assert list.length(first_batch) == 2

  // Second call deletes the remaining 1 expired row
  let assert Ok(second_batch) = session.delete_expired(tx, 2)
  assert list.length(second_batch) == 1

  let deleted_all = list.append(first_batch, second_batch)
  list.each(expired_ids, fn(id) {
    assert list.contains(deleted_all, id)
  })

  // Third call finds nothing left, while the active session remains valid
  assert session.delete_expired(tx, 10) == Ok([])
  assert session.current_user(active_authed, tx, secret) == Some(alice)
}

pub fn session_cleanup_runs_periodically_and_publishes_revocations_test() {
  use tx <- test_helper.with_db

  let assert Ok(alice) = user.create(tx, "PeriodicCleanupAlice")
  let secret = "periodic_cleanup_secret_key_base_0123456789abcdefghijk"
  let assert Ok(revocations) = pubsub.start()
  let rev_sub = process.new_subject()
  pubsub.subscribe(revocations, rev_sub)

  // Create 3 expired sessions and 1 active session
  let active_req = simulate.browser_request(http.Post, "/auth/password/login")
  let assert Ok(active_resp) =
    session.create(wisp.ok(), active_req, tx, secret, alice)
  let active_authed =
    simulate.browser_request(http.Get, "/")
    |> simulate.session(active_req, active_resp)

  let expired_ids =
    list.map([1, 2, 3], fn(_) {
      let req = simulate.browser_request(http.Post, "/auth/password/login")
      let assert Ok(resp) = session.create(wisp.ok(), req, tx, secret, alice)
      let authed =
        simulate.browser_request(http.Get, "/")
        |> simulate.session(req, resp)
      let assert Some(sid) = session.session_id(authed, secret)
      let assert Ok(_) =
        pog.query(
          "UPDATE sessions SET expires_at = NOW() - INTERVAL '5 minutes' WHERE id = $1",
        )
        |> pog.parameter(pog.text(sid))
        |> pog.returning(decode.dynamic)
        |> pog.execute(tx)
      sid
    })

  // Start periodic cleanup with a small batch size (2) and short interval (30ms)
  let assert Ok(started) = session_cleanup.start(tx, revocations, 30, 2)

  // All 3 expired session IDs are deleted across 2 batches and published to revocations
  let assert Ok(r1) = process.receive(rev_sub, 500)
  let assert Ok(r2) = process.receive(rev_sub, 500)
  let assert Ok(r3) = process.receive(rev_sub, 500)
  let notified = [r1, r2, r3]
  list.each(expired_ids, fn(id) {
    assert list.contains(notified, id)
  })

  // Stop the actor cleanly before transaction rollback
  let mon = process.monitor(started.pid)
  session_cleanup.stop(started.data)
  let down_selector =
    process.new_selector()
    |> process.select_specific_monitor(mon, fn(down) { down })
  let assert Ok(_) = process.selector_receive(down_selector, 500)

  // DB has no expired rows remaining and active session is untouched
  assert session.delete_expired(tx, 10) == Ok([])
  assert session.current_user(active_authed, tx, secret) == Some(alice)
}
