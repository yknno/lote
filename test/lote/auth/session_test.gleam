import gleam/crypto
import gleam/dynamic/decode
import gleam/http
import gleam/http/request
import gleam/option.{None, Some}
import lote/auth/session
import lote/auth/user
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

  let authed_req =
    simulate.browser_request(http.Get, "/")
    |> simulate.session(req, resp)

  assert session.current_user(authed_req, tx, secret) == Some(created)
  // Verifying with a different secret must fail
  assert session.current_user(authed_req, tx, simulate.default_secret_key_base)
    == None

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
    |> request.set_cookie("lote_session_id", empty_signed)
  assert session.session_id(empty_cookie_req, secret) == None
  assert session.current_session(empty_cookie_req, tx, secret) == None

  // Tampered signature is rejected
  let tampered_req =
    simulate.browser_request(http.Get, "/")
    |> request.set_cookie("lote_session_id", empty_signed <> "tampered")
  assert session.session_id(tampered_req, secret) == None
  assert session.current_session(tampered_req, tx, secret) == None
}
