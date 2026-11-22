import gleam/http
import gleam/option.{None, Some}
import lote/auth/session
import lote/auth/user
import lote/test_helper
import wisp
import wisp/simulate

pub fn create_verify_and_destroy_session_test() {
  use tx <- test_helper.with_db

  let assert Ok(created) = user.create(tx, "Session User")
  let secret = simulate.default_secret_key_base

  let req = simulate.browser_request(http.Post, "/auth/password/login")
  let assert Ok(resp) = session.create(wisp.ok(), req, tx, created)

  let authed_req =
    simulate.browser_request(http.Get, "/")
    |> simulate.session(req, resp)

  assert session.current_user(authed_req, tx, secret) == Some(created)

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
}
