import gleam/http
import gleam/option.{None, Some}
import lote/auth.{Auth, Password}
import lote/auth/password
import lote/auth/session
import lote/auth/user
import lote/test_helper
import lote/web/router
import wisp/simulate

pub fn health_endpoint_returns_ok_test() {
  use tx <- test_helper.with_db

  let auth_ctx =
    Auth(db: tx, secret_key_base: simulate.default_secret_key_base, methods: [])
  let req = simulate.request(http.Get, "/health")
  let resp = router.handle_request(req, auth_ctx)

  assert resp.status == 200
  assert simulate.read_body(resp) == "ok"
}

pub fn password_login_returns_404_when_adapter_disabled_test() {
  use tx <- test_helper.with_db

  let auth_ctx =
    Auth(db: tx, secret_key_base: simulate.default_secret_key_base, methods: [])
  let req =
    simulate.browser_request(http.Post, "/auth/password/login")
    |> simulate.form_body([
      #("login_id", "alice"),
      #("password", "password1234"),
    ])
  let resp = router.handle_request(req, auth_ctx)

  assert resp.status == 404
}

pub fn password_login_issues_session_cookie_when_enabled_test() {
  use tx <- test_helper.with_db

  let assert Ok(created) = user.create(tx, "Router User")
  let assert Ok(Nil) =
    password.create(tx, created.id, "router_user", "secretpass123")

  let secret = simulate.default_secret_key_base
  let auth_ctx = Auth(db: tx, secret_key_base: secret, methods: [Password])

  let login_req =
    simulate.browser_request(http.Post, "/auth/password/login")
    |> simulate.form_body([
      #("login_id", "router_user"),
      #("password", "secretpass123"),
    ])
  let login_resp = router.handle_request(login_req, auth_ctx)

  assert login_resp.status == 303

  let next_req =
    simulate.browser_request(http.Get, "/")
    |> simulate.session(login_req, login_resp)
  assert session.current_user(next_req, tx, secret) == Some(created)

  let logout_req =
    simulate.browser_request(http.Post, "/auth/logout")
    |> simulate.session(login_req, login_resp)
  let logout_resp = router.handle_request(logout_req, auth_ctx)
  assert logout_resp.status == 303

  let after_req =
    simulate.browser_request(http.Get, "/")
    |> simulate.session(logout_req, logout_resp)
  assert session.current_user(after_req, tx, secret) == None
}
