import gleam/erlang/process
import gleam/http
import gleam/http/request
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import lote/auth.{Auth, Password}
import lote/auth/password
import lote/auth/session
import lote/auth/user
import lote/realtime/pubsub
import lote/test_helper
import lote/web/csrf
import lote/web/router
import wisp/simulate

fn extract_between(body: String, before: String, after: String) -> String {
  let assert Ok(#(_, rest)) = string.split_once(body, before)
  let assert Ok(#(value, _)) = string.split_once(rest, after)
  value
}

fn find_tag_containing(html_body: String, needle: String) -> String {
  let assert Ok(#(before, after)) = string.split_once(html_body, needle)
  let tag_start = case string.split(before, "<") {
    [] -> ""
    parts -> {
      let assert Ok(last) = list.last(parts)
      last
    }
  }
  let assert Ok(#(tag_end, _)) = string.split_once(after, ">")
  tag_start <> needle <> tag_end
}

fn extract_form_csrf_token(html_body: String) -> String {
  let tag =
    find_tag_containing(html_body, "name=\"" <> csrf.form_field_name <> "\"")
  extract_between(tag, "value=\"", "\"")
}

fn extract_meta_csrf_token(html_body: String) -> String {
  let tag = find_tag_containing(html_body, "name=\"csrf-token\"")
  extract_between(tag, "content=\"", "\"")
}

pub fn health_endpoint_returns_ok_test() {
  use tx <- test_helper.with_db
  let assert Ok(session_revocations) = pubsub.start()

  let auth_ctx =
    Auth(
      db: tx,
      secret_key_base: simulate.default_secret_key_base,
      methods: [],
      session_revocations:,
    )
  let req = simulate.request(http.Get, "/health")
  let resp = router.handle_request(req, auth_ctx)

  assert resp.status == 200
  assert simulate.read_body(resp) == "ok"
}

pub fn password_login_returns_404_when_adapter_disabled_test() {
  use tx <- test_helper.with_db
  let assert Ok(session_revocations) = pubsub.start()

  let auth_ctx =
    Auth(
      db: tx,
      secret_key_base: simulate.default_secret_key_base,
      methods: [],
      session_revocations:,
    )
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
  let assert Ok(session_revocations) = pubsub.start()

  let assert Ok(created) = user.create(tx, "Router User")
  let assert Ok(Nil) =
    password.create(tx, created.id, "router_user", "secretpass123")

  let secret = simulate.default_secret_key_base
  let auth_ctx =
    Auth(
      db: tx,
      secret_key_base: secret,
      methods: [Password],
      session_revocations:,
    )

  // Fetch login page to obtain CSRF cookie and embedded form token
  let login_page_req = simulate.browser_request(http.Get, "/auth/login")
  let login_page_resp = router.handle_request(login_page_req, auth_ctx)
  assert login_page_resp.status == 200
  let login_csrf = extract_form_csrf_token(simulate.read_body(login_page_resp))

  let login_req =
    simulate.browser_request(http.Post, "/auth/password/login")
    |> simulate.session(login_page_req, login_page_resp)
    |> simulate.form_body([
      #(csrf.form_field_name, login_csrf),
      #("login_id", "router_user"),
      #("password", "secretpass123"),
    ])
  let login_resp = router.handle_request(login_req, auth_ctx)

  assert login_resp.status == 303

  // Fetch index page after login (CSRF cookie was rotated on login)
  let index_req =
    simulate.browser_request(http.Get, "/")
    |> simulate.session(login_req, login_resp)
  let assert Some(active_session) =
    session.current_session(index_req, tx, secret)
  assert active_session.user == created

  let index_resp = router.handle_request(index_req, auth_ctx)
  assert index_resp.status == 200
  let logout_csrf = extract_meta_csrf_token(simulate.read_body(index_resp))
  assert logout_csrf != login_csrf

  let revocation_sub = process.new_subject()
  pubsub.subscribe(session_revocations, revocation_sub)

  let logout_req =
    simulate.browser_request(http.Post, "/auth/logout")
    |> simulate.session(index_req, index_resp)
    |> simulate.form_body([#(csrf.form_field_name, logout_csrf)])
  let logout_resp = router.handle_request(logout_req, auth_ctx)
  assert logout_resp.status == 303
  assert process.receive(revocation_sub, 100) == Ok(active_session.id)

  let after_req =
    simulate.browser_request(http.Get, "/")
    |> simulate.session(logout_req, logout_resp)
  assert session.current_user(after_req, tx, secret) == None
}

pub fn login_and_logout_reject_missing_token_or_cross_origin_test() {
  use tx <- test_helper.with_db
  let assert Ok(session_revocations) = pubsub.start()

  let assert Ok(created) = user.create(tx, "Csrf User")
  let assert Ok(Nil) =
    password.create(tx, created.id, "csrf_user", "secretpass123")

  let secret = simulate.default_secret_key_base
  let auth_ctx =
    Auth(
      db: tx,
      secret_key_base: secret,
      methods: [Password],
      session_revocations:,
    )

  let login_page_req = simulate.browser_request(http.Get, "/auth/login")
  let login_page_resp = router.handle_request(login_page_req, auth_ctx)
  let login_csrf = extract_form_csrf_token(simulate.read_body(login_page_resp))

  // Missing _csrf on login -> 403
  let missing_csrf_login =
    simulate.browser_request(http.Post, "/auth/password/login")
    |> simulate.session(login_page_req, login_page_resp)
    |> simulate.form_body([
      #("login_id", "csrf_user"),
      #("password", "secretpass123"),
    ])
  assert router.handle_request(missing_csrf_login, auth_ctx).status == 403

  // Cross-origin Origin header on login -> 400
  let cross_origin_login =
    simulate.browser_request(http.Post, "/auth/password/login")
    |> simulate.session(login_page_req, login_page_resp)
    |> request.set_header("origin", "https://evil.example")
    |> simulate.form_body([
      #(csrf.form_field_name, login_csrf),
      #("login_id", "csrf_user"),
      #("password", "secretpass123"),
    ])
  assert router.handle_request(cross_origin_login, auth_ctx).status == 400

  // Legitimate login succeeds
  let login_req =
    simulate.browser_request(http.Post, "/auth/password/login")
    |> simulate.session(login_page_req, login_page_resp)
    |> simulate.form_body([
      #(csrf.form_field_name, login_csrf),
      #("login_id", "csrf_user"),
      #("password", "secretpass123"),
    ])
  let login_resp = router.handle_request(login_req, auth_ctx)
  assert login_resp.status == 303

  // Logout without _csrf -> 403 and session remains active
  let missing_csrf_logout =
    simulate.browser_request(http.Post, "/auth/logout")
    |> simulate.session(login_req, login_resp)
    |> simulate.form_body([])
  assert router.handle_request(missing_csrf_logout, auth_ctx).status == 403

  // Logout with cross-origin Origin header -> 400 and session remains active
  let cross_origin_logout =
    simulate.browser_request(http.Post, "/auth/logout")
    |> simulate.session(login_req, login_resp)
    |> request.set_header("origin", "https://evil.example")
    |> simulate.form_body([])
  assert router.handle_request(cross_origin_logout, auth_ctx).status == 400

  let verify_session_req =
    simulate.browser_request(http.Get, "/")
    |> simulate.session(login_req, login_resp)
  assert session.current_user(verify_session_req, tx, secret) == Some(created)
}
