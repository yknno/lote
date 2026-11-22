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
import lote/db/post_repo
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

  let secret =
    "custom_router_secret_key_base_0123456789abcdefghijklmnopqrstuvwxyz"
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

  let next_req =
    simulate.browser_request(http.Get, "/")
    |> simulate.session(login_req, login_resp)
  let assert Some(active_session) =
    session.current_session(next_req, tx, secret)
  assert active_session.user == created

  // CSRF token cookie is rotated on login
  let assert Ok(logout_csrf) = csrf.read_token(next_req, secret)
  assert logout_csrf != login_csrf

  let revocation_sub = process.new_subject()
  pubsub.subscribe(session_revocations, revocation_sub)

  let logout_req =
    simulate.browser_request(http.Post, "/auth/logout")
    |> simulate.session(login_req, login_resp)
    |> simulate.form_body([#(csrf.form_field_name, logout_csrf)])
  let logout_resp = router.handle_request(logout_req, auth_ctx)
  assert logout_resp.status == 303
  assert process.receive(revocation_sub, 100) == Ok(active_session.id)

  let after_req =
    simulate.browser_request(http.Get, "/")
    |> simulate.session(logout_req, logout_resp)
  assert session.current_user(after_req, tx, secret) == None
}

pub fn relogin_destroys_and_revokes_previous_session_test() {
  use tx <- test_helper.with_db
  let assert Ok(session_revocations) = pubsub.start()

  let assert Ok(alice) = user.create(tx, "Alice")
  let assert Ok(Nil) =
    password.create(tx, alice.id, "alice_relogin", "secretpass123")
  let assert Ok(bob) = user.create(tx, "Bob")
  let assert Ok(Nil) =
    password.create(tx, bob.id, "bob_relogin", "secretpass123")

  let secret = "relogin_secret_key_base_0123456789abcdefghijklmnopqrstuvwxyz"
  let auth_ctx =
    Auth(
      db: tx,
      secret_key_base: secret,
      methods: [Password],
      session_revocations:,
    )

  // First login as Alice
  let page1_req = simulate.browser_request(http.Get, "/auth/login")
  let page1_resp = router.handle_request(page1_req, auth_ctx)
  let csrf1 = extract_form_csrf_token(simulate.read_body(page1_resp))

  let login1_req =
    simulate.browser_request(http.Post, "/auth/password/login")
    |> simulate.session(page1_req, page1_resp)
    |> simulate.form_body([
      #(csrf.form_field_name, csrf1),
      #("login_id", "alice_relogin"),
      #("password", "secretpass123"),
    ])
  let login1_resp = router.handle_request(login1_req, auth_ctx)
  assert login1_resp.status == 303

  let alice_authed_req =
    simulate.browser_request(http.Get, "/")
    |> simulate.session(login1_req, login1_resp)
  let assert Some(alice_session) =
    session.current_session(alice_authed_req, tx, secret)
  assert alice_session.user == alice

  // Subscribe to session_revocations before re-logging in as Bob on the same browser session
  let revocation_sub = process.new_subject()
  pubsub.subscribe(session_revocations, revocation_sub)

  let page2_req =
    simulate.browser_request(http.Get, "/auth/login")
    |> simulate.session(login1_req, login1_resp)
  let page2_resp = router.handle_request(page2_req, auth_ctx)
  let csrf2 = extract_form_csrf_token(simulate.read_body(page2_resp))

  let login2_req =
    simulate.browser_request(http.Post, "/auth/password/login")
    |> simulate.session(page2_req, page2_resp)
    |> simulate.form_body([
      #(csrf.form_field_name, csrf2),
      #("login_id", "bob_relogin"),
      #("password", "secretpass123"),
    ])
  let login2_resp = router.handle_request(login2_req, auth_ctx)
  assert login2_resp.status == 303

  // Alice's previous session ID must be revoked via pubsub AND deleted from DB
  assert process.receive(revocation_sub, 100) == Ok(alice_session.id)
  assert session.current_session(alice_authed_req, tx, secret) == None

  // New session belongs to Bob with a distinct session ID
  let bob_authed_req =
    simulate.browser_request(http.Get, "/")
    |> simulate.session(login2_req, login2_resp)
  let assert Some(bob_session) =
    session.current_session(bob_authed_req, tx, secret)
  assert bob_session.user == bob
  assert bob_session.id != alice_session.id
}

pub fn failed_login_preserves_csrf_token_and_issues_no_session_test() {
  use tx <- test_helper.with_db
  let assert Ok(session_revocations) = pubsub.start()

  let assert Ok(created) = user.create(tx, "Fail Login User")
  let assert Ok(Nil) =
    password.create(tx, created.id, "fail_login_user", "secretpass123")

  let secret = "fail_login_secret_key_base_0123456789abcdefghijklmnopqrstuv"
  let auth_ctx =
    Auth(
      db: tx,
      secret_key_base: secret,
      methods: [Password],
      session_revocations:,
    )

  let page_req = simulate.browser_request(http.Get, "/auth/login")
  let page_resp = router.handle_request(page_req, auth_ctx)
  let csrf_token = extract_form_csrf_token(simulate.read_body(page_resp))

  // Wrong password returns 200 with error message and keeps the same CSRF token
  let bad_pass_req =
    simulate.browser_request(http.Post, "/auth/password/login")
    |> simulate.session(page_req, page_resp)
    |> simulate.form_body([
      #(csrf.form_field_name, csrf_token),
      #("login_id", "fail_login_user"),
      #("password", "wrongpass"),
    ])
  let bad_pass_resp = router.handle_request(bad_pass_req, auth_ctx)
  assert bad_pass_resp.status == 200
  let bad_pass_body = simulate.read_body(bad_pass_resp)
  assert string.contains(bad_pass_body, "ID またはパスワードが正しくありません")
  assert extract_form_csrf_token(bad_pass_body) == csrf_token

  let after_bad_pass_req =
    simulate.browser_request(http.Get, "/")
    |> simulate.session(bad_pass_req, bad_pass_resp)
  assert session.current_user(after_bad_pass_req, tx, secret) == None

  // Missing password field returns 200 with validation error
  let missing_field_req =
    simulate.browser_request(http.Post, "/auth/password/login")
    |> simulate.session(page_req, page_resp)
    |> simulate.form_body([
      #(csrf.form_field_name, csrf_token),
      #("login_id", "fail_login_user"),
    ])
  let missing_field_resp = router.handle_request(missing_field_req, auth_ctx)
  assert missing_field_resp.status == 200
  assert string.contains(simulate.read_body(missing_field_resp), "入力が不足しています")
}

pub fn login_and_logout_reject_missing_token_or_cross_origin_test() {
  use tx <- test_helper.with_db
  let assert Ok(session_revocations) = pubsub.start()

  let assert Ok(created) = user.create(tx, "Csrf User")
  let assert Ok(Nil) =
    password.create(tx, created.id, "csrf_user", "secretpass123")

  let secret = "csrf_router_secret_key_base_0123456789abcdefghijklmnopqrstuv"
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

  // Missing Origin and Referer on login strips cookies -> 403 Invalid CSRF token
  let no_origin_login =
    simulate.request(http.Post, "/auth/password/login")
    |> simulate.session(login_page_req, login_page_resp)
    |> simulate.form_body([
      #(csrf.form_field_name, login_csrf),
      #("login_id", "csrf_user"),
      #("password", "secretpass123"),
    ])
  assert router.handle_request(no_origin_login, auth_ctx).status == 403

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

pub fn get_post_permalink_renders_post_and_handles_missing_or_invalid_id_test() {
  use tx <- test_helper.with_db
  let assert Ok(session_revocations) = pubsub.start()

  let assert Ok(author) = user.create(tx, "Permalink Author")
  let assert Ok(created) =
    post_repo.create(tx, author.id, "Hello permalink world!")

  let auth_ctx =
    Auth(
      db: tx,
      secret_key_base: simulate.default_secret_key_base,
      methods: [],
      session_revocations:,
    )

  let ok_resp =
    simulate.browser_request(http.Get, "/posts/" <> created.id)
    |> router.handle_request(auth_ctx)
  assert ok_resp.status == 200
  let body = simulate.read_body(ok_resp)
  assert string.contains(body, "Permalink Author")
  assert string.contains(body, "Hello permalink world!")
  assert string.contains(body, created.id)
  assert string.contains(body, "<lote-time")
  assert string.contains(body, "/static/lote-time.js")

  // Unknown valid UUID -> 404
  let missing_resp =
    simulate.browser_request(
      http.Get,
      "/posts/00000000-0000-7000-8000-000000000000",
    )
    |> router.handle_request(auth_ctx)
  assert missing_resp.status == 404

  // Invalid non-UUID -> 404
  let invalid_resp =
    simulate.browser_request(http.Get, "/posts/not-a-uuid")
    |> router.handle_request(auth_ctx)
  assert invalid_resp.status == 404

  // Non-GET method -> 405
  let post_method_resp =
    simulate.browser_request(http.Post, "/posts/" <> created.id)
    |> router.handle_request(auth_ctx)
  assert post_method_resp.status == 405
}
