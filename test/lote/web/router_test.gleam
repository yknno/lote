import gleam/erlang/process
import gleam/http
import gleam/http/request
import gleam/http/response
import gleam/int
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import lote/auth.{Auth, Password}
import lote/auth/password
import lote/auth/session
import lote/auth/user
import lote/db/post_repo
import lote/rate_limit
import lote/realtime/pubsub
import lote/test_helper
import lote/web/auth/password_handler
import lote/web/client_ip
import lote/web/components/timeline
import lote/web/csrf
import lote/web/http_rate_limit
import lote/web/router
import wisp
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
  let assert Ok(post_pubsub) = pubsub.start()

  let auth_ctx =
    Auth(
      db: tx,
      secret_key_base: simulate.default_secret_key_base,
      methods: [],
      session_revocations:,
      rate_limiter: rate_limit.disabled(),
    )
  let req = simulate.request(http.Get, "/health")
  let resp = router.handle_request(req, auth_ctx, post_pubsub)

  assert resp.status == 200
  assert simulate.read_body(resp) == "ok"
}

pub fn password_login_returns_404_when_adapter_disabled_test() {
  use tx <- test_helper.with_db
  let assert Ok(session_revocations) = pubsub.start()
  let assert Ok(post_pubsub) = pubsub.start()

  let auth_ctx =
    Auth(
      db: tx,
      secret_key_base: simulate.default_secret_key_base,
      methods: [],
      session_revocations:,
      rate_limiter: rate_limit.disabled(),
    )
  let req =
    simulate.browser_request(http.Post, "/auth/password/login")
    |> simulate.form_body([
      #("login_id", "alice"),
      #("password", "password1234"),
    ])
  let resp = router.handle_request(req, auth_ctx, post_pubsub)

  assert resp.status == 404
}

pub fn password_login_issues_session_cookie_when_enabled_test() {
  use tx <- test_helper.with_db
  let assert Ok(session_revocations) = pubsub.start()
  let assert Ok(post_pubsub) = pubsub.start()

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
      rate_limiter: rate_limit.disabled(),
    )

  // Fetch login page to obtain CSRF cookie and embedded form token
  let login_page_req = simulate.browser_request(http.Get, "/auth/login")
  let login_page_resp =
    router.handle_request(login_page_req, auth_ctx, post_pubsub)
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
  let login_resp = router.handle_request(login_req, auth_ctx, post_pubsub)

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
  let logout_resp = router.handle_request(logout_req, auth_ctx, post_pubsub)
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
  let assert Ok(post_pubsub) = pubsub.start()

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
      rate_limiter: rate_limit.disabled(),
    )

  // First login as Alice
  let page1_req = simulate.browser_request(http.Get, "/auth/login")
  let page1_resp = router.handle_request(page1_req, auth_ctx, post_pubsub)
  let csrf1 = extract_form_csrf_token(simulate.read_body(page1_resp))

  let login1_req =
    simulate.browser_request(http.Post, "/auth/password/login")
    |> simulate.session(page1_req, page1_resp)
    |> simulate.form_body([
      #(csrf.form_field_name, csrf1),
      #("login_id", "alice_relogin"),
      #("password", "secretpass123"),
    ])
  let login1_resp = router.handle_request(login1_req, auth_ctx, post_pubsub)
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
  let page2_resp = router.handle_request(page2_req, auth_ctx, post_pubsub)
  let csrf2 = extract_form_csrf_token(simulate.read_body(page2_resp))

  let login2_req =
    simulate.browser_request(http.Post, "/auth/password/login")
    |> simulate.session(page2_req, page2_resp)
    |> simulate.form_body([
      #(csrf.form_field_name, csrf2),
      #("login_id", "bob_relogin"),
      #("password", "secretpass123"),
    ])
  let login2_resp = router.handle_request(login2_req, auth_ctx, post_pubsub)
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
  let assert Ok(post_pubsub) = pubsub.start()

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
      rate_limiter: rate_limit.disabled(),
    )

  let page_req = simulate.browser_request(http.Get, "/auth/login")
  let page_resp = router.handle_request(page_req, auth_ctx, post_pubsub)
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
  let bad_pass_resp = router.handle_request(bad_pass_req, auth_ctx, post_pubsub)
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
  let missing_field_resp =
    router.handle_request(missing_field_req, auth_ctx, post_pubsub)
  assert missing_field_resp.status == 200
  assert string.contains(simulate.read_body(missing_field_resp), "入力が不足しています")
}

pub fn login_and_logout_reject_missing_token_or_cross_origin_test() {
  use tx <- test_helper.with_db
  let assert Ok(session_revocations) = pubsub.start()
  let assert Ok(post_pubsub) = pubsub.start()

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
      rate_limiter: rate_limit.disabled(),
    )

  let login_page_req = simulate.browser_request(http.Get, "/auth/login")
  let login_page_resp =
    router.handle_request(login_page_req, auth_ctx, post_pubsub)
  let login_csrf = extract_form_csrf_token(simulate.read_body(login_page_resp))

  // Missing _csrf on login -> 403
  let missing_csrf_login =
    simulate.browser_request(http.Post, "/auth/password/login")
    |> simulate.session(login_page_req, login_page_resp)
    |> simulate.form_body([
      #("login_id", "csrf_user"),
      #("password", "secretpass123"),
    ])
  assert router.handle_request(missing_csrf_login, auth_ctx, post_pubsub).status
    == 403

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
  assert router.handle_request(cross_origin_login, auth_ctx, post_pubsub).status
    == 400

  // Missing Origin and Referer on login strips cookies -> 403 Invalid CSRF token
  let no_origin_login =
    simulate.request(http.Post, "/auth/password/login")
    |> simulate.session(login_page_req, login_page_resp)
    |> simulate.form_body([
      #(csrf.form_field_name, login_csrf),
      #("login_id", "csrf_user"),
      #("password", "secretpass123"),
    ])
  assert router.handle_request(no_origin_login, auth_ctx, post_pubsub).status
    == 403

  // Legitimate login succeeds
  let login_req =
    simulate.browser_request(http.Post, "/auth/password/login")
    |> simulate.session(login_page_req, login_page_resp)
    |> simulate.form_body([
      #(csrf.form_field_name, login_csrf),
      #("login_id", "csrf_user"),
      #("password", "secretpass123"),
    ])
  let login_resp = router.handle_request(login_req, auth_ctx, post_pubsub)
  assert login_resp.status == 303

  // Logout without _csrf -> 403 and session remains active
  let missing_csrf_logout =
    simulate.browser_request(http.Post, "/auth/logout")
    |> simulate.session(login_req, login_resp)
    |> simulate.form_body([])
  assert router.handle_request(missing_csrf_logout, auth_ctx, post_pubsub).status
    == 403

  // Logout with cross-origin Origin header -> 400 and session remains active
  let cross_origin_logout =
    simulate.browser_request(http.Post, "/auth/logout")
    |> simulate.session(login_req, login_resp)
    |> request.set_header("origin", "https://evil.example")
    |> simulate.form_body([])
  assert router.handle_request(cross_origin_logout, auth_ctx, post_pubsub).status
    == 400

  let verify_session_req =
    simulate.browser_request(http.Get, "/")
    |> simulate.session(login_req, login_resp)
  assert session.current_user(verify_session_req, tx, secret) == Some(created)
}

pub fn get_post_permalink_renders_post_and_handles_missing_or_invalid_id_test() {
  use tx <- test_helper.with_db
  let assert Ok(session_revocations) = pubsub.start()
  let assert Ok(post_pubsub) = pubsub.start()

  let assert Ok(author) = user.create(tx, "Permalink Author")
  let assert Ok(created) =
    post_repo.create(tx, author.id, "Hello permalink world!")

  let auth_ctx =
    Auth(
      db: tx,
      secret_key_base: simulate.default_secret_key_base,
      methods: [],
      session_revocations:,
      rate_limiter: rate_limit.disabled(),
    )

  let ok_resp =
    simulate.browser_request(http.Get, "/posts/" <> created.id)
    |> router.handle_request(auth_ctx, post_pubsub)
  assert ok_resp.status == 200
  let body = simulate.read_body(ok_resp)
  assert string.contains(body, "Permalink Author")
  assert string.contains(body, "Hello permalink world!")
  assert string.contains(body, created.id)
  assert string.contains(body, "<lote-time")
  assert string.contains(body, "/static/lote-time.js")
  assert !string.contains(body, "/posts/" <> created.id <> "/delete")

  // Unknown valid UUID -> 404
  let missing_resp =
    simulate.browser_request(
      http.Get,
      "/posts/00000000-0000-7000-8000-000000000000",
    )
    |> router.handle_request(auth_ctx, post_pubsub)
  assert missing_resp.status == 404

  // Invalid non-UUID -> 404
  let invalid_resp =
    simulate.browser_request(http.Get, "/posts/not-a-uuid")
    |> router.handle_request(auth_ctx, post_pubsub)
  assert invalid_resp.status == 404

  // Non-GET method -> 405
  let post_method_resp =
    simulate.browser_request(http.Post, "/posts/" <> created.id)
    |> router.handle_request(auth_ctx, post_pubsub)
  assert post_method_resp.status == 405
}

pub fn post_delete_route_enforces_csrf_auth_and_ownership_and_broadcasts_test() {
  use tx <- test_helper.with_db
  let assert Ok(session_revocations) = pubsub.start()
  let assert Ok(post_pubsub) = pubsub.start()
  let post_sub = process.new_subject()
  pubsub.subscribe(post_pubsub, post_sub)

  let assert Ok(alice) = user.create(tx, "Alice")
  let assert Ok(Nil) =
    password.create(tx, alice.id, "alice_del", "secretpass123")
  let assert Ok(bob) = user.create(tx, "Bob")
  let assert Ok(Nil) = password.create(tx, bob.id, "bob_del", "secretpass123")
  let assert Ok(created) =
    post_repo.create(tx, alice.id, "Alice post to delete")

  let secret = "delete_router_secret_key_base_0123456789abcdefghijklmnopqrstuv"
  let auth_ctx =
    Auth(
      db: tx,
      secret_key_base: secret,
      methods: [Password],
      session_revocations:,
      rate_limiter: rate_limit.disabled(),
    )

  let delete_path = "/posts/" <> created.id <> "/delete"

  // Non-POST method on /posts/:id/delete -> 405
  let get_delete_resp =
    simulate.browser_request(http.Get, delete_path)
    |> router.handle_request(auth_ctx, post_pubsub)
  assert get_delete_resp.status == 405

  // Unauthenticated POST with valid CSRF token -> 401
  let anon_page_req = simulate.browser_request(http.Get, "/auth/login")
  let anon_page_resp =
    router.handle_request(anon_page_req, auth_ctx, post_pubsub)
  let anon_csrf = extract_form_csrf_token(simulate.read_body(anon_page_resp))
  let unauth_delete_resp =
    simulate.browser_request(http.Post, delete_path)
    |> simulate.session(anon_page_req, anon_page_resp)
    |> simulate.form_body([#(csrf.form_field_name, anon_csrf)])
    |> router.handle_request(auth_ctx, post_pubsub)
  assert unauth_delete_resp.status == 401

  // Log in as Bob (non-owner)
  let bob_login_req =
    simulate.browser_request(http.Post, "/auth/password/login")
    |> simulate.session(anon_page_req, anon_page_resp)
    |> simulate.form_body([
      #(csrf.form_field_name, anon_csrf),
      #("login_id", "bob_del"),
      #("password", "secretpass123"),
    ])
  let bob_login_resp =
    router.handle_request(bob_login_req, auth_ctx, post_pubsub)
  assert bob_login_resp.status == 303

  // Bob viewing Alice's permalink does not see the delete form
  let bob_view_req =
    simulate.browser_request(http.Get, "/posts/" <> created.id)
    |> simulate.session(bob_login_req, bob_login_resp)
  let bob_view_resp = router.handle_request(bob_view_req, auth_ctx, post_pubsub)
  assert bob_view_resp.status == 200
  assert !string.contains(simulate.read_body(bob_view_resp), delete_path)

  // Bob attempting POST /posts/:id/delete with his valid CSRF token -> 404
  let assert Ok(bob_csrf) = csrf.read_token(bob_view_req, secret)
  let bob_delete_resp =
    simulate.browser_request(http.Post, delete_path)
    |> simulate.session(bob_login_req, bob_login_resp)
    |> simulate.form_body([#(csrf.form_field_name, bob_csrf)])
    |> router.handle_request(auth_ctx, post_pubsub)
  assert bob_delete_resp.status == 404
  let assert Ok(Some(_)) = post_repo.find_by_id(tx, created.id)

  // Log in as Alice (owner)
  let alice_page_req = simulate.browser_request(http.Get, "/auth/login")
  let alice_page_resp =
    router.handle_request(alice_page_req, auth_ctx, post_pubsub)
  let alice_login_csrf =
    extract_form_csrf_token(simulate.read_body(alice_page_resp))
  let alice_login_req =
    simulate.browser_request(http.Post, "/auth/password/login")
    |> simulate.session(alice_page_req, alice_page_resp)
    |> simulate.form_body([
      #(csrf.form_field_name, alice_login_csrf),
      #("login_id", "alice_del"),
      #("password", "secretpass123"),
    ])
  let alice_login_resp =
    router.handle_request(alice_login_req, auth_ctx, post_pubsub)
  assert alice_login_resp.status == 303

  // Alice viewing her own permalink sees the delete form with CSRF token
  let alice_view_req =
    simulate.browser_request(http.Get, "/posts/" <> created.id)
    |> simulate.session(alice_login_req, alice_login_resp)
  let alice_view_resp =
    router.handle_request(alice_view_req, auth_ctx, post_pubsub)
  assert alice_view_resp.status == 200
  let alice_view_body = simulate.read_body(alice_view_resp)
  assert string.contains(alice_view_body, delete_path)
  let alice_delete_csrf = extract_form_csrf_token(alice_view_body)

  // Missing _csrf token -> 403 and post remains intact
  let missing_csrf_resp =
    simulate.browser_request(http.Post, delete_path)
    |> simulate.session(alice_view_req, alice_view_resp)
    |> simulate.form_body([])
    |> router.handle_request(auth_ctx, post_pubsub)
  assert missing_csrf_resp.status == 403
  let assert Ok(Some(_)) = post_repo.find_by_id(tx, created.id)

  // Valid owner delete -> 303 redirect to /, PubSub Deleted event, DB row gone
  let ok_delete_resp =
    simulate.browser_request(http.Post, delete_path)
    |> simulate.session(alice_view_req, alice_view_resp)
    |> simulate.form_body([#(csrf.form_field_name, alice_delete_csrf)])
    |> router.handle_request(auth_ctx, post_pubsub)
  assert ok_delete_resp.status == 303
  assert process.receive(post_sub, 100) == Ok(timeline.Deleted(created.id))
  assert post_repo.find_by_id(tx, created.id) == Ok(None)

  // Permalink now returns 404
  let after_delete_resp =
    simulate.browser_request(http.Get, "/posts/" <> created.id)
    |> router.handle_request(auth_ctx, post_pubsub)
  assert after_delete_resp.status == 404
}

pub fn dynamic_and_error_routes_return_no_store_cache_control_test() {
  use tx <- test_helper.with_db
  let assert Ok(session_revocations) = pubsub.start()
  let assert Ok(post_pubsub) = pubsub.start()

  let assert Ok(author) = user.create(tx, "CacheAuthor")
  let assert Ok(created) = post_repo.create(tx, author.id, "cache test post")

  let auth_ctx =
    Auth(
      db: tx,
      secret_key_base: simulate.default_secret_key_base,
      methods: [Password],
      session_revocations:,
      rate_limiter: rate_limit.disabled(),
    )

  // GET / -> no-store
  let index_resp =
    simulate.browser_request(http.Get, "/")
    |> router.handle_request(auth_ctx, post_pubsub)
  assert index_resp.status == 200
  assert response.get_header(index_resp, "cache-control") == Ok("no-store")

  // GET /posts/:id -> no-store
  let post_resp =
    simulate.browser_request(http.Get, "/posts/" <> created.id)
    |> router.handle_request(auth_ctx, post_pubsub)
  assert post_resp.status == 200
  assert response.get_header(post_resp, "cache-control") == Ok("no-store")

  // GET /auth/login -> no-store
  let login_resp =
    simulate.browser_request(http.Get, "/auth/login")
    |> router.handle_request(auth_ctx, post_pubsub)
  assert login_resp.status == 200
  assert response.get_header(login_resp, "cache-control") == Ok("no-store")

  // GET /health -> no-store
  let health_resp =
    simulate.request(http.Get, "/health")
    |> router.handle_request(auth_ctx, post_pubsub)
  assert health_resp.status == 200
  assert response.get_header(health_resp, "cache-control") == Ok("no-store")

  // 404 Not Found -> no-store
  let not_found_resp =
    simulate.browser_request(http.Get, "/does-not-exist")
    |> router.handle_request(auth_ctx, post_pubsub)
  assert not_found_resp.status == 404
  assert response.get_header(not_found_resp, "cache-control") == Ok("no-store")

  // 405 Method Not Allowed -> no-store
  let method_not_allowed_resp =
    simulate.browser_request(http.Post, "/posts/" <> created.id)
    |> router.handle_request(auth_ctx, post_pubsub)
  assert method_not_allowed_resp.status == 405
  assert response.get_header(method_not_allowed_resp, "cache-control")
    == Ok("no-store")

  // 400 Cross-origin CSRF rejection -> no-store
  let csrf_400_resp =
    simulate.browser_request(http.Post, "/auth/logout")
    |> request.set_header("origin", "https://evil.example")
    |> router.handle_request(auth_ctx, post_pubsub)
  assert csrf_400_resp.status == 400
  assert response.get_header(csrf_400_resp, "cache-control") == Ok("no-store")
}

pub fn static_assets_return_public_no_cache_with_etag_and_errors_return_no_store_test() {
  use tx <- test_helper.with_db
  let assert Ok(session_revocations) = pubsub.start()
  let assert Ok(post_pubsub) = pubsub.start()

  let auth_ctx =
    Auth(
      db: tx,
      secret_key_base: simulate.default_secret_key_base,
      methods: [],
      session_revocations:,
      rate_limiter: rate_limit.disabled(),
    )

  // GET existing static file -> 200 + public, no-cache + ETag
  let static_resp =
    simulate.request(http.Get, "/static/lote-time.js")
    |> router.handle_request(auth_ctx, post_pubsub)
  assert static_resp.status == 200
  assert response.get_header(static_resp, "cache-control")
    == Ok("public, no-cache")
  let assert Ok(etag) = response.get_header(static_resp, "etag")

  // Conditional GET with matching If-None-Match -> 304 + public, no-cache + ETag
  let revalidated_resp =
    simulate.request(http.Get, "/static/lote-time.js")
    |> request.set_header("if-none-match", etag)
    |> router.handle_request(auth_ctx, post_pubsub)
  assert revalidated_resp.status == 304
  assert response.get_header(revalidated_resp, "cache-control")
    == Ok("public, no-cache")
  assert response.get_header(revalidated_resp, "etag") == Ok(etag)

  // HEAD existing static file -> 200 + public, no-cache
  let head_resp =
    simulate.request(http.Head, "/static/lote-time.js")
    |> router.handle_request(auth_ctx, post_pubsub)
  assert head_resp.status == 200
  assert response.get_header(head_resp, "cache-control")
    == Ok("public, no-cache")

  // Missing static file -> 404 + no-store
  let missing_static_resp =
    simulate.request(http.Get, "/static/does-not-exist.js")
    |> router.handle_request(auth_ctx, post_pubsub)
  assert missing_static_resp.status == 404
  assert response.get_header(missing_static_resp, "cache-control")
    == Ok("no-store")

  // Invalid Range header on static file -> 400 + no-store
  let bad_range_resp =
    simulate.request(http.Get, "/static/lote-time.js")
    |> request.set_header("range", "bytes=invalid")
    |> router.handle_request(auth_ctx, post_pubsub)
  assert bad_range_resp.status == 400
  assert response.get_header(bad_range_resp, "cache-control") == Ok("no-store")
}

pub fn sessions_routes_list_and_revoke_with_csrf_ownership_and_pubsub_test() {
  use tx <- test_helper.with_db
  let assert Ok(session_revocations) = pubsub.start()
  let assert Ok(post_pubsub) = pubsub.start()
  let revocation_sub = process.new_subject()
  pubsub.subscribe(session_revocations, revocation_sub)

  let assert Ok(alice) = user.create(tx, "Alice")
  let assert Ok(Nil) =
    password.create(tx, alice.id, "alice_sess", "secretpass123")
  let assert Ok(bob) = user.create(tx, "Bob")
  let assert Ok(Nil) = password.create(tx, bob.id, "bob_sess", "secretpass123")

  let secret = "sessions_router_secret_key_base_0123456789abcdefghijklmnop"
  let auth_ctx =
    Auth(
      db: tx,
      secret_key_base: secret,
      methods: [Password],
      session_revocations:,
      rate_limiter: rate_limit.disabled(),
    )

  // Unauthenticated GET /sessions -> 303 redirect to /auth/login + no-store
  let anon_sessions_resp =
    simulate.browser_request(http.Get, "/sessions")
    |> router.handle_request(auth_ctx, post_pubsub)
  assert anon_sessions_resp.status == 303
  assert response.get_header(anon_sessions_resp, "location")
    == Ok("/auth/login")
  assert response.get_header(anon_sessions_resp, "cache-control")
    == Ok("no-store")

  // Method not allowed checks -> 405
  assert router.handle_request(
      simulate.browser_request(http.Post, "/sessions"),
      auth_ctx,
      post_pubsub,
    ).status
    == 405
  assert router.handle_request(
      simulate.browser_request(http.Get, "/sessions/revoke-others"),
      auth_ctx,
      post_pubsub,
    ).status
    == 405

  // Helper: log in a browser session with a custom User-Agent
  let login_as = fn(login_id: String, ua: String) {
    let page_req = simulate.browser_request(http.Get, "/auth/login")
    let page_resp = router.handle_request(page_req, auth_ctx, post_pubsub)
    let token = extract_form_csrf_token(simulate.read_body(page_resp))
    let req =
      simulate.browser_request(http.Post, "/auth/password/login")
      |> simulate.session(page_req, page_resp)
      |> request.set_header("user-agent", ua)
      |> simulate.form_body([
        #(csrf.form_field_name, token),
        #("login_id", login_id),
        #("password", "secretpass123"),
      ])
    let resp = router.handle_request(req, auth_ctx, post_pubsub)
    assert resp.status == 303
    #(req, resp)
  }

  let #(a1_req, a1_resp) =
    login_as("alice_sess", "Mozilla/5.0 (Macintosh) Chrome/130.0")
  let #(a2_req, a2_resp) =
    login_as("alice_sess", "Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0")
  let #(a3_req, a3_resp) = login_as("alice_sess", "curl/8.5.0")
  let #(bob_req, bob_resp) =
    login_as("bob_sess", "Mozilla/5.0 (Windows NT 10.0) Edg/130.0")

  let a1_check =
    simulate.browser_request(http.Get, "/")
    |> simulate.session(a1_req, a1_resp)
  let assert Some(a1_sid) = session.session_id(a1_check, secret)
  let a2_check =
    simulate.browser_request(http.Get, "/")
    |> simulate.session(a2_req, a2_resp)
  let assert Some(a2_sid) = session.session_id(a2_check, secret)
  let a3_check =
    simulate.browser_request(http.Get, "/")
    |> simulate.session(a3_req, a3_resp)
  let assert Some(a3_sid) = session.session_id(a3_check, secret)

  // Alice views /sessions from device 1
  let list_req =
    simulate.browser_request(http.Get, "/sessions")
    |> simulate.session(a1_req, a1_resp)
  let list_resp = router.handle_request(list_req, auth_ctx, post_pubsub)
  assert list_resp.status == 200
  assert response.get_header(list_resp, "cache-control") == Ok("no-store")
  let list_body = simulate.read_body(list_resp)
  assert string.contains(list_body, "3 active sessions")
  assert string.contains(list_body, "Chrome on macOS")
  assert string.contains(list_body, "Firefox on Linux")
  assert string.contains(list_body, "curl")
  assert string.contains(list_body, "Current")
  assert string.contains(list_body, "/sessions/revoke-others")
  // Raw internal session IDs must NEVER appear in the rendered HTML
  assert !string.contains(list_body, a1_sid)
  assert !string.contains(list_body, a2_sid)
  assert !string.contains(list_body, a3_sid)

  let assert Ok(alice_sessions) =
    session.list_active_for_user(tx, alice.id, a1_sid)
  let assert Ok(a2_info) =
    list.find(alice_sessions, fn(s) {
      string.contains(s.user_agent, "Firefox/131.0")
    })
  let assert Ok(a1_info) = list.find(alice_sessions, fn(s) { s.is_current })
  let a2_revoke_path = "/sessions/" <> a2_info.public_id <> "/revoke"
  assert string.contains(list_body, a2_revoke_path)

  let alice_csrf = extract_form_csrf_token(list_body)

  // Missing CSRF on revoke -> 403
  let no_csrf_resp =
    simulate.browser_request(http.Post, a2_revoke_path)
    |> simulate.session(list_req, list_resp)
    |> simulate.form_body([])
    |> router.handle_request(auth_ctx, post_pubsub)
  assert no_csrf_resp.status == 403

  // Unauthenticated POST with valid CSRF cookie -> 401
  let anon_page_req = simulate.browser_request(http.Get, "/auth/login")
  let anon_page_resp =
    router.handle_request(anon_page_req, auth_ctx, post_pubsub)
  let anon_csrf = extract_form_csrf_token(simulate.read_body(anon_page_resp))
  let unauth_revoke_resp =
    simulate.browser_request(http.Post, a2_revoke_path)
    |> simulate.session(anon_page_req, anon_page_resp)
    |> simulate.form_body([#(csrf.form_field_name, anon_csrf)])
    |> router.handle_request(auth_ctx, post_pubsub)
  assert unauth_revoke_resp.status == 401

  // Bob cannot revoke Alice's session -> 404
  let bob_list_req =
    simulate.browser_request(http.Get, "/sessions")
    |> simulate.session(bob_req, bob_resp)
  let bob_list_resp = router.handle_request(bob_list_req, auth_ctx, post_pubsub)
  let bob_csrf = extract_form_csrf_token(simulate.read_body(bob_list_resp))
  let bob_revoke_resp =
    simulate.browser_request(http.Post, a2_revoke_path)
    |> simulate.session(bob_list_req, bob_list_resp)
    |> simulate.form_body([#(csrf.form_field_name, bob_csrf)])
    |> router.handle_request(auth_ctx, post_pubsub)
  assert bob_revoke_resp.status == 404
  assert session.current_user(a2_check, tx, secret) == Some(alice)

  // Alice revokes device 2 -> 303 to /sessions, publishes a2_sid to PubSub, invalidates a2
  let revoke_one_resp =
    simulate.browser_request(http.Post, a2_revoke_path)
    |> simulate.session(list_req, list_resp)
    |> simulate.form_body([#(csrf.form_field_name, alice_csrf)])
    |> router.handle_request(auth_ctx, post_pubsub)
  assert revoke_one_resp.status == 303
  assert response.get_header(revoke_one_resp, "location") == Ok("/sessions")
  assert process.receive(revocation_sub, 100) == Ok(a2_sid)
  assert session.current_user(a2_check, tx, secret) == None
  assert session.current_user(a1_check, tx, secret) == Some(alice)

  // Alice revokes all other sessions -> publishes a3_sid, leaves only a1 active
  let revoke_others_resp =
    simulate.browser_request(http.Post, "/sessions/revoke-others")
    |> simulate.session(list_req, list_resp)
    |> simulate.form_body([#(csrf.form_field_name, alice_csrf)])
    |> router.handle_request(auth_ctx, post_pubsub)
  assert revoke_others_resp.status == 303
  assert response.get_header(revoke_others_resp, "location") == Ok("/sessions")
  assert process.receive(revocation_sub, 100) == Ok(a3_sid)
  assert session.current_user(a3_check, tx, secret) == None
  assert session.current_user(a1_check, tx, secret) == Some(alice)

  // With only 1 active session left, /sessions omits the Revoke other sessions form
  let after_others_resp = router.handle_request(list_req, auth_ctx, post_pubsub)
  let after_others_body = simulate.read_body(after_others_resp)
  assert string.contains(after_others_body, "1 active session")
  assert !string.contains(after_others_body, "/sessions/revoke-others")

  // Revoking own current session via endpoint clears cookie, publishes a1_sid, redirects to /
  let revoke_self_req =
    simulate.browser_request(
      http.Post,
      "/sessions/" <> a1_info.public_id <> "/revoke",
    )
    |> simulate.session(list_req, list_resp)
    |> simulate.form_body([#(csrf.form_field_name, alice_csrf)])
  let revoke_self_resp =
    router.handle_request(revoke_self_req, auth_ctx, post_pubsub)
  assert revoke_self_resp.status == 303
  assert response.get_header(revoke_self_resp, "location") == Ok("/")
  assert process.receive(revocation_sub, 100) == Ok(a1_sid)
  assert session.current_user(a1_check, tx, secret) == None
}

pub fn password_login_rate_limits_by_ip_and_account_and_resets_on_success_test() {
  use tx <- test_helper.with_db
  let assert Ok(session_revocations) = pubsub.start()
  let assert Ok(post_pubsub) = pubsub.start()
  let secret = "login_rl_secret_key_base_0123456789abcdefghijklmnopqrstuvwxyz"
  let assert Ok(rate_limiter) = rate_limit.start_memory(secret)

  let assert Ok(alice) = user.create(tx, "RateAlice")
  let assert Ok(Nil) =
    password.create(tx, alice.id, "rate_alice", "correctpass123")
  let assert Ok(bob) = user.create(tx, "RateBob")
  let assert Ok(Nil) = password.create(tx, bob.id, "rate_bob", "correctpass123")
  let auth_ctx =
    Auth(
      db: tx,
      secret_key_base: secret,
      methods: [Password],
      session_revocations:,
      rate_limiter:,
    )

  let page_req = simulate.browser_request(http.Get, "/auth/login")
  let page_resp = router.handle_request(page_req, auth_ctx, post_pubsub)
  let login_csrf = extract_form_csrf_token(simulate.read_body(page_resp))

  let submit_login = fn(ip: String, login_id: String, pw: String) {
    simulate.browser_request(http.Post, "/auth/password/login")
    |> simulate.session(page_req, page_resp)
    |> simulate.form_body([
      #(csrf.form_field_name, login_csrf),
      #("login_id", login_id),
      #("password", pw),
    ])
    |> router.handle_request_with_ip(auth_ctx, post_pubsub, ip)
  }

  // 5 failed attempts from 203.0.113.10 for rate_alice return 200 with credential error
  let _ =
    int.range(from: 1, to: 6, with: Nil, run: fn(_, _) {
      let resp = submit_login("203.0.113.10", "rate_alice", "wrongpass")
      assert resp.status == 200
      Nil
    })

  // 6th attempt from same IP for same account (even uppercase) returns 429 + Retry-After + no-store
  let limited_resp =
    submit_login("203.0.113.10", "RATE_ALICE", "correctpass123")
  assert limited_resp.status == 429
  assert response.get_header(limited_resp, "cache-control") == Ok("no-store")
  let assert Ok(retry_after) = response.get_header(limited_resp, "retry-after")
  let assert Ok(retry_seconds) = int.parse(retry_after)
  assert retry_seconds >= 1
  assert string.contains(simulate.read_body(limited_resp), "ログイン試行回数が上限に達しました")

  // Another IP is NOT locked out of rate_alice (prevents cross-IP lockout DoS)
  let other_ip_resp =
    submit_login("203.0.113.20", "rate_alice", "correctpass123")
  assert other_ip_resp.status == 303

  // Same IP can still log in to a different account (rate_bob), and success resets account quota
  let bob_fail1 = submit_login("203.0.113.10", "rate_bob", "wrongpass")
  assert bob_fail1.status == 200
  let bob_ok = submit_login("203.0.113.10", "rate_bob", "correctpass123")
  assert bob_ok.status == 303
  // After reset on success, rate_bob from 203.0.113.10 gets a fresh account bucket
  let bob_after_reset = submit_login("203.0.113.10", "rate_bob", "wrongpass")
  assert bob_after_reset.status == 200

  // IP-wide limit (20/15m) blocks the 21st attempt from an IP even with fresh login_ids
  let flood_ip = "198.51.100.9"
  let _ =
    int.range(from: 1, to: 20, with: Nil, run: fn(_, _) {
      let _ =
        rate_limit.check(
          rate_limiter,
          "login:ip:" <> client_ip.rate_limit_bucket(flood_ip),
          password_handler.ip_policy,
        )
      Nil
    })
  let ip_ok = submit_login(flood_ip, "brand_new_id_20", "wrong")
  assert ip_ok.status == 200
  let ip_limited = submit_login(flood_ip, "brand_new_id_21", "wrong")
  assert ip_limited.status == 429

  // IPv6 addresses rotating within the same /64 share the rate-limit bucket,
  // while an adjacent /64 remains unaffected
  let _ =
    ["1", "2", "3", "4", "5"]
    |> list.each(fn(host) {
      let resp =
        submit_login("2001:db8:aaaa:bbbb::" <> host, "rate_alice", "wrongpass")
      assert resp.status == 200
    })
  let v6_same_prefix_limited =
    submit_login("2001:0DB8:aaaa:bbbb:ffff::99", "rate_alice", "correctpass123")
  assert v6_same_prefix_limited.status == 429
  let v6_other_prefix_ok =
    submit_login("2001:db8:aaaa:bbbc::1", "rate_alice", "correctpass123")
  assert v6_other_prefix_ok.status == 303

  rate_limit.stop_memory(rate_limiter)
}

pub fn http_write_endpoints_enforce_user_and_ip_rate_limits_test() {
  use tx <- test_helper.with_db
  let assert Ok(session_revocations) = pubsub.start()
  let assert Ok(post_pubsub) = pubsub.start()
  let secret = "write_rl_secret_key_base_0123456789abcdefghijklmnopqrstuvwxyz"
  let assert Ok(rate_limiter) = rate_limit.start_memory(secret)

  let assert Ok(alice) = user.create(tx, "WriteAlice")
  let assert Ok(bob) = user.create(tx, "WriteBob")
  let auth_ctx =
    Auth(
      db: tx,
      secret_key_base: secret,
      methods: [Password],
      session_revocations:,
      rate_limiter:,
    )

  let login_req = simulate.browser_request(http.Post, "/auth/password/login")
  let assert Ok(alice_login) =
    session.create(wisp.ok(), login_req, tx, secret, alice)
  let alice_sessions_req =
    simulate.browser_request(http.Get, "/sessions")
    |> simulate.session(login_req, alice_login)
  let alice_sessions_resp =
    router.handle_request(alice_sessions_req, auth_ctx, post_pubsub)
  let alice_csrf =
    extract_form_csrf_token(simulate.read_body(alice_sessions_resp))

  // Exhaust Alice's user write burst (10) via revoke-others
  let _ =
    int.range(
      from: 1,
      to: http_rate_limit.write_policy.burst + 1,
      with: Nil,
      run: fn(_, _) {
        let resp =
          simulate.browser_request(http.Post, "/sessions/revoke-others")
          |> simulate.session(alice_sessions_req, alice_sessions_resp)
          |> simulate.form_body([#(csrf.form_field_name, alice_csrf)])
          |> router.handle_request(auth_ctx, post_pubsub)
        assert resp.status == 303
        Nil
      },
    )

  // Next write by Alice (e.g. POST /posts/:id/delete) is rate-limited with 429 + Retry-After + no-store
  let assert Ok(alice_post) = post_repo.create(tx, alice.id, "protected by rl")
  let delete_limited =
    simulate.browser_request(http.Post, "/posts/" <> alice_post.id <> "/delete")
    |> simulate.session(alice_sessions_req, alice_sessions_resp)
    |> simulate.form_body([#(csrf.form_field_name, alice_csrf)])
    |> router.handle_request(auth_ctx, post_pubsub)
  assert delete_limited.status == 429
  assert response.get_header(delete_limited, "cache-control") == Ok("no-store")
  let assert Ok(retry_after) =
    response.get_header(delete_limited, "retry-after")
  let assert Ok(retry_sec) = int.parse(retry_after)
  assert retry_sec >= 1
  // Post was NOT deleted while rate-limited
  let assert Ok(Some(_)) = post_repo.find_by_id(tx, alice_post.id)

  // Bob's user write bucket is independent and succeeds
  let assert Ok(bob_login) =
    session.create(wisp.ok(), login_req, tx, secret, bob)
  let bob_sessions_req =
    simulate.browser_request(http.Get, "/sessions")
    |> simulate.session(login_req, bob_login)
  let bob_sessions_resp =
    router.handle_request(bob_sessions_req, auth_ctx, post_pubsub)
  let bob_csrf = extract_form_csrf_token(simulate.read_body(bob_sessions_resp))
  let bob_revoke =
    simulate.browser_request(http.Post, "/sessions/revoke-others")
    |> simulate.session(bob_sessions_req, bob_sessions_resp)
    |> simulate.form_body([#(csrf.form_field_name, bob_csrf)])
    |> router.handle_request(auth_ctx, post_pubsub)
  assert bob_revoke.status == 303

  // POST /auth/logout enforces per-IP write rate limit
  let logout_ip = "203.0.113.88"
  let page_req = simulate.browser_request(http.Get, "/auth/login")
  let page_resp = router.handle_request(page_req, auth_ctx, post_pubsub)
  let logout_csrf = extract_form_csrf_token(simulate.read_body(page_resp))
  let _ =
    int.range(
      from: 1,
      to: http_rate_limit.write_policy.burst + 1,
      with: Nil,
      run: fn(_, _) {
        let resp =
          simulate.browser_request(http.Post, "/auth/logout")
          |> simulate.session(page_req, page_resp)
          |> simulate.form_body([#(csrf.form_field_name, logout_csrf)])
          |> router.handle_request_with_ip(auth_ctx, post_pubsub, logout_ip)
        assert resp.status == 303
        Nil
      },
    )
  let logout_limited =
    simulate.browser_request(http.Post, "/auth/logout")
    |> simulate.session(page_req, page_resp)
    |> simulate.form_body([#(csrf.form_field_name, logout_csrf)])
    |> router.handle_request_with_ip(auth_ctx, post_pubsub, logout_ip)
  assert logout_limited.status == 429
  assert response.get_header(logout_limited, "cache-control") == Ok("no-store")

  // IPv6 logout writes rotating within the same /64 share a bucket
  let _ =
    int.range(
      from: 1,
      to: http_rate_limit.write_policy.burst + 1,
      with: Nil,
      run: fn(_, n) {
        let resp =
          simulate.browser_request(http.Post, "/auth/logout")
          |> simulate.session(page_req, page_resp)
          |> simulate.form_body([#(csrf.form_field_name, logout_csrf)])
          |> router.handle_request_with_ip(
            auth_ctx,
            post_pubsub,
            "2001:db8:feed:1::" <> int.to_string(n),
          )
        assert resp.status == 303
        Nil
      },
    )
  let logout_v6_limited =
    simulate.browser_request(http.Post, "/auth/logout")
    |> simulate.session(page_req, page_resp)
    |> simulate.form_body([#(csrf.form_field_name, logout_csrf)])
    |> router.handle_request_with_ip(
      auth_ctx,
      post_pubsub,
      "2001:db8:feed:1:ffff::99",
    )
  assert logout_v6_limited.status == 429

  rate_limit.stop_memory(rate_limiter)
}
