import gleam/erlang/process
import gleam/http
import gleam/http/request
import gleam/http/response
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
import lote/web/components/timeline
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
  let assert Ok(post_pubsub) = pubsub.start()

  let auth_ctx =
    Auth(
      db: tx,
      secret_key_base: simulate.default_secret_key_base,
      methods: [],
      session_revocations:,
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
