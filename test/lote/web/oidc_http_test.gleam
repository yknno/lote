import gleam/bit_array
import gleam/dynamic/decode
import gleam/erlang/process
import gleam/http
import gleam/http/request
import gleam/http/response
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/set
import gleam/string
import lote
import lote/auth.{type Auth, Auth, Password}
import lote/auth/password
import lote/auth/session
import lote/auth/user
import lote/config
import lote/db/post_repo
import lote/oidc.{type Oidc}
import lote/oidc/client
import lote/oidc/grant
import lote/oidc/scope
import lote/oidc/token
import lote/rate_limit.{type Limiter}
import lote/realtime/pubsub.{type PubSub}
import lote/test_helper
import lote/web/components/timeline
import lote/web/csrf
import lote/web/http_rate_limit
import lote/web/oidc/bearer
import lote/web/oidc/handler as oidc_handler
import lote/web/router
import pog
import wisp
import wisp/simulate

const test_secret =
  "oidc_http_test_secret_key_base_0123456789abcdefghijklmnopqrstuvwx"

const test_issuer = "https://lote.example"

const valid_pkce_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

fn setup_contexts(
  tx: pog.Connection,
  limiter: Limiter,
) -> #(Auth, Oidc, PubSub(timeline.PostEvent), PubSub(String)) {
  let assert Ok(session_revocations) = pubsub.start()
  let assert Ok(grant_revocations) = pubsub.start()
  let assert Ok(post_pubsub) = pubsub.start()

  let auth_ctx =
    Auth(
      db: tx,
      secret_key_base: test_secret,
      methods: [Password],
      session_revocations:,
      rate_limiter: limiter,
    )
  let oidc_ctx = oidc.new(tx, test_issuer, grant_revocations, limiter)
  #(auth_ctx, oidc_ctx, post_pubsub, grant_revocations)
}

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

fn basic_auth_header(raw_id: String, raw_secret: String) -> String {
  let credentials = raw_id <> ":" <> raw_secret
  "Basic " <> bit_array.base64_encode(<<credentials:utf8>>, True)
}

fn parse_error_code(resp: wisp.Response) -> String {
  let decoder = {
    use err <- decode.field("error", decode.string)
    decode.success(err)
  }
  let assert Ok(code) = json.parse(simulate.read_body(resp), decoder)
  code
}

fn parse_access_token(
  resp: wisp.Response,
) -> #(String, String, Option(String)) {
  let decoder = {
    use access_token <- decode.field("access_token", decode.string)
    use token_type <- decode.field("token_type", decode.string)
    use expires_in <- decode.field("expires_in", decode.int)
    use scope_str <- decode.field("scope", decode.string)
    use refresh_token <- decode.optional_field(
      "refresh_token",
      None,
      decode.optional(decode.string),
    )
    assert token_type == "Bearer"
    assert expires_in == token.access_token_ttl_seconds
    decode.success(#(access_token, scope_str, refresh_token))
  }
  let assert Ok(parsed) = json.parse(simulate.read_body(resp), decoder)
  parsed
}

pub fn settings_clients_browser_workflow_secret_rotation_and_revocation_test() {
  use tx <- test_helper.with_db
  let #(auth_ctx, oidc_ctx, post_pubsub, grant_revocations) =
    setup_contexts(tx, rate_limit.disabled())

  let grant_rev_sub = process.new_subject()
  pubsub.subscribe(grant_revocations, grant_rev_sub)

  let assert Ok(alice) = user.create(tx, "AliceClientOwner")
  let assert Ok(Nil) =
    password.create(tx, alice.id, "alice_clients", "secretpass123")
  let assert Ok(bob) = user.create(tx, "BobOtherUser")
  let assert Ok(Nil) =
    password.create(tx, bob.id, "bob_clients", "secretpass123")

  let dispatch = fn(req: wisp.Request) {
    router.handle_request_with_oidc(
      req,
      auth_ctx,
      oidc_ctx,
      post_pubsub,
      "127.0.0.1",
    )
  }

  // Unauthenticated GET /settings/clients -> 303 redirect to /auth/login
  let anon_get =
    simulate.browser_request(http.Get, "/settings/clients")
    |> dispatch
  assert anon_get.status == 303
  assert response.get_header(anon_get, "location") == Ok("/auth/login")
  assert response.get_header(anon_get, "cache-control") == Ok("no-store")

  // Method not allowed checks on /settings/clients/*
  assert dispatch(simulate.browser_request(http.Post, "/settings/clients")).status
    == 405
  assert dispatch(simulate.browser_request(http.Get, "/settings/clients/bots")).status
    == 405
  assert dispatch(simulate.browser_request(
      http.Get,
      "/settings/clients/cli_123/delete",
    )).status
    == 405

  // Unauthenticated POST without CSRF -> 403; with valid CSRF cookie -> 401
  let anon_post_no_csrf =
    simulate.browser_request(http.Post, "/settings/clients/bots")
    |> simulate.form_body([#("name", "Anon Bot"), #("scopes", "posts:read")])
    |> dispatch
  assert anon_post_no_csrf.status == 403

  let login_page_req = simulate.browser_request(http.Get, "/auth/login")
  let login_page_resp = dispatch(login_page_req)
  let anon_csrf = extract_form_csrf_token(simulate.read_body(login_page_resp))

  let anon_post_with_csrf =
    simulate.browser_request(http.Post, "/settings/clients/bots")
    |> simulate.session(login_page_req, login_page_resp)
    |> simulate.form_body([
      #(csrf.form_field_name, anon_csrf),
      #("name", "Anon Bot"),
      #("scopes", "posts:read"),
    ])
    |> dispatch
  assert anon_post_with_csrf.status == 401

  // Log in Alice and Bob via browser sessions
  let login_req = simulate.browser_request(http.Post, "/auth/password/login")
  let assert Ok(alice_login) =
    session.create(wisp.ok(), login_req, tx, test_secret, alice)
  let assert Ok(bob_login) =
    session.create(wisp.ok(), login_req, tx, test_secret, bob)

  // Check navigation links on /sessions and /settings/clients
  let sessions_resp =
    simulate.browser_request(http.Get, "/sessions")
    |> simulate.session(login_req, alice_login)
    |> dispatch
  assert sessions_resp.status == 200
  assert string.contains(simulate.read_body(sessions_resp), "/settings/clients")

  let index_req =
    simulate.browser_request(http.Get, "/settings/clients")
    |> simulate.session(login_req, alice_login)
  let index_resp = dispatch(index_req)
  assert index_resp.status == 200
  assert response.get_header(index_resp, "cache-control") == Ok("no-store")
  let index_html = simulate.read_body(index_resp)
  assert string.contains(index_html, "Subordinate Bots &amp; Apps")
    || string.contains(index_html, "Subordinate Bots & Apps")
  assert string.contains(index_html, "No clients registered yet.")
  assert string.contains(index_html, "/sessions")
  // Enforce sharp corners (no rounded-* utility classes)
  assert !string.contains(index_html, "rounded-")

  let alice_csrf = extract_form_csrf_token(index_html)

  // Cross-origin POST to /settings/clients/bots is blocked by Wisp CSRF origin check -> 400
  let cross_origin_bot =
    simulate.browser_request(http.Post, "/settings/clients/bots")
    |> simulate.session(index_req, index_resp)
    |> request.set_header("origin", "https://evil.example")
    |> simulate.form_body([
      #(csrf.form_field_name, alice_csrf),
      #("name", "Cross Origin Bot"),
      #("scopes", "posts:read"),
    ])
    |> dispatch
  assert cross_origin_bot.status == 400

  // Missing CSRF form token -> 403
  let missing_csrf_bot =
    simulate.browser_request(http.Post, "/settings/clients/bots")
    |> simulate.session(index_req, index_resp)
    |> simulate.form_body([#("name", "No Csrf Bot"), #("scopes", "posts:read")])
    |> dispatch
  assert missing_csrf_bot.status == 403

  // Validation failures return 422 with alert box (empty name, empty scopes, non-bot scope)
  let empty_name_resp =
    simulate.browser_request(http.Post, "/settings/clients/bots")
    |> simulate.session(index_req, index_resp)
    |> simulate.form_body([
      #(csrf.form_field_name, alice_csrf),
      #("name", "   "),
      #("scopes", "posts:read"),
    ])
    |> dispatch
  assert empty_name_resp.status == 422

  let no_scopes_resp =
    simulate.browser_request(http.Post, "/settings/clients/bots")
    |> simulate.session(index_req, index_resp)
    |> simulate.form_body([
      #(csrf.form_field_name, alice_csrf),
      #("name", "Scopeless Bot"),
    ])
    |> dispatch
  assert no_scopes_resp.status == 422

  let bad_scope_resp =
    simulate.browser_request(http.Post, "/settings/clients/bots")
    |> simulate.session(index_req, index_resp)
    |> simulate.form_body([
      #(csrf.form_field_name, alice_csrf),
      #("name", "Bad Scope Bot"),
      #("scopes", "openid"),
    ])
    |> dispatch
  assert bad_scope_resp.status == 422

  // Valid Subordinate Bot creation via form POST -> 200 with one-time secret banner
  let create_bot_resp =
    simulate.browser_request(http.Post, "/settings/clients/bots")
    |> simulate.session(index_req, index_resp)
    |> simulate.form_body([
      #(csrf.form_field_name, alice_csrf),
      #("name", "Release Bot"),
      #("secret_label", "primary"),
      #("scopes", "posts:read"),
      #("scopes", "posts:write"),
    ])
    |> dispatch
  assert create_bot_resp.status == 200
  assert response.get_header(create_bot_resp, "cache-control") == Ok("no-store")
  // Never put raw secret in URL location or cookies
  assert response.get_header(create_bot_resp, "location") == Error(Nil)
  let set_cookies = list.key_filter(create_bot_resp.headers, "set-cookie")
  assert list.all(set_cookies, fn(c) { !string.contains(c, "lote_cs_") })

  let created_html = simulate.read_body(create_bot_resp)
  assert !string.contains(created_html, "rounded-")
  let bot_client_id = extract_between(created_html, "data-client-id=\"", "\"")
  let secret1 = extract_between(created_html, "data-client-secret=\"", "\"")
  assert string.starts_with(bot_client_id, "cli_")
  assert string.starts_with(secret1, "lote_cs_")

  // Subsequent GET /settings/clients shows only prefix, never full secret1
  let reload_resp = dispatch(index_req)
  let reload_html = simulate.read_body(reload_resp)
  assert string.contains(reload_html, bot_client_id)
  assert !string.contains(reload_html, secret1)

  // Add 2nd secret via POST /settings/clients/:client_id/secrets (zero-downtime rotation)
  let add_secret_resp =
    simulate.browser_request(
      http.Post,
      "/settings/clients/" <> bot_client_id <> "/secrets",
    )
    |> simulate.session(index_req, index_resp)
    |> simulate.form_body([
      #(csrf.form_field_name, alice_csrf),
      #("label", "rotated-v2"),
    ])
    |> dispatch
  assert add_secret_resp.status == 200
  assert response.get_header(add_secret_resp, "cache-control") == Ok("no-store")
  let secret2 =
    extract_between(
      simulate.read_body(add_secret_resp),
      "data-client-secret=\"",
      "\"",
    )
  assert string.starts_with(secret2, "lote_cs_")
  assert secret2 != secret1

  // Both old (secret1) and new (secret2) secrets work at POST /oidc/token
  let token_with_secret = fn(sec: String) {
    simulate.request(http.Post, "/oidc/token")
    |> request.set_header(
      "authorization",
      basic_auth_header(bot_client_id, sec),
    )
    |> simulate.form_body([#("grant_type", "client_credentials")])
    |> dispatch
  }
  let tok1_resp = token_with_secret(secret1)
  assert tok1_resp.status == 200
  let assert #(at1, scope1, None) = parse_access_token(tok1_resp)
  assert scope1 == "posts:read posts:write"

  let tok2_resp = token_with_secret(secret2)
  assert tok2_resp.status == 200
  let assert #(at2, _, None) = parse_access_token(tok2_resp)

  // Find secret1's public_id from DB / HTML revoke action
  let assert Ok([#(_, listed_secrets)]) = client.list_for_owner(tx, alice.id)
  let assert Ok(s1_info) =
    list.find(listed_secrets, fn(s) { s.label == "primary" })
  let s1_revoke_path =
    "/settings/clients/"
    <> bot_client_id
    <> "/secrets/"
    <> s1_info.public_id
    <> "/revoke"

  // Bob cannot add secrets, revoke secrets, or delete Alice's bot -> 404
  let bob_index_req =
    simulate.browser_request(http.Get, "/settings/clients")
    |> simulate.session(login_req, bob_login)
  let bob_index_resp = dispatch(bob_index_req)
  let bob_csrf = extract_form_csrf_token(simulate.read_body(bob_index_resp))

  assert dispatch(
      simulate.browser_request(
        http.Post,
        "/settings/clients/" <> bot_client_id <> "/secrets",
      )
      |> simulate.session(bob_index_req, bob_index_resp)
      |> simulate.form_body([
        #(csrf.form_field_name, bob_csrf),
        #("label", "intruder"),
      ]),
    ).status
    == 404
  assert dispatch(
      simulate.browser_request(http.Post, s1_revoke_path)
      |> simulate.session(bob_index_req, bob_index_resp)
      |> simulate.form_body([#(csrf.form_field_name, bob_csrf)]),
    ).status
    == 404
  assert dispatch(
      simulate.browser_request(
        http.Post,
        "/settings/clients/" <> bot_client_id <> "/delete",
      )
      |> simulate.session(bob_index_req, bob_index_resp)
      |> simulate.form_body([#(csrf.form_field_name, bob_csrf)]),
    ).status
    == 404

  // Alice revokes secret1 -> 303 redirect, secret1 fails at /oidc/token, secret2 still works!
  let revoke_s1_resp =
    simulate.browser_request(http.Post, s1_revoke_path)
    |> simulate.session(index_req, index_resp)
    |> simulate.form_body([#(csrf.form_field_name, alice_csrf)])
    |> dispatch
  assert revoke_s1_resp.status == 303
  assert response.get_header(revoke_s1_resp, "location")
    == Ok("/settings/clients")

  let revoked_s1_tok = token_with_secret(secret1)
  assert revoked_s1_tok.status == 401
  assert parse_error_code(revoked_s1_tok) == "invalid_client"

  let still_valid_s2_tok = token_with_secret(secret2)
  assert still_valid_s2_tok.status == 200
  let assert #(at3, _, None) = parse_access_token(still_valid_s2_tok)

  // Verify issued access tokens currently authenticate on /api/v1/posts
  assert dispatch(
      simulate.request(http.Get, "/api/v1/posts")
      |> request.set_header("authorization", "Bearer " <> at1),
    ).status
    == 200
  assert dispatch(
      simulate.request(http.Get, "/api/v1/posts")
      |> request.set_header("authorization", "Bearer " <> at3),
    ).status
    == 200

  let assert Ok(active_grants_before) =
    grant.list_active_grants_for_user(tx, alice.id)
  assert list.length(active_grants_before) == 3
  let expected_grant_ids =
    active_grants_before |> list.map(fn(g) { g.public_id }) |> set.from_list

  // Alice deletes the Bot -> 303 redirect, publishes all active grant_ids, and tokens immediately 401!
  let delete_bot_resp =
    simulate.browser_request(
      http.Post,
      "/settings/clients/" <> bot_client_id <> "/delete",
    )
    |> simulate.session(index_req, index_resp)
    |> simulate.form_body([#(csrf.form_field_name, alice_csrf)])
    |> dispatch
  assert delete_bot_resp.status == 303
  assert response.get_header(delete_bot_resp, "location")
    == Ok("/settings/clients")

  let assert Ok(rev1) = process.receive(grant_rev_sub, 100)
  let assert Ok(rev2) = process.receive(grant_rev_sub, 100)
  let assert Ok(rev3) = process.receive(grant_rev_sub, 100)
  assert set.from_list([rev1, rev2, rev3]) == expected_grant_ids

  let after_del_api1 =
    simulate.request(http.Get, "/api/v1/posts")
    |> request.set_header("authorization", "Bearer " <> at1)
    |> dispatch
  assert after_del_api1.status == 401
  assert parse_error_code(after_del_api1) == "invalid_token"

  let after_del_api2 =
    simulate.request(http.Get, "/api/v1/posts")
    |> request.set_header("authorization", "Bearer " <> at2)
    |> dispatch
  assert after_del_api2.status == 401
}

pub fn oidc_token_client_credentials_auth_methods_origin_cookies_scopes_and_audience_test() {
  use tx <- test_helper.with_db
  let #(auth_ctx, oidc_ctx, post_pubsub, _grant_revocations) =
    setup_contexts(tx, rate_limit.disabled())

  let assert Ok(alice) = user.create(tx, "TokenTestOwner")
  let assert Ok(bot) =
    client.create_subordinate_bot(
      tx,
      alice.id,
      "Token Spec Bot",
      set.from_list([scope.PostsRead, scope.PostsWrite]),
      "spec",
      None,
    )
  let assert Ok(#(conf_app, Some(conf_secret))) =
    client.create_app(
      tx,
      alice.id,
      "Confidential Web App",
      True,
      client.Private,
      client.Web,
      ["https://app.example/cb"],
      set.from_list([scope.OpenId, scope.PostsRead]),
    )

  let dispatch = fn(req: wisp.Request) {
    router.handle_request_with_oidc(
      req,
      auth_ctx,
      oidc_ctx,
      post_pubsub,
      "127.0.0.1",
    )
  }

  let assert_no_store_pragma = fn(resp: wisp.Response) {
    assert response.get_header(resp, "cache-control") == Ok("no-store")
    assert response.get_header(resp, "pragma") == Ok("no-cache")
  }

  // Method not allowed & unknown /oidc/* paths still carry no-store + pragma
  let get_tok = dispatch(simulate.request(http.Get, "/oidc/token"))
  assert get_tok.status == 405
  assert_no_store_pragma(get_tok)

  let not_found_oidc = dispatch(simulate.request(http.Post, "/oidc/unknown"))
  assert not_found_oidc.status == 404
  assert_no_store_pragma(not_found_oidc)

  // 1. Authorization: Basic with URL-encoded (%5F for '_') client_id and client_secret (RFC 6749 2.3.1)
  let encoded_id = string.replace(bot.client.client_id, each: "_", with: "%5F")
  let encoded_sec = string.replace(bot.secret.secret, each: "_", with: "%5F")
  assert encoded_id != bot.client.client_id
  assert encoded_sec != bot.secret.secret

  let basic_encoded_resp =
    simulate.request(http.Post, "/oidc/token")
    |> request.set_header(
      "authorization",
      "basic "
        <> bit_array.base64_encode(
        <<{ encoded_id <> ":" <> encoded_sec }:utf8>>,
        True,
      ),
    )
    |> request.set_header("origin", "https://external-mcp.example")
    |> request.set_header("cookie", "lote_session=should_be_stripped")
    |> simulate.form_body([#("grant_type", "client_credentials")])
    |> dispatch
  assert basic_encoded_resp.status == 200
  assert_no_store_pragma(basic_encoded_resp)
  let assert #(at_basic, scope_basic, None) =
    parse_access_token(basic_encoded_resp)
  assert scope_basic == "posts:read posts:write"
  assert string.starts_with(at_basic, "lote_at_")

  // 2. client_secret_post works
  let post_secret_resp =
    simulate.request(http.Post, "/oidc/token")
    |> simulate.form_body([
      #("grant_type", "client_credentials"),
      #("client_id", bot.client.client_id),
      #("client_secret", bot.secret.secret),
    ])
    |> dispatch
  assert post_secret_resp.status == 200
  assert_no_store_pragma(post_secret_resp)

  // 3. Dual authentication (Basic header + form client_secret) -> 400 invalid_request
  let dual_auth_resp =
    simulate.request(http.Post, "/oidc/token")
    |> request.set_header(
      "authorization",
      basic_auth_header(bot.client.client_id, bot.secret.secret),
    )
    |> simulate.form_body([
      #("grant_type", "client_credentials"),
      #("client_secret", bot.secret.secret),
    ])
    |> dispatch
  assert dual_auth_resp.status == 400
  assert parse_error_code(dual_auth_resp) == "invalid_request"

  // Mismatched client_id between Basic header and form body -> 400 invalid_request
  let mismatch_id_resp =
    simulate.request(http.Post, "/oidc/token")
    |> request.set_header(
      "authorization",
      basic_auth_header(bot.client.client_id, bot.secret.secret),
    )
    |> simulate.form_body([
      #("grant_type", "client_credentials"),
      #("client_id", "cli_different"),
    ])
    |> dispatch
  assert mismatch_id_resp.status == 400
  assert parse_error_code(mismatch_id_resp) == "invalid_request"

  // Non-Basic Authorization header -> 400 invalid_request
  let bearer_on_tok =
    simulate.request(http.Post, "/oidc/token")
    |> request.set_header("authorization", "Bearer " <> at_basic)
    |> simulate.form_body([#("grant_type", "client_credentials")])
    |> dispatch
  assert bearer_on_tok.status == 400
  assert parse_error_code(bearer_on_tok) == "invalid_request"

  // 4. Duplicate OAuth form parameters -> 400 invalid_request (RFC 6749 3.2)
  let dup_param_resp =
    simulate.request(http.Post, "/oidc/token")
    |> request.set_header(
      "authorization",
      basic_auth_header(bot.client.client_id, bot.secret.secret),
    )
    |> simulate.string_body(
      "grant_type=client_credentials&scope=posts:read&scope=posts:write",
    )
    |> request.set_header("content-type", "application/x-www-form-urlencoded")
    |> dispatch
  assert dup_param_resp.status == 400
  assert parse_error_code(dup_param_resp) == "invalid_request"

  // Non-form Content-Type -> 400 invalid_request
  let json_ct_resp =
    simulate.request(http.Post, "/oidc/token")
    |> simulate.json_body(
      json.object([#("grant_type", json.string("client_credentials"))]),
    )
    |> dispatch
  assert json_ct_resp.status == 400
  assert parse_error_code(json_ct_resp) == "invalid_request"

  // Missing or unsupported grant_type
  let missing_gt =
    simulate.request(http.Post, "/oidc/token")
    |> request.set_header(
      "authorization",
      basic_auth_header(bot.client.client_id, bot.secret.secret),
    )
    |> simulate.form_body([])
    |> dispatch
  assert missing_gt.status == 400
  assert parse_error_code(missing_gt) == "invalid_request"

  let unsupported_gt =
    simulate.request(http.Post, "/oidc/token")
    |> request.set_header(
      "authorization",
      basic_auth_header(bot.client.client_id, bot.secret.secret),
    )
    |> simulate.form_body([#("grant_type", "password")])
    |> dispatch
  assert unsupported_gt.status == 400
  assert parse_error_code(unsupported_gt) == "unsupported_grant_type"

  // 5. Invalid credentials & malformed Basic header -> 401 invalid_client + WWW-Authenticate: Basic
  let bad_secret_resp =
    simulate.request(http.Post, "/oidc/token")
    |> request.set_header(
      "authorization",
      basic_auth_header(bot.client.client_id, "lote_cs_wrong_secret"),
    )
    |> simulate.form_body([#("grant_type", "client_credentials")])
    |> dispatch
  assert bad_secret_resp.status == 401
  assert parse_error_code(bad_secret_resp) == "invalid_client"
  let assert Ok(www_auth) =
    response.get_header(bad_secret_resp, "www-authenticate")
  assert string.starts_with(www_auth, "Basic ")
  assert_no_store_pragma(bad_secret_resp)

  let malformed_basic_resp =
    simulate.request(http.Post, "/oidc/token")
    |> request.set_header("authorization", "Basic !!!not_base64!!!")
    |> simulate.form_body([#("grant_type", "client_credentials")])
    |> dispatch
  assert malformed_basic_resp.status == 401
  assert parse_error_code(malformed_basic_resp) == "invalid_client"
  assert response.get_header(malformed_basic_resp, "www-authenticate")
    == Ok("Basic realm=\"lote\", charset=\"UTF-8\"")

  let malformed_pct_resp =
    simulate.request(http.Post, "/oidc/token")
    |> request.set_header(
      "authorization",
      basic_auth_header("cli_bad%ZZ", bot.secret.secret),
    )
    |> simulate.form_body([#("grant_type", "client_credentials")])
    |> dispatch
  assert malformed_pct_resp.status == 401
  assert parse_error_code(malformed_pct_resp) == "invalid_client"

  // ConfidentialApp (non-bot) cannot use client_credentials -> 400 unauthorized_client
  let non_bot_cc =
    simulate.request(http.Post, "/oidc/token")
    |> request.set_header(
      "authorization",
      basic_auth_header(conf_app.client_id, conf_secret.secret),
    )
    |> simulate.form_body([#("grant_type", "client_credentials")])
    |> dispatch
  assert non_bot_cc.status == 400
  assert parse_error_code(non_bot_cc) == "unauthorized_client"

  // 6. Scope narrowing & invalid/unconsented scope rejection
  let narrowed_resp =
    simulate.request(http.Post, "/oidc/token")
    |> request.set_header(
      "authorization",
      basic_auth_header(bot.client.client_id, bot.secret.secret),
    )
    |> simulate.form_body([
      #("grant_type", "client_credentials"),
      #("scope", "posts:read"),
    ])
    |> dispatch
  assert narrowed_resp.status == 200
  let assert #(_at_narrow, scope_narrow, None) =
    parse_access_token(narrowed_resp)
  assert scope_narrow == "posts:read"

  let unknown_scope_resp =
    simulate.request(http.Post, "/oidc/token")
    |> request.set_header(
      "authorization",
      basic_auth_header(bot.client.client_id, bot.secret.secret),
    )
    |> simulate.form_body([
      #("grant_type", "client_credentials"),
      #("scope", "posts:admin"),
    ])
    |> dispatch
  assert unknown_scope_resp.status == 400
  assert parse_error_code(unknown_scope_resp) == "invalid_scope"

  let unconsented_scope_resp =
    simulate.request(http.Post, "/oidc/token")
    |> request.set_header(
      "authorization",
      basic_auth_header(bot.client.client_id, bot.secret.secret),
    )
    |> simulate.form_body([
      #("grant_type", "client_credentials"),
      #("scope", "posts:delete"),
    ])
    |> dispatch
  assert unconsented_scope_resp.status == 400
  assert parse_error_code(unconsented_scope_resp) == "invalid_scope"

  // 7. RFC 8707 resource indicator & strict audience enforcement on /api/v1/posts
  let bad_resource_resp =
    simulate.request(http.Post, "/oidc/token")
    |> request.set_header(
      "authorization",
      basic_auth_header(bot.client.client_id, bot.secret.secret),
    )
    |> simulate.form_body([
      #("grant_type", "client_credentials"),
      #("resource", "https://other.example/mcp#fragment"),
    ])
    |> dispatch
  assert bad_resource_resp.status == 400
  assert parse_error_code(bad_resource_resp) == "invalid_target"

  let other_aud_tok_resp =
    simulate.request(http.Post, "/oidc/token")
    |> request.set_header(
      "authorization",
      basic_auth_header(bot.client.client_id, bot.secret.secret),
    )
    |> simulate.form_body([
      #("grant_type", "client_credentials"),
      #("resource", "https://other-service.example/mcp"),
    ])
    |> dispatch
  assert other_aud_tok_resp.status == 200
  let assert #(at_other_aud, _, None) = parse_access_token(other_aud_tok_resp)

  // Wrong-audience token is rejected by lote's /api/v1/posts with 401 invalid_token!
  let wrong_aud_api =
    simulate.request(http.Get, "/api/v1/posts")
    |> request.set_header("authorization", "Bearer " <> at_other_aud)
    |> dispatch
  assert wrong_aud_api.status == 401
  assert parse_error_code(wrong_aud_api) == "invalid_token"
  assert response.get_header(wrong_aud_api, "www-authenticate")
    == Ok("Bearer realm=\"lote\", error=\"invalid_token\"")
}

pub fn oidc_auth_code_pkce_refresh_rotation_reuse_introspect_and_revoke_http_test() {
  use tx <- test_helper.with_db
  let #(auth_ctx, oidc_ctx, post_pubsub, grant_revocations) =
    setup_contexts(tx, rate_limit.disabled())

  let grant_rev_sub = process.new_subject()
  pubsub.subscribe(grant_revocations, grant_rev_sub)

  let assert Ok(alice) = user.create(tx, "PkceAlice")
  let redirect_uri = "http://127.0.0.1:43210/callback"
  let scopes =
    set.from_list([
      scope.OpenId,
      scope.Profile,
      scope.OfflineAccess,
      scope.PostsRead,
    ])

  let assert Ok(#(public_app, None)) =
    client.create_app(
      tx,
      alice.id,
      "CLI Public App",
      False,
      client.Public,
      client.Native,
      [redirect_uri],
      scopes,
    )
  let assert Ok(#(conf_app, Some(conf_secret))) =
    client.create_app(
      tx,
      alice.id,
      "Confidential OAuth App",
      True,
      client.Private,
      client.Web,
      ["https://conf.example/cb"],
      scopes,
    )
  let assert Ok(#(other_conf, Some(other_secret))) =
    client.create_app(
      tx,
      alice.id,
      "Other Confidential App",
      True,
      client.Private,
      client.Web,
      ["https://other.example/cb"],
      scopes,
    )

  let dispatch = fn(req: wisp.Request) {
    router.handle_request_with_oidc(
      req,
      auth_ctx,
      oidc_ctx,
      post_pubsub,
      "127.0.0.1",
    )
  }

  let challenge = token.compute_pkce_s256_challenge(valid_pkce_verifier)

  // PublicApp auth code exchange + refresh rotation + reuse detection over HTTP
  let assert Ok(#(pub_consent_id, _, _)) =
    grant.upsert_consent(tx, alice.id, public_app.id, scopes)
  let assert Ok(#(pub_code, pub_grant_id)) =
    token.issue_authorization_code(
      tx,
      pub_consent_id,
      scopes,
      test_issuer,
      redirect_uri,
      challenge,
      Some("nonce-123"),
      "TestBrowser/1.0",
    )

  // Confidential client CANNOT omit client_secret on authorization_code -> 401 invalid_client
  let assert Ok(#(conf_consent_id, _, _)) =
    grant.upsert_consent(tx, alice.id, conf_app.id, scopes)
  let assert Ok(#(conf_code1, conf_grant1)) =
    token.issue_authorization_code(
      tx,
      conf_consent_id,
      scopes,
      test_issuer,
      "https://conf.example/cb",
      challenge,
      None,
      "TestBrowser/1.0",
    )
  let conf_no_secret =
    simulate.request(http.Post, "/oidc/token")
    |> simulate.form_body([
      #("grant_type", "authorization_code"),
      #("client_id", conf_app.client_id),
      #("code", conf_code1),
      #("redirect_uri", "https://conf.example/cb"),
      #("code_verifier", valid_pkce_verifier),
    ])
    |> dispatch
  assert conf_no_secret.status == 401
  assert parse_error_code(conf_no_secret) == "invalid_client"

  // Public client exchanges code without client_secret -> 200 with access_token + refresh_token
  let pub_exchange =
    simulate.request(http.Post, "/oidc/token")
    |> simulate.form_body([
      #("grant_type", "authorization_code"),
      #("client_id", public_app.client_id),
      #("code", pub_code),
      #("redirect_uri", redirect_uri),
      #("code_verifier", valid_pkce_verifier),
    ])
    |> dispatch
  assert pub_exchange.status == 200
  let assert #(pub_at1, _, Some(pub_rt1)) = parse_access_token(pub_exchange)
  assert string.starts_with(pub_rt1, "lote_rt_")

  // Replaying used authorization_code revokes the entire grant and publishes revocation!
  let pub_code_replay =
    simulate.request(http.Post, "/oidc/token")
    |> simulate.form_body([
      #("grant_type", "authorization_code"),
      #("client_id", public_app.client_id),
      #("code", pub_code),
      #("redirect_uri", redirect_uri),
      #("code_verifier", valid_pkce_verifier),
    ])
    |> dispatch
  assert pub_code_replay.status == 400
  assert parse_error_code(pub_code_replay) == "invalid_grant"
  assert process.receive(grant_rev_sub, 100) == Ok(pub_grant_id)

  // Previously issued pub_at1 is immediately invalidated
  assert dispatch(
      simulate.request(http.Get, "/api/v1/posts")
      |> request.set_header("authorization", "Bearer " <> pub_at1),
    ).status
    == 401

  // ConfidentialApp exchanges conf_code1 with Basic auth -> 200 (conf_at1, conf_rt1)
  let conf_exchange =
    simulate.request(http.Post, "/oidc/token")
    |> request.set_header(
      "authorization",
      basic_auth_header(conf_app.client_id, conf_secret.secret),
    )
    |> simulate.form_body([
      #("grant_type", "authorization_code"),
      #("code", conf_code1),
      #("redirect_uri", "https://conf.example/cb"),
      #("code_verifier", valid_pkce_verifier),
    ])
    |> dispatch
  assert conf_exchange.status == 200
  let assert #(conf_at1, _, Some(conf_rt1)) = parse_access_token(conf_exchange)

  // POST /oidc/introspect:
  // - Public client rejected (401 invalid_client)
  let pub_introspect =
    simulate.request(http.Post, "/oidc/introspect")
    |> simulate.form_body([
      #("client_id", public_app.client_id),
      #("token", conf_at1),
    ])
    |> dispatch
  assert pub_introspect.status == 401
  assert parse_error_code(pub_introspect) == "invalid_client"

  // - Other confidential client sees {"active": false} (cross-client isolation)
  let other_introspect =
    simulate.request(http.Post, "/oidc/introspect")
    |> request.set_header(
      "authorization",
      basic_auth_header(other_conf.client_id, other_secret.secret),
    )
    |> simulate.form_body([#("token", conf_at1)])
    |> dispatch
  assert other_introspect.status == 200
  let active_decoder = {
    use active <- decode.field("active", decode.bool)
    decode.success(active)
  }
  assert json.parse(simulate.read_body(other_introspect), active_decoder)
    == Ok(False)

  // - Owning confidential client sees full RFC 7662 active metadata
  let own_introspect =
    simulate.request(http.Post, "/oidc/introspect")
    |> request.set_header(
      "authorization",
      basic_auth_header(conf_app.client_id, conf_secret.secret),
    )
    |> simulate.form_body([#("token", conf_at1)])
    |> dispatch
  assert own_introspect.status == 200
  assert response.get_header(own_introspect, "cache-control") == Ok("no-store")
  assert response.get_header(own_introspect, "pragma") == Ok("no-cache")
  let introspect_decoder = {
    use active <- decode.field("active", decode.bool)
    use cid <- decode.field("client_id", decode.string)
    use iss <- decode.field("iss", decode.string)
    use aud <- decode.field("aud", decode.string)
    use tok_type <- decode.field("token_type", decode.string)
    use sub <- decode.field("sub", decode.string)
    use exp <- decode.field("exp", decode.int)
    use iat <- decode.field("iat", decode.int)
    decode.success(#(active, cid, iss, aud, tok_type, sub, exp > iat))
  }
  let assert Ok(#(True, introspected_cid, iss, aud, "Bearer", sub, True)) =
    json.parse(simulate.read_body(own_introspect), introspect_decoder)
  assert introspected_cid == conf_app.client_id
  assert iss == test_issuer
  assert aud == test_issuer
  assert string.length(sub) == 36

  // Refresh token rotation with narrowed scope -> 200 (conf_at2, conf_rt2)
  let rotate_resp =
    simulate.request(http.Post, "/oidc/token")
    |> request.set_header(
      "authorization",
      basic_auth_header(conf_app.client_id, conf_secret.secret),
    )
    |> simulate.form_body([
      #("grant_type", "refresh_token"),
      #("refresh_token", conf_rt1),
      #("scope", "posts:read"),
    ])
    |> dispatch
  assert rotate_resp.status == 200
  let assert #(conf_at2, rotated_scope, Some(conf_rt2)) =
    parse_access_token(rotate_resp)
  assert rotated_scope == "posts:read"
  assert conf_rt2 != conf_rt1

  // Replaying rotated-out conf_rt1 triggers reuse detection -> revokes grant + publishes revocation!
  let rt_replay =
    simulate.request(http.Post, "/oidc/token")
    |> request.set_header(
      "authorization",
      basic_auth_header(conf_app.client_id, conf_secret.secret),
    )
    |> simulate.form_body([
      #("grant_type", "refresh_token"),
      #("refresh_token", conf_rt1),
    ])
    |> dispatch
  assert rt_replay.status == 400
  assert parse_error_code(rt_replay) == "invalid_grant"
  assert process.receive(grant_rev_sub, 100) == Ok(conf_grant1)

  // Both conf_at2 and conf_rt2 are now inactive!
  let after_reuse_introspect =
    simulate.request(http.Post, "/oidc/introspect")
    |> request.set_header(
      "authorization",
      basic_auth_header(conf_app.client_id, conf_secret.secret),
    )
    |> simulate.form_body([#("token", conf_at2)])
    |> dispatch
  assert json.parse(simulate.read_body(after_reuse_introspect), active_decoder)
    == Ok(False)

  // POST /oidc/revoke on a fresh token revokes grant + publishes revocation + returns 200 {}
  let assert Ok(#(conf_code2, conf_grant2)) =
    token.issue_authorization_code(
      tx,
      conf_consent_id,
      scopes,
      test_issuer,
      "https://conf.example/cb",
      challenge,
      None,
      "TestBrowser/1.0",
    )
  let conf_ex2 =
    simulate.request(http.Post, "/oidc/token")
    |> request.set_header(
      "authorization",
      basic_auth_header(conf_app.client_id, conf_secret.secret),
    )
    |> simulate.form_body([
      #("grant_type", "authorization_code"),
      #("code", conf_code2),
      #("redirect_uri", "https://conf.example/cb"),
      #("code_verifier", valid_pkce_verifier),
    ])
    |> dispatch
  let assert #(conf_at3, _, Some(conf_rt3)) = parse_access_token(conf_ex2)

  let revoke_resp =
    simulate.request(http.Post, "/oidc/revoke")
    |> request.set_header(
      "authorization",
      basic_auth_header(conf_app.client_id, conf_secret.secret),
    )
    |> simulate.form_body([#("token", conf_rt3)])
    |> dispatch
  assert revoke_resp.status == 200
  assert simulate.read_body(revoke_resp) == "{}"
  assert response.get_header(revoke_resp, "cache-control") == Ok("no-store")
  assert response.get_header(revoke_resp, "pragma") == Ok("no-cache")
  assert process.receive(grant_rev_sub, 100) == Ok(conf_grant2)

  assert dispatch(
      simulate.request(http.Get, "/api/v1/posts")
      |> request.set_header("authorization", "Bearer " <> conf_at3),
    ).status
    == 401
}

pub fn api_v1_posts_crud_scopes_pagination_realtime_and_privilege_separation_test() {
  use tx <- test_helper.with_db
  let #(auth_ctx, oidc_ctx, post_pubsub, _grant_revocations) =
    setup_contexts(tx, rate_limit.disabled())

  let post_events_sub = process.new_subject()
  pubsub.subscribe(post_pubsub, post_events_sub)

  let assert Ok(alice) = user.create(tx, "AliceApiAuthor")
  let assert Ok(bob) = user.create(tx, "BobApiAuthor")

  let assert Ok(read_bot) =
    client.create_subordinate_bot(
      tx,
      alice.id,
      "Read Only Bot",
      set.from_list([scope.PostsRead]),
      "ro",
      None,
    )
  let assert Ok(rw_bot) =
    client.create_subordinate_bot(
      tx,
      alice.id,
      "Read Write Bot",
      set.from_list([scope.PostsRead, scope.PostsWrite]),
      "rw",
      None,
    )
  let assert Ok(full_bot) =
    client.create_subordinate_bot(
      tx,
      alice.id,
      "Full Bot",
      set.from_list([scope.PostsRead, scope.PostsWrite, scope.PostsDelete]),
      "full",
      None,
    )
  let assert Ok(bob_del_bot) =
    client.create_subordinate_bot(
      tx,
      bob.id,
      "Bob Delete Bot",
      set.from_list([scope.PostsDelete]),
      "del",
      None,
    )

  let mint = fn(b: client.CreatedBot) {
    let assert Ok(issued) =
      token.issue_client_credentials(
        oidc_ctx,
        b.client.client_id,
        b.secret.secret,
        None,
        None,
        "TestRunner/1.0",
      )
    issued.access_token
  }
  let ro_token = mint(read_bot)
  let rw_token = mint(rw_bot)
  let full_token = mint(full_bot)
  let bob_del_token = mint(bob_del_bot)

  let dispatch = fn(req: wisp.Request) {
    router.handle_request_with_oidc(
      req,
      auth_ctx,
      oidc_ctx,
      post_pubsub,
      "127.0.0.1",
    )
  }

  // 1. Missing or non-Bearer header -> 401 unauthorized + WWW-Authenticate: Bearer realm="lote"
  let no_auth = dispatch(simulate.request(http.Get, "/api/v1/posts"))
  assert no_auth.status == 401
  assert parse_error_code(no_auth) == "unauthorized"
  assert response.get_header(no_auth, "www-authenticate")
    == Ok("Bearer realm=\"lote\"")

  let basic_on_api =
    simulate.request(http.Get, "/api/v1/posts")
    |> request.set_header("authorization", "Basic dXNlcjpwYXNz")
    |> dispatch
  assert basic_on_api.status == 401
  assert parse_error_code(basic_on_api) == "unauthorized"

  // Invalid Bearer token -> 401 invalid_token + WWW-Authenticate error="invalid_token"
  let bad_tok =
    simulate.request(http.Get, "/api/v1/posts")
    |> request.set_header("authorization", "Bearer lote_at_nonexistent")
    |> dispatch
  assert bad_tok.status == 401
  assert parse_error_code(bad_tok) == "invalid_token"
  assert response.get_header(bad_tok, "www-authenticate")
    == Ok("Bearer realm=\"lote\", error=\"invalid_token\"")

  // 2. Insufficient scope -> 403 + RFC 6750 WWW-Authenticate with required scope
  let ro_write =
    simulate.request(http.Post, "/api/v1/posts")
    |> request.set_header("authorization", "Bearer " <> ro_token)
    |> simulate.json_body(json.object([#("body", json.string("nope"))]))
    |> dispatch
  assert ro_write.status == 403
  assert parse_error_code(ro_write) == "insufficient_scope"
  assert response.get_header(ro_write, "www-authenticate")
    == Ok(
      "Bearer realm=\"lote\", error=\"insufficient_scope\", scope=\"posts:write\"",
    )

  // 3. POST /api/v1/posts validation, creation, cross-origin Origin support, and post_pubsub event
  let malformed_json =
    simulate.request(http.Post, "/api/v1/posts")
    |> request.set_header("authorization", "Bearer " <> rw_token)
    |> simulate.string_body("{not valid json")
    |> request.set_header("content-type", "application/json")
    |> dispatch
  assert malformed_json.status == 400
  assert parse_error_code(malformed_json) == "invalid_request"

  let empty_body_post =
    simulate.request(http.Post, "/api/v1/posts")
    |> request.set_header("authorization", "Bearer " <> rw_token)
    |> simulate.json_body(json.object([#("body", json.string("   "))]))
    |> dispatch
  assert empty_body_post.status == 422
  assert parse_error_code(empty_body_post) == "invalid_body"

  let create_post_decoder = {
    use post <- decode.field("post", {
      use id <- decode.field("id", decode.string)
      use author <- decode.field("author_name", decode.string)
      use body <- decode.field("body", decode.string)
      use created_at <- decode.field("created_at", decode.string)
      decode.success(#(id, author, body, created_at))
    })
    decode.success(post)
  }

  let create1_resp =
    simulate.request(http.Post, "/api/v1/posts")
    |> request.set_header("authorization", "bearer " <> rw_token)
    |> request.set_header("origin", "https://bot-worker.example")
    |> request.set_header("cookie", "lote_session=ignored")
    |> simulate.json_body(
      json.object([#("body", json.string("First API post"))]),
    )
    |> dispatch
  assert create1_resp.status == 201
  let assert Ok(#(post1_id, "AliceApiAuthor", "First API post", post1_ts)) =
    json.parse(simulate.read_body(create1_resp), create_post_decoder)
  assert response.get_header(create1_resp, "location")
    == Ok("/posts/" <> post1_id)
  assert string.contains(post1_ts, "T")

  // Realtime PubSub received timeline.Created!
  let assert Ok(timeline.Created(pub_post1)) =
    process.receive(post_events_sub, 100)
  assert pub_post1.id == post1_id
  assert pub_post1.author_name == "AliceApiAuthor"
  assert pub_post1.body == "First API post"

  // Create two more posts for pagination checks
  let create2_resp =
    simulate.request(http.Post, "/api/v1/posts")
    |> request.set_header("authorization", "Bearer " <> rw_token)
    |> simulate.json_body(
      json.object([#("body", json.string("Second API post"))]),
    )
    |> dispatch
  let assert Ok(#(post2_id, _, _, _)) =
    json.parse(simulate.read_body(create2_resp), create_post_decoder)
  let assert Ok(timeline.Created(_)) = process.receive(post_events_sub, 100)

  let create3_resp =
    simulate.request(http.Post, "/api/v1/posts")
    |> request.set_header("authorization", "Bearer " <> rw_token)
    |> simulate.json_body(
      json.object([#("body", json.string("Third API post"))]),
    )
    |> dispatch
  let assert Ok(#(post3_id, _, _, _)) =
    json.parse(simulate.read_body(create3_resp), create_post_decoder)
  let assert Ok(timeline.Created(_)) = process.receive(post_events_sub, 100)

  // 4. GET /api/v1/posts & GET /api/v1/posts/:id & pagination validation
  let list_ids_decoder = {
    use ids <- decode.field(
      "posts",
      decode.list({
        use id <- decode.field("id", decode.string)
        decode.success(id)
      }),
    )
    decode.success(ids)
  }

  let list_resp =
    simulate.request(http.Get, "/api/v1/posts?limit=2")
    |> request.set_header("authorization", "Bearer " <> ro_token)
    |> dispatch
  assert list_resp.status == 200
  assert json.parse(simulate.read_body(list_resp), list_ids_decoder)
    == Ok([post3_id, post2_id])

  let before_resp =
    simulate.request(http.Get, "/api/v1/posts?before=" <> post2_id)
    |> request.set_header("authorization", "Bearer " <> ro_token)
    |> dispatch
  assert before_resp.status == 200
  assert json.parse(simulate.read_body(before_resp), list_ids_decoder)
    == Ok([post1_id])

  let after_resp =
    simulate.request(http.Get, "/api/v1/posts?after=" <> post1_id)
    |> request.set_header("authorization", "Bearer " <> ro_token)
    |> dispatch
  assert after_resp.status == 200
  assert json.parse(simulate.read_body(after_resp), list_ids_decoder)
    == Ok([post3_id, post2_id])

  // Invalid query parameters -> 400 invalid_request
  assert dispatch(
      simulate.request(http.Get, "/api/v1/posts?limit=0")
      |> request.set_header("authorization", "Bearer " <> ro_token),
    ).status
    == 400
  assert dispatch(
      simulate.request(http.Get, "/api/v1/posts?limit=51")
      |> request.set_header("authorization", "Bearer " <> ro_token),
    ).status
    == 400
  assert dispatch(
      simulate.request(http.Get, "/api/v1/posts?before=not-a-uuid")
      |> request.set_header("authorization", "Bearer " <> ro_token),
    ).status
    == 400
  assert dispatch(
      simulate.request(
        http.Get,
        "/api/v1/posts?before=" <> post2_id <> "&after=" <> post1_id,
      )
      |> request.set_header("authorization", "Bearer " <> ro_token),
    ).status
    == 400

  // GET /api/v1/posts/:id
  let show_resp =
    simulate.request(http.Get, "/api/v1/posts/" <> post1_id)
    |> request.set_header("authorization", "Bearer " <> ro_token)
    |> dispatch
  assert show_resp.status == 200

  let missing_show =
    simulate.request(
      http.Get,
      "/api/v1/posts/00000000-0000-0000-0000-000000000000",
    )
    |> request.set_header("authorization", "Bearer " <> ro_token)
    |> dispatch
  assert missing_show.status == 404
  assert parse_error_code(missing_show) == "not_found"

  // 5. DELETE /api/v1/posts/:id scope & ownership & post_pubsub Deleted event
  let rw_delete =
    simulate.request(http.Delete, "/api/v1/posts/" <> post1_id)
    |> request.set_header("authorization", "Bearer " <> rw_token)
    |> dispatch
  assert rw_delete.status == 403
  assert response.get_header(rw_delete, "www-authenticate")
    == Ok(
      "Bearer realm=\"lote\", error=\"insufficient_scope\", scope=\"posts:delete\"",
    )

  // Bob's bot cannot delete Alice's post -> 404
  let bob_delete =
    simulate.request(http.Delete, "/api/v1/posts/" <> post1_id)
    |> request.set_header("authorization", "Bearer " <> bob_del_token)
    |> dispatch
  assert bob_delete.status == 404

  // Alice's full-scope bot deletes post1 -> 204 + Deleted event
  let ok_delete =
    simulate.request(
      http.Delete,
      "/api/v1/posts/" <> string.uppercase(post1_id),
    )
    |> request.set_header("authorization", "Bearer " <> full_token)
    |> dispatch
  assert ok_delete.status == 204
  assert simulate.read_body(ok_delete) == ""
  assert process.receive(post_events_sub, 100)
    == Ok(timeline.Deleted(string.lowercase(post1_id)))
  assert post_repo.find_by_id(tx, post1_id) == Ok(None)

  // Unknown /api/* path and unsupported method return JSON 404 / 405
  let unknown_api = dispatch(simulate.request(http.Get, "/api/v1/unknown"))
  assert unknown_api.status == 404
  assert parse_error_code(unknown_api) == "not_found"

  let put_posts = dispatch(simulate.request(http.Put, "/api/v1/posts"))
  assert put_posts.status == 405
  assert parse_error_code(put_posts) == "method_not_allowed"

  // 6. Strict privilege separation: Bearer tokens NEVER authenticate /settings/clients or /sessions!
  let bearer_clients_get =
    simulate.browser_request(http.Get, "/settings/clients")
    |> request.set_header("authorization", "Bearer " <> full_token)
    |> dispatch
  assert bearer_clients_get.status == 303
  assert response.get_header(bearer_clients_get, "location")
    == Ok("/auth/login")

  let bearer_sessions_get =
    simulate.browser_request(http.Get, "/sessions")
    |> request.set_header("authorization", "Bearer " <> full_token)
    |> dispatch
  assert bearer_sessions_get.status == 303
  assert response.get_header(bearer_sessions_get, "location")
    == Ok("/auth/login")

  // Even with a valid CSRF cookie + Bearer header, POST /settings/clients/bots returns 401 without session cookie
  let login_page_req = simulate.browser_request(http.Get, "/auth/login")
  let login_page_resp = dispatch(login_page_req)
  let csrf_tok = extract_form_csrf_token(simulate.read_body(login_page_resp))

  let bearer_clients_post =
    simulate.browser_request(http.Post, "/settings/clients/bots")
    |> simulate.session(login_page_req, login_page_resp)
    |> request.set_header("authorization", "Bearer " <> full_token)
    |> simulate.form_body([
      #(csrf.form_field_name, csrf_tok),
      #("name", "Escalation Bot"),
      #("scopes", "posts:read"),
    ])
    |> dispatch
  assert bearer_clients_post.status == 401
}

pub fn two_tier_rate_limits_and_oidc_endpoint_rate_limits_test() {
  use tx <- test_helper.with_db
  let assert Ok(limiter) = rate_limit.start_memory(test_secret)
  let #(auth_ctx, oidc_ctx, post_pubsub, _grant_revocations) =
    setup_contexts(tx, limiter)

  let assert Ok(alice) = user.create(tx, "TieredAlice")
  let assert Ok(carol) = user.create(tx, "MultiBotCarol")

  // Part 1: Single Bot hits its per-client write burst (5), leaving owner's remaining user write quota (5) intact!
  let assert Ok(alice_bot) =
    client.create_subordinate_bot(
      tx,
      alice.id,
      "Alice Noisy Bot",
      set.from_list([scope.PostsWrite]),
      "v1",
      None,
    )
  let assert Ok(alice_bot_tok) =
    token.issue_client_credentials(
      oidc_ctx,
      alice_bot.client.client_id,
      alice_bot.secret.secret,
      None,
      None,
      "Bot/1.0",
    )

  let dispatch_ip = fn(req: wisp.Request, ip: String) {
    router.handle_request_with_oidc(req, auth_ctx, oidc_ctx, post_pubsub, ip)
  }

  let post_via_token = fn(tok: String) {
    simulate.request(http.Post, "/api/v1/posts")
    |> request.set_header("authorization", "Bearer " <> tok)
    |> simulate.json_body(json.object([#("body", json.string("rate test"))]))
    |> dispatch_ip("127.0.0.1")
  }

  // First 5 writes by alice_bot succeed (burst = 5)
  let _ =
    int.range(
      from: 1,
      to: bearer.client_write_policy.burst + 1,
      with: Nil,
      run: fn(_, _) {
        assert post_via_token(alice_bot_tok.access_token).status == 201
        Nil
      },
    )

  // 6th write by alice_bot is throttled at Tier 1 (client bucket) BEFORE touching Alice's user bucket!
  let throttled_bot_resp = post_via_token(alice_bot_tok.access_token)
  assert throttled_bot_resp.status == 429
  assert parse_error_code(throttled_bot_resp) == "too_many_requests"
  let assert Ok(retry_hdr) =
    response.get_header(throttled_bot_resp, "retry-after")
  let assert Ok(retry_sec) = int.parse(retry_hdr)
  assert retry_sec >= 1

  // Even repeated rejected attempts by alice_bot do NOT drain Alice's user write bucket!
  assert post_via_token(alice_bot_tok.access_token).status == 429
  assert post_via_token(alice_bot_tok.access_token).status == 429

  // Alice in her human browser session STILL has 5 writes remaining (10 - 5 = 5)!
  let login_req = simulate.browser_request(http.Post, "/auth/password/login")
  let assert Ok(alice_login) =
    session.create(wisp.ok(), login_req, tx, test_secret, alice)
  let sess_req =
    simulate.browser_request(http.Get, "/sessions")
    |> simulate.session(login_req, alice_login)
  let sess_resp = dispatch_ip(sess_req, "127.0.0.1")
  let alice_csrf = extract_form_csrf_token(simulate.read_body(sess_resp))

  let remaining_human_writes =
    http_rate_limit.write_policy.burst - bearer.client_write_policy.burst
  assert remaining_human_writes == 5

  let _ =
    int.range(from: 1, to: remaining_human_writes + 1, with: Nil, run: fn(_, _) {
      let resp =
        simulate.browser_request(http.Post, "/sessions/revoke-others")
        |> simulate.session(sess_req, sess_resp)
        |> simulate.form_body([#(csrf.form_field_name, alice_csrf)])
        |> dispatch_ip("127.0.0.1")
      assert resp.status == 303
      Nil
    })

  // Now Alice's shared user write ceiling (10) is exhausted -> 11th total write returns 429
  let human_over_resp =
    simulate.browser_request(http.Post, "/sessions/revoke-others")
    |> simulate.session(sess_req, sess_resp)
    |> simulate.form_body([#(csrf.form_field_name, alice_csrf)])
    |> dispatch_ip("127.0.0.1")
  assert human_over_resp.status == 429

  // Part 2: Multiple Subordinate Bots owned by Carol CANNOT exceed Carol's total user write ceiling (burst 10)!
  let mint_carol_bot = fn(label: String) {
    let assert Ok(b) =
      client.create_subordinate_bot(
        tx,
        carol.id,
        "Carol Bot " <> label,
        set.from_list([scope.PostsWrite]),
        label,
        None,
      )
    let assert Ok(tok) =
      token.issue_client_credentials(
        oidc_ctx,
        b.client.client_id,
        b.secret.secret,
        None,
        None,
        "Bot/1.0",
      )
    tok.access_token
  }

  let bot_a_tok = mint_carol_bot("a")
  let bot_b_tok = mint_carol_bot("b")
  let bot_c_tok = mint_carol_bot("c")

  // bot_a uses 5 writes, bot_b uses 5 writes -> total 10 writes on Carol's account
  let _ =
    int.range(from: 1, to: 6, with: Nil, run: fn(_, _) {
      assert post_via_token(bot_a_tok).status == 201
      Nil
    })
  let _ =
    int.range(from: 1, to: 6, with: Nil, run: fn(_, _) {
      assert post_via_token(bot_b_tok).status == 201
      Nil
    })

  // bot_c has a fresh client bucket, yet its very 1st write is blocked by Tier 2 (Carol's user write ceiling)!
  let bot_c_blocked = post_via_token(bot_c_tok)
  assert bot_c_blocked.status == 429
  assert parse_error_code(bot_c_blocked) == "too_many_requests"

  // Part 3: /oidc/token per-client (burst 20) and per-IP (burst 30) rate limits
  let endpoint_ip = "198.51.100.77"
  let _ =
    int.range(
      from: 1,
      to: oidc_handler.client_endpoint_policy.burst + 1,
      with: Nil,
      run: fn(_, _) {
        let r =
          simulate.request(http.Post, "/oidc/token")
          |> request.set_header(
            "authorization",
            basic_auth_header(
              alice_bot.client.client_id,
              alice_bot.secret.secret,
            ),
          )
          |> simulate.form_body([#("grant_type", "client_credentials")])
          |> dispatch_ip(endpoint_ip)
        assert r.status == 200
        Nil
      },
    )

  let client_rl_resp =
    simulate.request(http.Post, "/oidc/token")
    |> request.set_header(
      "authorization",
      basic_auth_header(alice_bot.client.client_id, alice_bot.secret.secret),
    )
    |> simulate.form_body([#("grant_type", "client_credentials")])
    |> dispatch_ip("198.51.100.78")
  assert client_rl_resp.status == 429
  assert parse_error_code(client_rl_resp) == "temporarily_unavailable"
  assert response.get_header(client_rl_resp, "cache-control") == Ok("no-store")
  assert response.get_header(client_rl_resp, "pragma") == Ok("no-cache")
  let assert Ok(_) = response.get_header(client_rl_resp, "retry-after")

  // Exhaust IP burst (30) on a fresh IP
  let flood_ip = "203.0.113.200"
  let _ =
    int.range(
      from: 1,
      to: oidc_handler.ip_endpoint_policy.burst + 1,
      with: Nil,
      run: fn(_, _) {
        let r =
          simulate.request(http.Post, "/oidc/revoke")
          |> simulate.form_body([#("token", "x")])
          |> dispatch_ip(flood_ip)
        assert r.status == 401
        Nil
      },
    )
  let ip_rl_resp =
    simulate.request(http.Post, "/oidc/revoke")
    |> simulate.form_body([#("token", "x")])
    |> dispatch_ip(flood_ip)
  assert ip_rl_resp.status == 429
  assert parse_error_code(ip_rl_resp) == "temporarily_unavailable"

  rate_limit.stop_memory(limiter)
}

pub fn grant_revocations_pubsub_adapter_memory_and_postgres_test() {
  use tx <- test_helper.with_db
  let assert Ok(mem_pubsub) =
    lote.start_grant_revocations_pubsub(config.MemoryPubSub, tx, "")
  let sub = process.new_subject()
  pubsub.subscribe(mem_pubsub, sub)
  pubsub.publish(mem_pubsub, "0193a000-0000-7000-8000-000000000001")
  assert process.receive(sub, 100) == Ok("0193a000-0000-7000-8000-000000000001")

  let pg_adapter =
    lote.grant_revocations_adapter(
      config.PostgresPubSub,
      tx,
      "postgres://localhost/lote",
    )
  let assert pubsub.Postgres(channel:, encode:, decode:, ..) = pg_adapter
  assert channel == lote.grant_revocations_channel
  assert encode("gid-1") == "gid-1"
  assert decode("gid-1") == Ok("gid-1")
  assert decode("") == Error(Nil)
}
