import gleam/bit_array
import gleam/dynamic/decode
import gleam/erlang/process
import gleam/http
import gleam/http/request
import gleam/http/response
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/set
import gleam/string
import gleam/uri
import lote/auth.{Auth, Password}
import lote/auth/password
import lote/auth/session
import lote/auth/user
import lote/oidc
import lote/oidc/client
import lote/oidc/grant
import lote/oidc/scope
import lote/oidc/token
import lote/rate_limit
import lote/realtime/pubsub
import lote/test_helper
import lote/web/auth/return_to
import lote/web/components/timeline
import lote/web/csrf
import lote/web/router
import pog
import wisp
import wisp/simulate

const test_secret = "oauth_phase2_secret_key_base_0123456789abcdefghijklmnopqr"

const test_issuer = "https://lote.example"

fn setup_contexts(
  tx: pog.Connection,
) -> #(
  auth.Auth,
  oidc.Oidc,
  pubsub.PubSub(timeline.PostEvent),
  pubsub.PubSub(String),
  fn(wisp.Request) -> wisp.Response,
) {
  let assert Ok(session_revocations) = pubsub.start()
  let assert Ok(grant_revocations) = pubsub.start()
  let assert Ok(post_pubsub) = pubsub.start()
  let limiter = rate_limit.disabled()

  let auth_ctx =
    Auth(
      db: tx,
      secret_key_base: test_secret,
      methods: [Password],
      session_revocations:,
      rate_limiter: limiter,
    )
  let oidc_ctx = oidc.new(tx, test_issuer, grant_revocations, limiter)
  let dispatch = fn(req: wisp.Request) {
    router.handle_request_with_oidc(
      req,
      auth_ctx,
      oidc_ctx,
      post_pubsub,
      "198.51.100.42",
    )
  }
  #(auth_ctx, oidc_ctx, post_pubsub, grant_revocations, dispatch)
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
  let assert Ok(#(_, rest)) = string.split_once(tag, "value=\"")
  let assert Ok(#(val, _)) = string.split_once(rest, "\"")
  val
}

fn basic_auth_header(raw_id: String, raw_secret: String) -> String {
  let credentials = raw_id <> ":" <> raw_secret
  "Basic " <> bit_array.base64_encode(<<credentials:utf8>>, True)
}

fn parse_token_response(resp: wisp.Response) -> #(String, Option(String)) {
  let decoder = {
    use at <- decode.field("access_token", decode.string)
    use rt <- decode.optional_field(
      "refresh_token",
      None,
      decode.optional(decode.string),
    )
    decode.success(#(at, rt))
  }
  let assert Ok(parsed) = json.parse(simulate.read_body(resp), decoder)
  parsed
}

fn parse_location_query(
  resp: wisp.Response,
) -> #(String, List(#(String, String))) {
  let assert Ok(loc) = response.get_header(resp, "location")
  let assert Ok(parsed) = uri.parse(loc)
  let assert Ok(query_pairs) =
    parsed.query |> option.unwrap("") |> uri.parse_query
  #(loc, query_pairs)
}

pub fn return_to_sanitizer_blocks_open_redirects_and_self_loops_test() {
  assert return_to.sanitize(None) == None
  assert return_to.sanitize(Some("")) == None
  assert return_to.sanitize(Some("https://evil.example/cb")) == None
  assert return_to.sanitize(Some("//evil.example/cb")) == None
  assert return_to.sanitize(Some("/\\evil.example")) == None
  assert return_to.sanitize(Some("/foo\\bar")) == None
  assert return_to.sanitize(Some("javascript:alert(1)")) == None
  assert return_to.sanitize(Some("/oidc/authorize#frag")) == None
  assert return_to.sanitize(Some("/oidc/authorize\r\nSet-Cookie: bad")) == None
  assert return_to.sanitize(Some("/oidc/authorize with space")) == None
  assert return_to.sanitize(Some("/auth/login")) == None
  assert return_to.sanitize(Some("/auth/login?return_to=%2F")) == None
  assert return_to.sanitize(Some("/auth/password/login")) == None
  assert return_to.sanitize(Some("/auth/logout")) == None
  assert return_to.sanitize(Some("/" <> string.repeat("a", 2048))) == None

  let valid = "/oidc/authorize?client_id=cli_123&state=a%2Bb"
  assert return_to.sanitize(Some(valid)) == Some(valid)
}

pub fn authorize_rejects_invalid_client_redirect_uri_and_duplicates_without_redirecting_test() {
  use tx <- test_helper.with_db
  let #(_auth_ctx, _oidc_ctx, _post_pubsub, _grant_revocations, dispatch) =
    setup_contexts(tx)

  let assert Ok(alice) = user.create(tx, "PreRedirectAlice")
  let login_req = simulate.browser_request(http.Post, "/auth/password/login")
  let assert Ok(alice_login) =
    session.create(wisp.ok(), login_req, tx, test_secret, alice)

  let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  let challenge = token.compute_pkce_s256_challenge(verifier)
  let valid_redirect = "https://app.example/callback"

  let assert Ok(#(web_app, _)) =
    client.create_app(
      tx,
      alice.id,
      "Web App",
      True,
      client.Private,
      client.Web,
      [valid_redirect],
      set.from_list([scope.PostsRead]),
    )
  let assert Ok(bot) =
    client.create_subordinate_bot(
      tx,
      alice.id,
      "Bot Only",
      set.from_list([scope.PostsRead]),
      "default",
      None,
    )

  let authed_get = fn(path_and_query: String) {
    simulate.browser_request(http.Get, path_and_query)
    |> simulate.session(login_req, alice_login)
    |> dispatch
  }

  // 1. Unknown client_id -> 400 HTML error, NO Location header
  let unknown_resp =
    authed_get(
      "/oidc/authorize?client_id=cli_00000000000000000000000000000000&redirect_uri="
      <> uri.percent_encode(valid_redirect)
      <> "&response_type=code&scope=posts%3Aread&code_challenge="
      <> challenge
      <> "&code_challenge_method=S256",
    )
  assert unknown_resp.status == 400
  assert response.get_header(unknown_resp, "location") == Error(Nil)
  assert response.get_header(unknown_resp, "x-frame-options") == Ok("DENY")
  assert response.get_header(unknown_resp, "referrer-policy")
    == Ok("no-referrer")
  let assert Ok(csp) =
    response.get_header(unknown_resp, "content-security-policy")
  assert string.contains(csp, "frame-ancestors 'none'")
  assert !string.contains(csp, "form-action")

  // 2. SubordinateBot client_id -> 400 HTML error, NO redirect
  let bot_resp =
    authed_get(
      "/oidc/authorize?client_id="
      <> bot.client.client_id
      <> "&redirect_uri="
      <> uri.percent_encode(valid_redirect)
      <> "&response_type=code&scope=posts%3Aread&code_challenge="
      <> challenge
      <> "&code_challenge_method=S256",
    )
  assert bot_resp.status == 400
  assert response.get_header(bot_resp, "location") == Error(Nil)

  // 3. Mismatched redirect_uri -> 400 HTML error, NO redirect
  let bad_redirect_resp =
    authed_get(
      "/oidc/authorize?client_id="
      <> web_app.client_id
      <> "&redirect_uri="
      <> uri.percent_encode("https://evil.example/steal")
      <> "&response_type=code&scope=posts%3Aread&code_challenge="
      <> challenge
      <> "&code_challenge_method=S256",
    )
  assert bad_redirect_resp.status == 400
  assert response.get_header(bad_redirect_resp, "location") == Error(Nil)

  // 4. Duplicate parameter (e.g. two scope or two redirect_uri values) -> 400 HTML error, NO redirect
  let dup_resp =
    authed_get(
      "/oidc/authorize?client_id="
      <> web_app.client_id
      <> "&redirect_uri="
      <> uri.percent_encode(valid_redirect)
      <> "&response_type=code&scope=posts%3Aread&scope=posts%3Awrite&code_challenge="
      <> challenge
      <> "&code_challenge_method=S256",
    )
  assert dup_resp.status == 400
  assert response.get_header(dup_resp, "location") == Error(Nil)
}

pub fn end_to_end_login_return_to_consent_skip_step_up_and_token_exchange_test() {
  use tx <- test_helper.with_db
  let #(_auth_ctx, _oidc_ctx, _post_pubsub, _grant_revocations, dispatch) =
    setup_contexts(tx)

  let assert Ok(alice) = user.create(tx, "AuthFlowAlice")
  let assert Ok(Nil) =
    password.create(tx, alice.id, "alice_oauth", "secretpass123")
  let assert Ok(bob) = user.create(tx, "AuthFlowBob")
  let assert Ok(Nil) = password.create(tx, bob.id, "bob_oauth", "secretpass123")

  // Alice logs in first to register a Private Confidential Web App & a Public Native CLI App via /settings/clients/apps
  let init_login_page =
    dispatch(simulate.browser_request(http.Get, "/auth/login"))
  let init_csrf = extract_form_csrf_token(simulate.read_body(init_login_page))
  let alice_sess_req =
    simulate.browser_request(http.Post, "/auth/password/login")
    |> simulate.session(
      simulate.browser_request(http.Get, "/auth/login"),
      init_login_page,
    )
    |> simulate.form_body([
      #(csrf.form_field_name, init_csrf),
      #("login_id", "alice_oauth"),
      #("password", "secretpass123"),
    ])
  let alice_sess_resp = dispatch(alice_sess_req)
  assert alice_sess_resp.status == 303

  let clients_get_req =
    simulate.browser_request(http.Get, "/settings/clients")
    |> simulate.session(alice_sess_req, alice_sess_resp)
  let clients_get_resp = dispatch(clients_get_req)
  assert clients_get_resp.status == 200
  let clients_csrf =
    extract_form_csrf_token(simulate.read_body(clients_get_resp))

  let web_redirect = "https://client.example/oauth/callback"
  let create_conf_resp =
    simulate.browser_request(http.Post, "/settings/clients/apps")
    |> simulate.session(clients_get_req, clients_get_resp)
    |> simulate.form_body([
      #(csrf.form_field_name, clients_csrf),
      #("name", "Alice Reader Web"),
      #("client_type", "confidential"),
      #("visibility", "private"),
      #("application_type", "web"),
      #("redirect_uris", web_redirect),
      #("scopes", "posts:read"),
      #("scopes", "posts:write"),
      #("scopes", "offline_access"),
    ])
    |> dispatch
  assert create_conf_resp.status == 200
  let conf_body = simulate.read_body(create_conf_resp)
  assert string.contains(conf_body, "Confidential OAuth app created")

  let create_pub_resp =
    simulate.browser_request(http.Post, "/settings/clients/apps")
    |> simulate.session(clients_get_req, clients_get_resp)
    |> simulate.form_body([
      #(csrf.form_field_name, clients_csrf),
      #("name", "Community CLI"),
      #("client_type", "public"),
      #("visibility", "public"),
      #("application_type", "native"),
      #("redirect_uris", "http://127.0.0.1/cb?mode=cli"),
      #("scopes", "posts:read"),
      #("scopes", "posts:write"),
    ])
    |> dispatch
  assert create_pub_resp.status == 303

  let assert Ok(owner_clients) = client.list_for_owner(tx, alice.id)
  let assert Ok(#(conf_client, _)) =
    list.find(owner_clients, fn(p) { p.0.kind == client.ConfidentialApp })
  let assert Ok(#(pub_client, pub_secrets)) =
    list.find(owner_clients, fn(p) { p.0.kind == client.PublicApp })
  assert pub_secrets == []
  // Mint a known rotated secret on conf_client so we can exchange tokens cleanly
  let assert Ok(conf_sec) =
    client.create_secret(tx, alice.id, conf_client.client_id, "test", None)

  let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  let challenge = token.compute_pkce_s256_challenge(verifier)

  // Unauthenticated GET /oidc/authorize with prompt=none -> redirects to redirect_uri with error=login_required + iss + state
  let prompt_none_unauth =
    dispatch(simulate.browser_request(
      http.Get,
      "/oidc/authorize?client_id="
        <> conf_client.client_id
        <> "&redirect_uri="
        <> uri.percent_encode(web_redirect)
        <> "&response_type=code&scope=posts%3Aread&code_challenge="
        <> challenge
        <> "&code_challenge_method=S256&prompt=none&state=st_none",
    ))
  assert prompt_none_unauth.status == 303
  let #(_, pnone_q) = parse_location_query(prompt_none_unauth)
  assert list.key_find(pnone_q, "error") == Ok("login_required")
  assert list.key_find(pnone_q, "iss") == Ok(test_issuer)
  assert list.key_find(pnone_q, "state") == Ok("st_none")

  // Unauthenticated GET /oidc/authorize -> redirects to /auth/login?return_to=... preserving '+' in state!
  let authz_path =
    "/oidc/authorize?client_id="
    <> conf_client.client_id
    <> "&redirect_uri="
    <> uri.percent_encode(web_redirect)
    <> "&response_type=code&scope="
    <> uri.percent_encode("posts:read offline_access")
    <> "&code_challenge="
    <> challenge
    <> "&code_challenge_method=S256&state="
    <> uri.percent_encode("a+b=1")

  let unauth_authz_resp =
    dispatch(simulate.browser_request(http.Get, authz_path))
  assert unauth_authz_resp.status == 303
  let assert Ok(login_loc) = response.get_header(unauth_authz_resp, "location")
  assert string.starts_with(login_loc, "/auth/login?return_to=")

  // Follow redirect to GET /auth/login?return_to=..., mistype password once, then succeed -> lands back on authz_path!
  let login_get_req = simulate.browser_request(http.Get, login_loc)
  let login_get_resp = dispatch(login_get_req)
  assert login_get_resp.status == 200
  let login_csrf = extract_form_csrf_token(simulate.read_body(login_get_resp))

  let wrong_pw_req =
    simulate.browser_request(http.Post, "/auth/password/login")
    |> simulate.session(login_get_req, login_get_resp)
    |> simulate.form_body([
      #(csrf.form_field_name, login_csrf),
      #("login_id", "alice_oauth"),
      #("password", "wrongpass"),
      #("return_to", authz_path),
    ])
  let wrong_pw_resp = dispatch(wrong_pw_req)
  assert wrong_pw_resp.status == 200
  // return_to hidden input is preserved on credential error!
  assert string.contains(
    simulate.read_body(wrong_pw_resp),
    "name=\"return_to\"",
  )

  let ok_pw_req =
    simulate.browser_request(http.Post, "/auth/password/login")
    |> simulate.session(login_get_req, login_get_resp)
    |> simulate.form_body([
      #(csrf.form_field_name, login_csrf),
      #("login_id", "alice_oauth"),
      #("password", "secretpass123"),
      #("return_to", authz_path),
    ])
  let ok_pw_resp = dispatch(ok_pw_req)
  assert ok_pw_resp.status == 303
  assert response.get_header(ok_pw_resp, "location") == Ok(authz_path)

  // Alice visits authz_path -> sees 200 consent page
  let consent_get_req =
    simulate.browser_request(http.Get, authz_path)
    |> simulate.session(ok_pw_req, ok_pw_resp)
  let consent_get_resp = dispatch(consent_get_req)
  assert consent_get_resp.status == 200
  let consent_html = simulate.read_body(consent_get_resp)
  assert string.contains(consent_html, "Alice Reader Web")
  let consent_csrf = extract_form_csrf_token(consent_html)

  // Denying redirects with error=access_denied + iss + exact state "a+b=1"
  let deny_resp =
    simulate.browser_request(http.Post, "/oidc/authorize")
    |> simulate.session(consent_get_req, consent_get_resp)
    |> simulate.form_body([
      #(csrf.form_field_name, consent_csrf),
      #("client_id", conf_client.client_id),
      #("redirect_uri", web_redirect),
      #("response_type", "code"),
      #("scope", "posts:read offline_access"),
      #("code_challenge", challenge),
      #("code_challenge_method", "S256"),
      #("state", "a+b=1"),
      #("decision", "deny"),
    ])
    |> dispatch
  assert deny_resp.status == 303
  let #(_, deny_q) = parse_location_query(deny_resp)
  assert list.key_find(deny_q, "error") == Ok("access_denied")
  assert list.key_find(deny_q, "iss") == Ok(test_issuer)
  assert list.key_find(deny_q, "state") == Ok("a+b=1")

  // Approving issues code + iss + state "a+b=1"
  let approve_resp =
    simulate.browser_request(http.Post, "/oidc/authorize")
    |> simulate.session(consent_get_req, consent_get_resp)
    |> simulate.form_body([
      #(csrf.form_field_name, consent_csrf),
      #("client_id", conf_client.client_id),
      #("redirect_uri", web_redirect),
      #("response_type", "code"),
      #("scope", "posts:read offline_access"),
      #("code_challenge", challenge),
      #("code_challenge_method", "S256"),
      #("state", "a+b=1"),
      #("decision", "approve"),
    ])
    |> dispatch
  assert approve_resp.status == 303
  let #(_, approve_q) = parse_location_query(approve_resp)
  let assert Ok(code1) = list.key_find(approve_q, "code")
  assert list.key_find(approve_q, "iss") == Ok(test_issuer)
  assert list.key_find(approve_q, "state") == Ok("a+b=1")

  // Exchange code1 at POST /oidc/token -> gets access_token + refresh_token
  let tok1_resp =
    simulate.request(http.Post, "/oidc/token")
    |> request.set_header(
      "authorization",
      basic_auth_header(conf_client.client_id, conf_sec.secret),
    )
    |> simulate.form_body([
      #("grant_type", "authorization_code"),
      #("code", code1),
      #("redirect_uri", web_redirect),
      #("code_verifier", verifier),
    ])
    |> dispatch
  assert tok1_resp.status == 200
  let assert #(at1, Some(_rt1)) = parse_token_response(tok1_resp)

  // Consent Skip: requesting subset scope (posts:read) auto-redirects with a fresh code (303)!
  let skip_resp =
    simulate.browser_request(
      http.Get,
      "/oidc/authorize?client_id="
        <> conf_client.client_id
        <> "&redirect_uri="
        <> uri.percent_encode(web_redirect)
        <> "&response_type=code&scope=posts%3Aread&code_challenge="
        <> challenge
        <> "&code_challenge_method=S256&state=skip1",
    )
    |> simulate.session(consent_get_req, consent_get_resp)
    |> dispatch
  assert skip_resp.status == 303
  let #(_, skip_q) = parse_location_query(skip_resp)
  let assert Ok(code2) = list.key_find(skip_q, "code")
  assert code2 != code1
  assert list.key_find(skip_q, "state") == Ok("skip1")

  // prompt=consent forces 200 consent screen even when scopes are already covered!
  let forced_consent_resp =
    simulate.browser_request(
      http.Get,
      "/oidc/authorize?client_id="
        <> conf_client.client_id
        <> "&redirect_uri="
        <> uri.percent_encode(web_redirect)
        <> "&response_type=code&scope=posts%3Aread&code_challenge="
        <> challenge
        <> "&code_challenge_method=S256&prompt=consent",
    )
    |> simulate.session(consent_get_req, consent_get_resp)
    |> dispatch
  assert forced_consent_resp.status == 200

  // Step-up Consent: requesting posts:read + posts:write (where posts:write is new) shows 200 consent page!
  let stepup_resp =
    simulate.browser_request(
      http.Get,
      "/oidc/authorize?client_id="
        <> conf_client.client_id
        <> "&redirect_uri="
        <> uri.percent_encode(web_redirect)
        <> "&response_type=code&scope="
        <> uri.percent_encode("posts:read posts:write")
        <> "&code_challenge="
        <> challenge
        <> "&code_challenge_method=S256",
    )
    |> simulate.session(consent_get_req, consent_get_resp)
    |> dispatch
  assert stepup_resp.status == 200

  // Bob (non-owner):
  // - Rejected with access_denied on Alice's Private conf_client
  // - Succeeds on Alice's Public Native CLI pub_client with dynamic loopback port & existing query param!
  let bob_sess_init =
    simulate.browser_request(http.Post, "/auth/password/login")
  let assert Ok(bob_sess_resp) =
    session.create(wisp.ok(), bob_sess_init, tx, test_secret, bob)

  let bob_private_resp =
    simulate.browser_request(
      http.Get,
      "/oidc/authorize?client_id="
        <> conf_client.client_id
        <> "&redirect_uri="
        <> uri.percent_encode(web_redirect)
        <> "&response_type=code&scope=posts%3Aread&code_challenge="
        <> challenge
        <> "&code_challenge_method=S256&state=bob_priv",
    )
    |> simulate.session(bob_sess_init, bob_sess_resp)
    |> dispatch
  assert bob_private_resp.status == 303
  let #(_, bob_priv_q) = parse_location_query(bob_private_resp)
  assert list.key_find(bob_priv_q, "error") == Ok("access_denied")
  assert list.key_find(bob_priv_q, "state") == Ok("bob_priv")

  // Native loopback allows ephemeral port only when path + query match registered URI
  let tampered_native_resp =
    simulate.browser_request(
      http.Get,
      "/oidc/authorize?client_id="
        <> pub_client.client_id
        <> "&redirect_uri="
        <> uri.percent_encode("http://127.0.0.1:54321/cb?mode=tampered")
        <> "&response_type=code&scope=posts%3Awrite&code_challenge="
        <> challenge
        <> "&code_challenge_method=S256",
    )
    |> simulate.session(bob_sess_init, bob_sess_resp)
    |> dispatch
  assert tampered_native_resp.status == 400
  assert response.get_header(tampered_native_resp, "location") == Error(Nil)

  let native_cb = "http://127.0.0.1:54321/cb?mode=cli"
  let bob_pub_get_req =
    simulate.browser_request(
      http.Get,
      "/oidc/authorize?client_id="
        <> pub_client.client_id
        <> "&redirect_uri="
        <> uri.percent_encode(native_cb)
        <> "&response_type=code&scope=posts%3Awrite&code_challenge="
        <> challenge
        <> "&code_challenge_method=S256&state=cli_state",
    )
    |> simulate.session(bob_sess_init, bob_sess_resp)
  let bob_pub_get_resp = dispatch(bob_pub_get_req)
  assert bob_pub_get_resp.status == 200
  let bob_csrf = extract_form_csrf_token(simulate.read_body(bob_pub_get_resp))

  let bob_approve_resp =
    simulate.browser_request(http.Post, "/oidc/authorize")
    |> simulate.session(bob_pub_get_req, bob_pub_get_resp)
    |> simulate.form_body([
      #(csrf.form_field_name, bob_csrf),
      #("client_id", pub_client.client_id),
      #("redirect_uri", native_cb),
      #("response_type", "code"),
      #("scope", "posts:write"),
      #("code_challenge", challenge),
      #("code_challenge_method", "S256"),
      #("state", "cli_state"),
      #("decision", "approve"),
    ])
    |> dispatch
  assert bob_approve_resp.status == 303
  let #(_, bob_pub_q) = parse_location_query(bob_approve_resp)
  assert list.key_find(bob_pub_q, "mode") == Ok("cli")
  assert list.key_find(bob_pub_q, "iss") == Ok(test_issuer)
  assert list.key_find(bob_pub_q, "state") == Ok("cli_state")
  let assert Ok(bob_code) = list.key_find(bob_pub_q, "code")

  let bob_tok_resp =
    simulate.request(http.Post, "/oidc/token")
    |> simulate.form_body([
      #("grant_type", "authorization_code"),
      #("client_id", pub_client.client_id),
      #("code", bob_code),
      #("redirect_uri", native_cb),
      #("code_verifier", verifier),
    ])
    |> dispatch
  assert bob_tok_resp.status == 200
  let assert #(bob_at, None) = parse_token_response(bob_tok_resp)

  // Both Alice's token (at1) and Bob's public CLI token (bob_at) work with personal account attribution!
  assert dispatch(
      simulate.request(http.Get, "/api/v1/posts")
      |> request.set_header("authorization", "Bearer " <> at1),
    ).status
    == 200

  let bob_post_resp =
    simulate.request(http.Post, "/api/v1/posts")
    |> request.set_header("authorization", "Bearer " <> bob_at)
    |> simulate.json_body(
      json.object([#("body", json.string("Posted from Bob CLI"))]),
    )
    |> dispatch
  assert bob_post_resp.status == 201
  assert string.contains(simulate.read_body(bob_post_resp), "AuthFlowBob")
}

pub fn settings_grants_ui_lists_and_revokes_grants_and_consents_safely_test() {
  use tx <- test_helper.with_db
  let #(_auth_ctx, oidc_ctx, _post_pubsub, grant_revocations, dispatch) =
    setup_contexts(tx)
  let rev_sub = process.new_subject()
  pubsub.subscribe(grant_revocations, rev_sub)

  let assert Ok(alice) = user.create(tx, "GrantsUiAlice")
  let assert Ok(bob) = user.create(tx, "GrantsUiBob")

  let assert Ok(#(app, Some(_app_sec))) =
    client.create_app(
      tx,
      alice.id,
      "Connected Web App",
      True,
      client.Private,
      client.Web,
      ["https://connected.example/cb"],
      set.from_list([scope.PostsRead, scope.OfflineAccess]),
    )
  let assert Ok(bot) =
    client.create_subordinate_bot(
      tx,
      alice.id,
      "Background Bot",
      set.from_list([scope.PostsRead]),
      "default",
      None,
    )

  // Mint 2 grants for `app` (Device 1 & Device 2) and 1 grant for `bot`
  let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  let challenge = token.compute_pkce_s256_challenge(verifier)
  let assert Ok(#(app_consent_id, app_consent_pub, _)) =
    grant.upsert_consent(
      tx,
      alice.id,
      app.id,
      set.from_list([scope.PostsRead, scope.OfflineAccess]),
    )

  let mint_app_grant = fn(ua: String) {
    let assert Ok(#(code, grant_pub)) =
      token.issue_authorization_code(
        tx,
        app_consent_id,
        set.from_list([scope.PostsRead, scope.OfflineAccess]),
        test_issuer,
        "https://connected.example/cb",
        challenge,
        None,
        ua,
      )
    let assert Ok(issued) =
      token.exchange_authorization_code_with_secret(
        oidc_ctx,
        app,
        None,
        code,
        "https://connected.example/cb",
        verifier,
        None,
      )
    #(issued.access_token, grant_pub)
  }

  let #(at_dev1, grant_dev1) = mint_app_grant("DeviceOne/1.0")
  let #(at_dev2, grant_dev2) = mint_app_grant("DeviceTwo/2.0")
  let assert Ok(bot_issued) =
    token.issue_client_credentials(
      oidc_ctx,
      bot.client.client_id,
      bot.secret.secret,
      None,
      None,
      "BotRunner/1.0",
    )

  let login_init = simulate.browser_request(http.Post, "/auth/password/login")
  let assert Ok(alice_login) =
    session.create(wisp.ok(), login_init, tx, test_secret, alice)
  let assert Ok(bob_login) =
    session.create(wisp.ok(), login_init, tx, test_secret, bob)

  // Unauthenticated GET /settings/grants redirects to /auth/login
  assert dispatch(simulate.browser_request(http.Get, "/settings/grants")).status
    == 303

  // Alice views /settings/grants -> sees Connected Web App, DeviceOne/1.0, DeviceTwo/2.0, BotRunner/1.0
  let grants_req =
    simulate.browser_request(http.Get, "/settings/grants")
    |> simulate.session(login_init, alice_login)
  let grants_resp = dispatch(grants_req)
  assert grants_resp.status == 200
  let grants_html = simulate.read_body(grants_resp)
  assert string.contains(grants_html, "Connected Web App")
  assert string.contains(grants_html, "DeviceOne/1.0")
  assert string.contains(grants_html, "DeviceTwo/2.0")
  assert string.contains(grants_html, "BotRunner/1.0")
  // SubordinateBot's internal consent is NOT exposed as a disconnectable Connected App consent
  assert !string.contains(
    grants_html,
    "/settings/grants/consents/" <> bot.consent_public_id <> "/revoke",
  )
  let alice_csrf = extract_form_csrf_token(grants_html)

  // Attempting to POST revoke on SubordinateBot's internal consent returns 404 and keeps bot working!
  let bot_consent_revoke =
    simulate.browser_request(
      http.Post,
      "/settings/grants/consents/" <> bot.consent_public_id <> "/revoke",
    )
    |> simulate.session(grants_req, grants_resp)
    |> simulate.form_body([#(csrf.form_field_name, alice_csrf)])
    |> dispatch
  assert bot_consent_revoke.status == 404
  assert dispatch(
      simulate.request(http.Get, "/api/v1/posts")
      |> request.set_header(
        "authorization",
        "Bearer " <> bot_issued.access_token,
      ),
    ).status
    == 200

  // Bob cannot revoke Alice's grant or consent -> 404
  let bob_grants_req =
    simulate.browser_request(http.Get, "/settings/grants")
    |> simulate.session(login_init, bob_login)
  let bob_grants_resp = dispatch(bob_grants_req)
  let bob_csrf = extract_form_csrf_token(simulate.read_body(bob_grants_resp))
  assert dispatch(
      simulate.browser_request(
        http.Post,
        "/settings/grants/" <> grant_dev1 <> "/revoke",
      )
      |> simulate.session(bob_grants_req, bob_grants_resp)
      |> simulate.form_body([#(csrf.form_field_name, bob_csrf)]),
    ).status
    == 404

  // Alice revokes individual grant_dev1 -> PubSub receives grant_dev1, at_dev1 -> 401, at_dev2 still -> 200!
  let rev_dev1_resp =
    simulate.browser_request(
      http.Post,
      "/settings/grants/" <> grant_dev1 <> "/revoke",
    )
    |> simulate.session(grants_req, grants_resp)
    |> simulate.form_body([#(csrf.form_field_name, alice_csrf)])
    |> dispatch
  assert rev_dev1_resp.status == 303
  assert process.receive(rev_sub, 200) == Ok(grant_dev1)
  assert dispatch(
      simulate.request(http.Get, "/api/v1/posts")
      |> request.set_header("authorization", "Bearer " <> at_dev1),
    ).status
    == 401
  assert dispatch(
      simulate.request(http.Get, "/api/v1/posts")
      |> request.set_header("authorization", "Bearer " <> at_dev2),
    ).status
    == 200

  // Alice revokes entire app consent -> PubSub receives grant_dev2, at_dev2 -> 401, bot remains 200!
  let rev_consent_resp =
    simulate.browser_request(
      http.Post,
      "/settings/grants/consents/" <> app_consent_pub <> "/revoke",
    )
    |> simulate.session(grants_req, grants_resp)
    |> simulate.form_body([#(csrf.form_field_name, alice_csrf)])
    |> dispatch
  assert rev_consent_resp.status == 303
  assert process.receive(rev_sub, 200) == Ok(grant_dev2)
  assert dispatch(
      simulate.request(http.Get, "/api/v1/posts")
      |> request.set_header("authorization", "Bearer " <> at_dev2),
    ).status
    == 401
  assert dispatch(
      simulate.request(http.Get, "/api/v1/posts")
      |> request.set_header(
        "authorization",
        "Bearer " <> bot_issued.access_token,
      ),
    ).status
    == 200
}

pub fn authorize_audience_isolation_head_rejection_and_unexchanged_grant_hygiene_test() {
  use tx <- test_helper.with_db
  let #(_auth_ctx, _oidc_ctx, _post_pubsub, _grant_revocations, dispatch) =
    setup_contexts(tx)

  let assert Ok(alice) = user.create(tx, "AudIsolationAlice")
  let cb = "https://aud-test.example/cb,v2"
  let assert Ok(#(app, Some(app_sec))) =
    client.create_app(
      tx,
      alice.id,
      "Aud Isolation App",
      True,
      client.Private,
      client.Web,
      [cb],
      set.from_list([scope.PostsRead, scope.PostsWrite]),
    )

  let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  let challenge = token.compute_pkce_s256_challenge(verifier)
  let ext_resource = "https://external-mcp.example"

  // Unauthenticated GET with invalid scope + prompt=none returns error=invalid_scope (not login_required)
  let unauth_invalid_scope =
    dispatch(simulate.browser_request(
      http.Get,
      "/oidc/authorize?client_id="
        <> app.client_id
        <> "&redirect_uri="
        <> uri.percent_encode(cb)
        <> "&response_type=code&scope=posts%3Adelete&code_challenge="
        <> challenge
        <> "&code_challenge_method=S256&prompt=none&state=s1",
    ))
  assert unauth_invalid_scope.status == 303
  let #(_, unauth_err_q) = parse_location_query(unauth_invalid_scope)
  assert list.key_find(unauth_err_q, "error") == Ok("invalid_scope")

  let login_init = simulate.browser_request(http.Post, "/auth/password/login")
  let assert Ok(alice_login) =
    session.create(wisp.ok(), login_init, tx, test_secret, alice)

  // HEAD /oidc/authorize is rejected with 405 and NEVER mints a grant or code
  let head_resp =
    simulate.browser_request(
      http.Head,
      "/oidc/authorize?client_id="
        <> app.client_id
        <> "&redirect_uri="
        <> uri.percent_encode(cb)
        <> "&response_type=code&scope=posts%3Aread&code_challenge="
        <> challenge
        <> "&code_challenge_method=S256",
    )
    |> simulate.session(login_init, alice_login)
    |> dispatch
  assert head_resp.status == 405
  assert response.get_header(head_resp, "location") == Error(Nil)

  // Step 1: Alice approves posts:write ONLY for external resource `https://external-mcp.example`
  let ext_get_req =
    simulate.browser_request(
      http.Get,
      "/oidc/authorize?client_id="
        <> app.client_id
        <> "&redirect_uri="
        <> uri.percent_encode(cb)
        <> "&response_type=code&scope=posts%3Awrite&code_challenge="
        <> challenge
        <> "&code_challenge_method=S256&resource="
        <> uri.percent_encode(ext_resource),
    )
    |> simulate.session(login_init, alice_login)
  let ext_get_resp = dispatch(ext_get_req)
  assert ext_get_resp.status == 200
  let csrf_tok = extract_form_csrf_token(simulate.read_body(ext_get_resp))

  let ext_approve_resp =
    simulate.browser_request(http.Post, "/oidc/authorize")
    |> simulate.session(ext_get_req, ext_get_resp)
    |> simulate.form_body([
      #(csrf.form_field_name, csrf_tok),
      #("client_id", app.client_id),
      #("redirect_uri", cb),
      #("response_type", "code"),
      #("scope", "posts:write"),
      #("code_challenge", challenge),
      #("code_challenge_method", "S256"),
      #("resource", ext_resource),
      #("decision", "approve"),
    ])
    |> dispatch
  assert ext_approve_resp.status == 303
  let #(_, ext_q) = parse_location_query(ext_approve_resp)
  let assert Ok(ext_code) = list.key_find(ext_q, "code")

  // Before exchanging ext_code at /oidc/token, unexchanged auth code is NOT listed in list_active_grants_for_user!
  assert grant.list_active_grants_for_user(tx, alice.id) == Ok([])

  // Exchange ext_code -> now active grant exists for ext_resource
  let ext_tok_resp =
    simulate.request(http.Post, "/oidc/token")
    |> request.set_header(
      "authorization",
      basic_auth_header(app.client_id, app_sec.secret),
    )
    |> simulate.form_body([
      #("grant_type", "authorization_code"),
      #("code", ext_code),
      #("redirect_uri", cb),
      #("code_verifier", verifier),
      #("resource", ext_resource),
    ])
    |> dispatch
  assert ext_tok_resp.status == 200
  let assert Ok(active_after_exchange) =
    grant.list_active_grants_for_user(tx, alice.id)
  assert list.length(active_after_exchange) == 1

  // CRITICAL RFC 8707 CHECK: Requesting posts:write WITHOUT `resource` (default Lote issuer)
  // MUST NOT silent-skip consent — it MUST render 200 consent page!
  let default_aud_attempt =
    simulate.browser_request(
      http.Get,
      "/oidc/authorize?client_id="
        <> app.client_id
        <> "&redirect_uri="
        <> uri.percent_encode(cb)
        <> "&response_type=code&scope=posts%3Awrite&code_challenge="
        <> challenge
        <> "&code_challenge_method=S256",
    )
    |> simulate.session(ext_get_req, ext_get_resp)
    |> dispatch
  assert default_aud_attempt.status == 200

  // Meanwhile, re-requesting the SAME external resource `https://external-mcp.example` DOES silent-skip (303)!
  let same_ext_skip =
    simulate.browser_request(
      http.Get,
      "/oidc/authorize?client_id="
        <> app.client_id
        <> "&redirect_uri="
        <> uri.percent_encode(cb)
        <> "&response_type=code&scope=posts%3Awrite&code_challenge="
        <> challenge
        <> "&code_challenge_method=S256&resource="
        <> uri.percent_encode(ext_resource),
    )
    |> simulate.session(ext_get_req, ext_get_resp)
    |> dispatch
  assert same_ext_skip.status == 303
}
