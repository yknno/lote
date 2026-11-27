import gleam/bit_array
import gleam/dynamic/decode
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
import lote/auth/session
import lote/auth/user
import lote/oidc
import lote/oidc/client
import lote/oidc/jwt
import lote/oidc/scope
import lote/oidc/token
import lote/rate_limit
import lote/realtime/pubsub
import lote/test_helper
import lote/web/components/timeline
import lote/web/csrf
import lote/web/router
import pog
import wisp
import wisp/simulate

const test_secret = "oidc_phase3_secret_key_base_0123456789abcdefghijklmnopqr"

const test_issuer = "https://lote.example"

fn setup_contexts_with_keyring(
  tx: pog.Connection,
  keyring: jwt.Keyring,
) -> #(
  auth.Auth,
  oidc.Oidc,
  pubsub.PubSub(timeline.PostEvent),
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
  let oidc_ctx =
    oidc.new_with_keyring(tx, test_issuer, keyring, grant_revocations, limiter)
  let dispatch = fn(req: wisp.Request) {
    router.handle_request_with_oidc(
      req,
      auth_ctx,
      oidc_ctx,
      post_pubsub,
      "198.51.100.77",
    )
  }
  #(auth_ctx, oidc_ctx, post_pubsub, dispatch)
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

fn parse_token_bundle(
  resp: wisp.Response,
) -> #(String, Option(String), Option(String)) {
  let decoder = {
    use at <- decode.field("access_token", decode.string)
    use rt <- decode.optional_field(
      "refresh_token",
      None,
      decode.optional(decode.string),
    )
    use idt <- decode.optional_field(
      "id_token",
      None,
      decode.optional(decode.string),
    )
    decode.success(#(at, rt, idt))
  }
  let assert Ok(parsed) = json.parse(simulate.read_body(resp), decoder)
  parsed
}

fn parse_userinfo(resp: wisp.Response) -> #(String, Option(String)) {
  let decoder = {
    use sub <- decode.field("sub", decode.string)
    use name <- decode.optional_field(
      "name",
      None,
      decode.optional(decode.string),
    )
    decode.success(#(sub, name))
  }
  let assert Ok(parsed) = json.parse(simulate.read_body(resp), decoder)
  parsed
}

fn parse_location_query(resp: wisp.Response) -> List(#(String, String)) {
  let assert Ok(loc) = response.get_header(resp, "location")
  let assert Ok(parsed) = uri.parse(loc)
  let assert Ok(query_pairs) =
    parsed.query |> option.unwrap("") |> uri.parse_query
  query_pairs
}

pub fn discovery_and_jwks_endpoints_expose_accurate_metadata_and_rotated_keys_test() {
  use tx <- test_helper.with_db
  let active_key = jwt.generate_signing_key()
  let retiring_key = jwt.generate_signing_key()
  let keyring =
    jwt.new_keyring(active_key, [jwt.signing_key_to_verify_key(retiring_key)])

  let #(_auth_ctx, _oidc_ctx, _post_pubsub, dispatch) =
    setup_contexts_with_keyring(tx, keyring)

  // GET /.well-known/openid-configuration
  let disc_resp =
    simulate.request(http.Get, "/.well-known/openid-configuration")
    |> dispatch
  assert disc_resp.status == 200
  assert response.get_header(disc_resp, "cache-control")
    == Ok("public, max-age=300")

  let disc_decoder = {
    use iss <- decode.field("issuer", decode.string)
    use authz <- decode.field("authorization_endpoint", decode.string)
    use tok <- decode.field("token_endpoint", decode.string)
    use uinfo <- decode.field("userinfo_endpoint", decode.string)
    use jwks_uri <- decode.field("jwks_uri", decode.string)
    use algs <- decode.field(
      "id_token_signing_alg_values_supported",
      decode.list(decode.string),
    )
    use iss_param <- decode.field(
      "authorization_response_iss_parameter_supported",
      decode.bool,
    )
    decode.success(#(iss, authz, tok, uinfo, jwks_uri, algs, iss_param))
  }
  let assert Ok(#(iss, authz, tok, uinfo, jwks_uri, algs, iss_param)) =
    json.parse(simulate.read_body(disc_resp), disc_decoder)
  assert iss == test_issuer
  assert authz == test_issuer <> "/oidc/authorize"
  assert tok == test_issuer <> "/oidc/token"
  assert uinfo == test_issuer <> "/oidc/userinfo"
  assert jwks_uri == test_issuer <> "/.well-known/jwks.json"
  assert algs == ["ES256"]
  assert iss_param == True

  // HEAD works (200 with matching headers; Mist suppresses wire body); POST returns 405
  let head_disc =
    simulate.request(http.Head, "/.well-known/openid-configuration")
    |> dispatch
  assert head_disc.status == 200
  assert response.get_header(head_disc, "cache-control")
    == Ok("public, max-age=300")

  assert dispatch(simulate.request(
      http.Post,
      "/.well-known/openid-configuration",
    )).status
    == 405

  // GET /.well-known/jwks.json exposes both active_key and retiring_key
  let jwks_resp =
    simulate.request(http.Get, "/.well-known/jwks.json")
    |> dispatch
  assert jwks_resp.status == 200
  assert response.get_header(jwks_resp, "cache-control")
    == Ok("public, max-age=300")

  let jwks_decoder = {
    use kids <- decode.field(
      "keys",
      decode.list({
        use kid <- decode.field("kid", decode.string)
        use kty <- decode.field("kty", decode.string)
        use crv <- decode.field("crv", decode.string)
        use alg <- decode.field("alg", decode.string)
        decode.success(#(kid, kty, crv, alg))
      }),
    )
    decode.success(kids)
  }
  let assert Ok(keys) = json.parse(simulate.read_body(jwks_resp), jwks_decoder)
  assert list.length(keys) == 2
  let assert [
    #(first_kid, "EC", "P-256", "ES256"),
    #(_, "EC", "P-256", "ES256"),
  ] = keys
  assert first_kid == jwt.active_kid(keyring)
}

pub fn sign_in_with_lote_id_token_userinfo_refresh_and_downscope_flow_test() {
  use tx <- test_helper.with_db
  let keyring = jwt.new_keyring(jwt.generate_signing_key(), [])
  let #(_auth_ctx, oidc_ctx, _post_pubsub, dispatch) =
    setup_contexts_with_keyring(tx, keyring)

  let assert Ok(alice) = user.create(tx, "OidcAlice")
  let cb = "https://rp.example/auth/callback"
  let assert Ok(#(rp_app, Some(rp_sec))) =
    client.create_app(
      tx,
      alice.id,
      "OIDC Relying Party",
      True,
      client.Public,
      client.Web,
      [cb],
      set.from_list([
        scope.OpenId,
        scope.Profile,
        scope.OfflineAccess,
        scope.PostsRead,
      ]),
    )
  let assert Ok(bot) =
    client.create_subordinate_bot(
      tx,
      alice.id,
      "Non-OIDC Bot",
      set.from_list([scope.PostsRead]),
      "default",
      None,
    )

  // SubordinateBot client_credentials NEVER issues an id_token and fails /oidc/userinfo with 403 insufficient_scope
  let bot_tok_resp =
    simulate.request(http.Post, "/oidc/token")
    |> request.set_header(
      "authorization",
      basic_auth_header(bot.client.client_id, bot.secret.secret),
    )
    |> simulate.form_body([#("grant_type", "client_credentials")])
    |> dispatch
  assert bot_tok_resp.status == 200
  let assert #(bot_at, None, None) = parse_token_bundle(bot_tok_resp)

  let bot_uinfo_resp =
    simulate.request(http.Get, "/oidc/userinfo")
    |> request.set_header("authorization", "Bearer " <> bot_at)
    |> dispatch
  assert bot_uinfo_resp.status == 403
  let assert Ok(www_auth) =
    response.get_header(bot_uinfo_resp, "www-authenticate")
  assert string.contains(www_auth, "insufficient_scope")
  assert string.contains(www_auth, "openid")

  // Alice logs in and authorizes OIDC RP with `openid profile offline_access posts:read` + `nonce`
  let login_init = simulate.browser_request(http.Post, "/auth/password/login")
  let assert Ok(alice_login) =
    session.create(wisp.ok(), login_init, tx, test_secret, alice)

  let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  let challenge = token.compute_pkce_s256_challenge(verifier)
  let nonce = "rp-nonce-xyz-98765"

  let authz_get_req =
    simulate.browser_request(
      http.Get,
      "/oidc/authorize?client_id="
        <> rp_app.client_id
        <> "&redirect_uri="
        <> uri.percent_encode(cb)
        <> "&response_type=code&scope="
        <> uri.percent_encode("openid profile offline_access posts:read")
        <> "&code_challenge="
        <> challenge
        <> "&code_challenge_method=S256&nonce="
        <> nonce
        <> "&state=rp_state_1",
    )
    |> simulate.session(login_init, alice_login)
  let authz_get_resp = dispatch(authz_get_req)
  assert authz_get_resp.status == 200
  let consent_csrf = extract_form_csrf_token(simulate.read_body(authz_get_resp))

  let approve_resp =
    simulate.browser_request(http.Post, "/oidc/authorize")
    |> simulate.session(authz_get_req, authz_get_resp)
    |> simulate.form_body([
      #(csrf.form_field_name, consent_csrf),
      #("client_id", rp_app.client_id),
      #("redirect_uri", cb),
      #("response_type", "code"),
      #("scope", "openid profile offline_access posts:read"),
      #("code_challenge", challenge),
      #("code_challenge_method", "S256"),
      #("nonce", nonce),
      #("state", "rp_state_1"),
      #("decision", "approve"),
    ])
    |> dispatch
  assert approve_resp.status == 303
  let approve_q = parse_location_query(approve_resp)
  let assert Ok(auth_code) = list.key_find(approve_q, "code")

  // Exchange auth_code -> receives access_token, refresh_token, AND signed ES256 id_token!
  let tok_resp =
    simulate.request(http.Post, "/oidc/token")
    |> request.set_header(
      "authorization",
      basic_auth_header(rp_app.client_id, rp_sec.secret),
    )
    |> simulate.form_body([
      #("grant_type", "authorization_code"),
      #("code", auth_code),
      #("redirect_uri", cb),
      #("code_verifier", verifier),
    ])
    |> dispatch
  assert tok_resp.status == 200
  let assert #(at1, Some(rt1), Some(idt1)) = parse_token_bundle(tok_resp)

  let now = jwt.now_unix_seconds()
  let assert Ok(verified1) =
    jwt.verify_id_token(
      oidc_ctx.keyring,
      idt1,
      test_issuer,
      rp_app.client_id,
      now,
    )
  assert verified1.iss == test_issuer
  assert verified1.aud == rp_app.client_id
  assert string.length(verified1.sub) == 36
  assert verified1.nonce == Some(nonce)
  assert verified1.name == Some("OidcAlice")
  assert verified1.at_hash == Some(jwt.compute_at_hash(at1))

  // GET and cross-origin POST /oidc/userinfo both succeed and match id_token `sub` + `name`!
  let uinfo_get =
    simulate.request(http.Get, "/oidc/userinfo")
    |> request.set_header("authorization", "Bearer " <> at1)
    |> dispatch
  assert uinfo_get.status == 200
  assert response.get_header(uinfo_get, "cache-control") == Ok("no-store")
  assert parse_userinfo(uinfo_get) == #(verified1.sub, Some("OidcAlice"))

  let uinfo_post =
    simulate.browser_request(http.Post, "/oidc/userinfo")
    |> request.set_header("origin", "https://spa-rp.example")
    |> request.set_header("authorization", "Bearer " <> at1)
    |> dispatch
  assert uinfo_post.status == 200
  assert parse_userinfo(uinfo_post) == #(verified1.sub, Some("OidcAlice"))

  // Query-string access_token on /oidc/userinfo is rejected with 400 invalid_request
  let query_tok_uinfo =
    simulate.request(http.Get, "/oidc/userinfo?access_token=" <> at1)
    |> request.set_header("authorization", "Bearer " <> at1)
    |> dispatch
  assert query_tok_uinfo.status == 400

  // Refresh token grant with `openid` (without `profile`) mints fresh id_token OMITTING `nonce` (OIDC Core §12.2) and omitting `name`!
  let refresh1_resp =
    simulate.request(http.Post, "/oidc/token")
    |> request.set_header(
      "authorization",
      basic_auth_header(rp_app.client_id, rp_sec.secret),
    )
    |> simulate.form_body([
      #("grant_type", "refresh_token"),
      #("refresh_token", rt1),
      #("scope", "openid offline_access posts:read"),
    ])
    |> dispatch
  assert refresh1_resp.status == 200
  let assert #(at2, Some(rt2), Some(idt2)) = parse_token_bundle(refresh1_resp)

  let assert Ok(verified2) =
    jwt.verify_id_token(
      oidc_ctx.keyring,
      idt2,
      test_issuer,
      rp_app.client_id,
      now,
    )
  assert verified2.sub == verified1.sub
  assert verified2.nonce == None
  assert verified2.name == None
  assert verified2.at_hash == Some(jwt.compute_at_hash(at2))

  // /oidc/userinfo with `at2` (has `openid`, no `profile`) returns `sub` ONLY (no `name`)!
  let uinfo_no_profile =
    simulate.request(http.Get, "/oidc/userinfo")
    |> request.set_header("authorization", "Bearer " <> at2)
    |> dispatch
  assert uinfo_no_profile.status == 200
  assert parse_userinfo(uinfo_no_profile) == #(verified1.sub, None)

  // Refresh downscoped to `posts:read` (omitting `openid`) omits `id_token` completely!
  let refresh2_resp =
    simulate.request(http.Post, "/oidc/token")
    |> request.set_header(
      "authorization",
      basic_auth_header(rp_app.client_id, rp_sec.secret),
    )
    |> simulate.form_body([
      #("grant_type", "refresh_token"),
      #("refresh_token", rt2),
      #("scope", "posts:read"),
    ])
    |> dispatch
  assert refresh2_resp.status == 200
  let assert #(at3, Some(_rt3), None) = parse_token_bundle(refresh2_resp)
  assert dispatch(
      simulate.request(http.Get, "/oidc/userinfo")
      |> request.set_header("authorization", "Bearer " <> at3),
    ).status
    == 403
}

pub fn custom_resource_id_token_keeps_client_aud_while_blocking_userinfo_replay_test() {
  use tx <- test_helper.with_db
  let keyring = jwt.new_keyring(jwt.generate_signing_key(), [])
  let #(_auth_ctx, oidc_ctx, _post_pubsub, dispatch) =
    setup_contexts_with_keyring(tx, keyring)

  let assert Ok(alice) = user.create(tx, "AudSplitAlice")
  let cb = "https://rp-mcp.example/cb"
  let ext_resource = "https://mcp-tool.example"
  let assert Ok(#(app, Some(sec))) =
    client.create_app(
      tx,
      alice.id,
      "MCP OIDC Client",
      True,
      client.Private,
      client.Web,
      [cb],
      set.from_list([scope.OpenId, scope.Profile, scope.PostsRead]),
    )

  let login_init = simulate.browser_request(http.Post, "/auth/password/login")
  let assert Ok(alice_login) =
    session.create(wisp.ok(), login_init, tx, test_secret, alice)

  let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  let challenge = token.compute_pkce_s256_challenge(verifier)

  let get_req =
    simulate.browser_request(
      http.Get,
      "/oidc/authorize?client_id="
        <> app.client_id
        <> "&redirect_uri="
        <> uri.percent_encode(cb)
        <> "&response_type=code&scope="
        <> uri.percent_encode("openid profile posts:read")
        <> "&code_challenge="
        <> challenge
        <> "&code_challenge_method=S256&resource="
        <> uri.percent_encode(ext_resource),
    )
    |> simulate.session(login_init, alice_login)
  let get_resp = dispatch(get_req)
  assert get_resp.status == 200
  let csrf_tok = extract_form_csrf_token(simulate.read_body(get_resp))

  let post_resp =
    simulate.browser_request(http.Post, "/oidc/authorize")
    |> simulate.session(get_req, get_resp)
    |> simulate.form_body([
      #(csrf.form_field_name, csrf_tok),
      #("client_id", app.client_id),
      #("redirect_uri", cb),
      #("response_type", "code"),
      #("scope", "openid profile posts:read"),
      #("code_challenge", challenge),
      #("code_challenge_method", "S256"),
      #("resource", ext_resource),
      #("decision", "approve"),
    ])
    |> dispatch
  assert post_resp.status == 303
  let assert Ok(code) = list.key_find(parse_location_query(post_resp), "code")

  let tok_resp =
    simulate.request(http.Post, "/oidc/token")
    |> request.set_header(
      "authorization",
      basic_auth_header(app.client_id, sec.secret),
    )
    |> simulate.form_body([
      #("grant_type", "authorization_code"),
      #("code", code),
      #("redirect_uri", cb),
      #("code_verifier", verifier),
      #("resource", ext_resource),
    ])
    |> dispatch
  assert tok_resp.status == 200
  let assert #(ext_at, None, Some(idt)) = parse_token_bundle(tok_resp)

  // id_token `aud` is STILL `app.client_id` (OIDC Core §2), NOT `ext_resource`!
  let assert Ok(verified) =
    jwt.verify_id_token(
      oidc_ctx.keyring,
      idt,
      test_issuer,
      app.client_id,
      jwt.now_unix_seconds(),
    )
  assert verified.aud == app.client_id

  // Meanwhile, replaying `ext_at` (bound to `ext_resource`) against Lote's `/oidc/userinfo` fails with 401!
  let replay_uinfo =
    simulate.request(http.Get, "/oidc/userinfo")
    |> request.set_header("authorization", "Bearer " <> ext_at)
    |> dispatch
  assert replay_uinfo.status == 401
}

pub fn oidc_audit_regressions_discovery_subpath_authorize_params_and_userinfo_fail_closed_test() {
  use tx <- test_helper.with_db
  let keyring = jwt.new_keyring(jwt.generate_signing_key(), [])
  let sub_issuer = "https://lote.example/idp"
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
  let oidc_ctx =
    oidc.new_with_keyring(tx, sub_issuer, keyring, grant_revocations, limiter)
  let dispatch = fn(req: wisp.Request) {
    router.handle_request_with_oidc(
      req,
      auth_ctx,
      oidc_ctx,
      post_pubsub,
      "198.51.100.88",
    )
  }

  // 1. Subpath issuer Discovery works via `/idp/.well-known/openid-configuration` (OIDC Discovery §4.1),
  //    `/.well-known/openid-configuration/idp` (RFC 8414 §3.1), and stripped `/.well-known/openid-configuration`,
  //    exposes CORS `*`, and sets `request_uri_parameter_supported: false`!
  let sub_disc =
    dispatch(simulate.request(http.Get, "/idp/.well-known/openid-configuration"))
  assert sub_disc.status == 200
  assert response.get_header(sub_disc, "access-control-allow-origin") == Ok("*")
  let flags_decoder = {
    use req_sup <- decode.field("request_parameter_supported", decode.bool)
    use req_uri_sup <- decode.field(
      "request_uri_parameter_supported",
      decode.bool,
    )
    use claims_sup <- decode.field("claims_parameter_supported", decode.bool)
    decode.success(#(req_sup, req_uri_sup, claims_sup))
  }
  assert json.parse(simulate.read_body(sub_disc), flags_decoder)
    == Ok(#(False, False, False))

  assert dispatch(simulate.request(
      http.Get,
      "/.well-known/openid-configuration/idp",
    )).status
    == 200
  assert dispatch(simulate.request(
      http.Get,
      "/.well-known/openid-configuration/other",
    )).status
    == 404
  assert dispatch(simulate.request(http.Get, "/idp/.well-known/jwks.json")).status
    == 200

  // 2. Authorize endpoint rejects unsupported response_mode, request, request_uri, registration, max_age, and prompt values
  let assert Ok(alice) = user.create(tx, "AuditAlice")
  let cb = "https://rp.example/cb"
  let assert Ok(#(app, Some(sec))) =
    client.create_app(
      tx,
      alice.id,
      "Audit RP",
      True,
      client.Private,
      client.Web,
      [cb],
      set.from_list([scope.OpenId, scope.Profile]),
    )
  let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  let challenge = token.compute_pkce_s256_challenge(verifier)
  let base_q =
    "/idp/oidc/authorize?client_id="
    <> app.client_id
    <> "&redirect_uri="
    <> uri.percent_encode(cb)
    <> "&response_type=code&scope=openid&code_challenge="
    <> challenge
    <> "&code_challenge_method=S256"

  let assert_authz_err = fn(extra: String, expected_error: String) {
    let resp = dispatch(simulate.browser_request(http.Get, base_q <> extra))
    assert resp.status == 303
    let q = parse_location_query(resp)
    assert list.key_find(q, "error") == Ok(expected_error)
    assert list.key_find(q, "iss") == Ok(sub_issuer)
  }

  assert_authz_err("&response_mode=fragment", "invalid_request")
  assert_authz_err("&response_mode=form_post", "invalid_request")
  assert_authz_err("&request=eyJhbGciOiJub25lIn0..", "request_not_supported")
  assert_authz_err(
    "&request_uri=" <> uri.percent_encode("https://rp.example/req.jwt"),
    "request_uri_not_supported",
  )
  assert_authz_err("&registration=%7B%7D", "registration_not_supported")
  assert_authz_err("&max_age=0", "invalid_request")
  assert_authz_err("&claims=%7B%7D", "invalid_request")
  assert_authz_err("&prompt=login", "login_required")
  assert_authz_err("&prompt=select_account", "account_selection_required")
  assert_authz_err("&prompt=none%20consent", "invalid_request")
  assert_authz_err("&prompt=", "invalid_request")

  // `response_mode=query` is explicitly accepted (redirects unauthenticated user to /auth/login)
  let query_mode_ok =
    dispatch(simulate.browser_request(
      http.Get,
      base_q <> "&response_mode=query",
    ))
  assert query_mode_ok.status == 303
  let assert Ok(login_loc) = response.get_header(query_mode_ok, "location")
  assert string.starts_with(login_loc, "/auth/login?")

  // 3. `POST /idp/oidc/userinfo` fails CLOSED (400 invalid_request) on malformed `%ZZ` or oversized >16KB form body!
  let login_init = simulate.browser_request(http.Post, "/auth/password/login")
  let assert Ok(alice_login) =
    session.create(wisp.ok(), login_init, tx, test_secret, alice)
  let get_req =
    simulate.browser_request(http.Get, base_q)
    |> simulate.session(login_init, alice_login)
  let get_resp = dispatch(get_req)
  assert get_resp.status == 200
  let csrf_tok = extract_form_csrf_token(simulate.read_body(get_resp))

  let post_resp =
    simulate.browser_request(http.Post, "/idp/oidc/authorize")
    |> simulate.session(get_req, get_resp)
    |> simulate.form_body([
      #(csrf.form_field_name, csrf_tok),
      #("client_id", app.client_id),
      #("redirect_uri", cb),
      #("response_type", "code"),
      #("scope", "openid"),
      #("code_challenge", challenge),
      #("code_challenge_method", "S256"),
      #("decision", "approve"),
    ])
    |> dispatch
  assert post_resp.status == 303
  let assert Ok(code) = list.key_find(parse_location_query(post_resp), "code")

  let tok_resp =
    simulate.request(http.Post, "/idp/oidc/token")
    |> request.set_header(
      "authorization",
      basic_auth_header(app.client_id, sec.secret),
    )
    |> simulate.form_body([
      #("grant_type", "authorization_code"),
      #("code", code),
      #("redirect_uri", cb),
      #("code_verifier", verifier),
    ])
    |> dispatch
  assert tok_resp.status == 200
  let #(at, _, _) = parse_token_bundle(tok_resp)

  // Valid cross-origin POST /idp/oidc/userinfo succeeds (200)
  let valid_post_uinfo =
    simulate.request(http.Post, "/idp/oidc/userinfo")
    |> request.set_header("origin", "https://spa-rp.example")
    |> request.set_header("authorization", "Bearer " <> at)
    |> dispatch
  assert valid_post_uinfo.status == 200

  // Malformed percent-encoding in form body alongside access_token MUST fail closed with 400!
  let malformed_form_uinfo =
    simulate.request(http.Post, "/idp/oidc/userinfo")
    |> request.set_header("authorization", "Bearer " <> at)
    |> simulate.string_body("bad=%ZZ&access_token=" <> at)
    |> request.set_header("content-type", "application/x-www-form-urlencoded")
    |> dispatch
  assert malformed_form_uinfo.status == 400

  // Oversized >16KB form body MUST fail closed with 400!
  let oversized_padding = string.repeat("a", 17_000)
  let oversized_form_uinfo =
    simulate.request(http.Post, "/idp/oidc/userinfo")
    |> request.set_header("authorization", "Bearer " <> at)
    |> simulate.string_body(
      "pad=" <> oversized_padding <> "&access_token=" <> at,
    )
    |> request.set_header("content-type", "application/x-www-form-urlencoded")
    |> dispatch
  assert oversized_form_uinfo.status == 400
}
