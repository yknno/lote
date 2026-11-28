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
import gleam/string
import gleam/uri
import lote/auth.{Auth, Password}
import lote/auth/password
import lote/auth/session
import lote/auth/user
import lote/oidc
import lote/oidc/cimd
import lote/oidc/jwt
import lote/oidc/token
import lote/rate_limit
import lote/realtime/pubsub
import lote/test_helper
import lote/web/csrf
import lote/web/router
import pog
import wisp
import wisp/simulate

const test_secret = "cimd_http_test_secret_key_base_0123456789abcdefghijklmnop"

const test_issuer = "https://lote.example"

const valid_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

fn setup_dispatch(
  tx: pog.Connection,
  keyring: jwt.Keyring,
  limiter: rate_limit.Limiter,
  fetcher: cimd.Fetcher,
  client_ip: String,
) -> fn(wisp.Request) -> wisp.Response {
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
  let oidc_ctx =
    oidc.new_with_keyring(tx, test_issuer, keyring, grant_revocations, limiter)
    |> oidc.with_cimd_fetcher(fetcher)

  fn(req: wisp.Request) {
    router.handle_request_with_oidc(
      req,
      auth_ctx,
      oidc_ctx,
      post_pubsub,
      client_ip,
    )
  }
}

fn valid_metadata_json(
  client_id: String,
  client_name: String,
  redirect_uris: List(String),
) -> String {
  json.object([
    #("client_id", json.string(client_id)),
    #("client_name", json.string(client_name)),
    #("redirect_uris", json.array(redirect_uris, json.string)),
    #(
      "grant_types",
      json.array(["authorization_code", "refresh_token"], json.string),
    ),
    #("response_types", json.array(["code"], json.string)),
    #("token_endpoint_auth_method", json.string("none")),
    #(
      "scope",
      json.string("openid profile offline_access posts:read posts:write"),
    ),
  ])
  |> json.to_string
}

fn json_fetch_response(body_json: String) -> cimd.FetchResponse {
  cimd.FetchResponse(
    status: 200,
    content_type: "application/json; charset=utf-8",
    cache_control: Some("public, max-age=300"),
    body: <<body_json:utf8>>,
  )
}

fn drain_subject(subject: process.Subject(a)) -> List(a) {
  drain_subject_loop(subject, [])
}

fn drain_subject_loop(subject: process.Subject(a), acc: List(a)) -> List(a) {
  case process.receive(subject, 0) {
    Ok(item) -> drain_subject_loop(subject, [item, ..acc])
    Error(Nil) -> list.reverse(acc)
  }
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

pub fn cimd_full_e2e_mcp_oidc_flow_test() {
  use tx <- test_helper.with_db

  let cimd_client_id = "https://mcp-client.example/oauth/metadata.json"
  let same_origin_cb = "https://mcp-client.example/oauth/callback"
  let cross_origin_cb = "https://cb.other-domain.example/oauth/callback"
  let doc_json =
    valid_metadata_json(cimd_client_id, "Example MCP Inspector", [
      same_origin_cb,
      cross_origin_cb,
    ])

  let fetch_log = process.new_subject()
  let fetcher = fn(url: String) {
    process.send(fetch_log, url)
    case url == cimd_client_id {
      True -> Ok(json_fetch_response(doc_json))
      False -> Error(cimd.InvalidHttpResponse("unexpected url: " <> url))
    }
  }

  let keyring = jwt.new_keyring(jwt.generate_signing_key(), [])
  let dispatch =
    setup_dispatch(tx, keyring, rate_limit.disabled(), fetcher, "198.51.100.10")

  // 1. Discovery advertises client_id_metadata_document_supported: true on both endpoints
  let cimd_sup_decoder =
    decode.field(
      "client_id_metadata_document_supported",
      decode.bool,
      decode.success,
    )

  let asm_resp =
    dispatch(simulate.request(
      http.Get,
      "/.well-known/oauth-authorization-server",
    ))
  assert asm_resp.status == 200
  assert json.parse(simulate.read_body(asm_resp), cimd_sup_decoder) == Ok(True)

  let oidc_disc_resp =
    dispatch(simulate.request(http.Get, "/.well-known/openid-configuration"))
  assert oidc_disc_resp.status == 200
  assert json.parse(simulate.read_body(oidc_disc_resp), cimd_sup_decoder)
    == Ok(True)

  // 2. Unauthenticated user visits GET /oidc/authorize -> fetcher called ONCE -> redirects to /auth/login?return_to=...
  let assert Ok(alice) = user.create(tx, "CimdAlice")
  let assert Ok(Nil) =
    password.create(tx, alice.id, "cimd_alice", "secretpass123")

  let challenge = token.compute_pkce_s256_challenge(valid_verifier)
  let requested_scope = "openid profile offline_access posts:read posts:write"
  let authz_path =
    "/oidc/authorize?client_id="
    <> uri.percent_encode(cimd_client_id)
    <> "&redirect_uri="
    <> uri.percent_encode(same_origin_cb)
    <> "&response_type=code&scope="
    <> uri.percent_encode(requested_scope)
    <> "&code_challenge="
    <> challenge
    <> "&code_challenge_method=S256&state=xyz&nonce=n1"

  let unauth_resp = dispatch(simulate.browser_request(http.Get, authz_path))
  assert unauth_resp.status == 303
  let assert Ok(login_loc) = response.get_header(unauth_resp, "location")
  assert string.starts_with(login_loc, "/auth/login?return_to=")
  assert drain_subject(fetch_log) == [cimd_client_id]

  // 3. User logs in and visits GET /oidc/authorize -> hits PostgreSQL cache (fetcher NOT called again!)
  let login_get_req = simulate.browser_request(http.Get, login_loc)
  let login_get_resp = dispatch(login_get_req)
  assert login_get_resp.status == 200
  let login_csrf = extract_form_csrf_token(simulate.read_body(login_get_resp))

  let login_post_req =
    simulate.browser_request(http.Post, "/auth/password/login")
    |> simulate.session(login_get_req, login_get_resp)
    |> simulate.form_body([
      #(csrf.form_field_name, login_csrf),
      #("login_id", "cimd_alice"),
      #("password", "secretpass123"),
      #("return_to", authz_path),
    ])
  let login_post_resp = dispatch(login_post_req)
  assert login_post_resp.status == 303
  assert response.get_header(login_post_resp, "location") == Ok(authz_path)

  let consent_get_req =
    simulate.browser_request(http.Get, authz_path)
    |> simulate.session(login_post_req, login_post_resp)
  let consent_get_resp = dispatch(consent_get_req)
  assert consent_get_resp.status == 200
  // Cache hit: zero additional outbound metadata fetches!
  assert drain_subject(fetch_log) == []

  let consent_html = simulate.read_body(consent_get_resp)
  assert string.contains(consent_html, "Example MCP Inspector")
  assert string.contains(consent_html, "Client ID Metadata Document")
  assert string.contains(consent_html, "Unregistered external client")
  assert string.contains(consent_html, "Client domain")
  assert string.contains(consent_html, "mcp-client.example")
  assert string.contains(consent_html, "Metadata URL")
  assert string.contains(consent_html, cimd_client_id)
  assert !string.contains(consent_html, "rounded-")

  // Cross-domain callback warning appears when redirect_uri host != cimd_host
  let cross_origin_path =
    "/oidc/authorize?client_id="
    <> uri.percent_encode(cimd_client_id)
    <> "&redirect_uri="
    <> uri.percent_encode(cross_origin_cb)
    <> "&response_type=code&scope=openid&code_challenge="
    <> challenge
    <> "&code_challenge_method=S256"
  let cross_consent_resp =
    simulate.browser_request(http.Get, cross_origin_path)
    |> simulate.session(consent_get_req, consent_get_resp)
    |> dispatch
  assert cross_consent_resp.status == 200
  let cross_consent_html = simulate.read_body(cross_consent_resp)
  assert string.contains(
    cross_consent_html,
    "Callback origin (https://cb.other-domain.example) differs from client domain (mcp-client.example).",
  )
  assert !string.contains(cross_consent_html, "rounded-")
  assert drain_subject(fetch_log) == []

  // 4. User approves consent -> 303 redirect with code, iss, state=xyz
  let consent_csrf = extract_form_csrf_token(consent_html)
  let approve_resp =
    simulate.browser_request(http.Post, "/oidc/authorize")
    |> simulate.session(consent_get_req, consent_get_resp)
    |> simulate.form_body([
      #(csrf.form_field_name, consent_csrf),
      #("client_id", cimd_client_id),
      #("redirect_uri", same_origin_cb),
      #("response_type", "code"),
      #("scope", requested_scope),
      #("code_challenge", challenge),
      #("code_challenge_method", "S256"),
      #("state", "xyz"),
      #("nonce", "n1"),
      #("decision", "approve"),
    ])
    |> dispatch
  assert approve_resp.status == 303
  assert drain_subject(fetch_log) == []
  let approve_query = parse_location_query(approve_resp)
  let assert Ok(auth_code) = list.key_find(approve_query, "code")
  assert list.key_find(approve_query, "iss") == Ok(test_issuer)
  assert list.key_find(approve_query, "state") == Ok("xyz")

  // 5. Sending client_secret or Basic auth for a CIMD public client at /oidc/token is REJECTED with 401 invalid_client
  let err_code_decoder = decode.field("error", decode.string, decode.success)

  let post_secret_attempt =
    simulate.request(http.Post, "/oidc/token")
    |> simulate.form_body([
      #("grant_type", "authorization_code"),
      #("client_id", cimd_client_id),
      #("client_secret", "lote_cs_unexpected_secret_for_public_cimd_client"),
      #("code", auth_code),
      #("redirect_uri", same_origin_cb),
      #("code_verifier", valid_verifier),
    ])
    |> dispatch
  assert post_secret_attempt.status == 401
  assert json.parse(simulate.read_body(post_secret_attempt), err_code_decoder)
    == Ok("invalid_client")

  let basic_auth_attempt =
    simulate.request(http.Post, "/oidc/token")
    |> request.set_header(
      "authorization",
      basic_auth_header(uri.percent_encode(cimd_client_id), "any_secret"),
    )
    |> simulate.form_body([
      #("grant_type", "authorization_code"),
      #("code", auth_code),
      #("redirect_uri", same_origin_cb),
      #("code_verifier", valid_verifier),
    ])
    |> dispatch
  assert basic_auth_attempt.status == 401
  assert json.parse(simulate.read_body(basic_auth_attempt), err_code_decoder)
    == Ok("invalid_client")

  // 6. Legitimate public-client token exchange (token_endpoint_auth_method: none)
  let tok_resp =
    simulate.request(http.Post, "/oidc/token")
    |> simulate.form_body([
      #("grant_type", "authorization_code"),
      #("client_id", cimd_client_id),
      #("code", auth_code),
      #("redirect_uri", same_origin_cb),
      #("code_verifier", valid_verifier),
    ])
    |> dispatch
  assert tok_resp.status == 200
  let assert #(at1, Some(rt1), Some(idt1)) = parse_token_bundle(tok_resp)

  // 7. Verify ES256 id_token aud == cimd_client_id, nonce, name, and at_hash
  let assert Ok(claims) =
    jwt.verify_id_token(
      keyring,
      idt1,
      test_issuer,
      cimd_client_id,
      jwt.now_unix_seconds(),
    )
  assert claims.aud == cimd_client_id
  assert claims.nonce == Some("n1")
  assert claims.name == Some("CimdAlice")
  assert claims.at_hash == Some(jwt.compute_at_hash(at1))

  // 8. GET /oidc/userinfo returns sub + name
  let uinfo_resp =
    simulate.request(http.Get, "/oidc/userinfo")
    |> request.set_header("authorization", "Bearer " <> at1)
    |> dispatch
  assert uinfo_resp.status == 200
  assert parse_userinfo(uinfo_resp) == #(claims.sub, Some("CimdAlice"))

  // 9. POST /api/v1/posts creates a post attributed to the user
  let post_resp =
    simulate.request(http.Post, "/api/v1/posts")
    |> request.set_header("authorization", "Bearer " <> at1)
    |> simulate.json_body(
      json.object([#("body", json.string("Hello from CIMD MCP client"))]),
    )
    |> dispatch
  assert post_resp.status == 201
  let post_author_decoder = decode.at(["post", "author_name"], decode.string)
  assert json.parse(simulate.read_body(post_resp), post_author_decoder)
    == Ok("CimdAlice")

  // 10. GET /settings/grants displays the CIMD badge, client name, and metadata URL
  let grants_resp =
    simulate.browser_request(http.Get, "/settings/grants")
    |> simulate.session(consent_get_req, consent_get_resp)
    |> dispatch
  assert grants_resp.status == 200
  let grants_html = simulate.read_body(grants_resp)
  assert string.contains(grants_html, "CIMD")
  assert string.contains(grants_html, "Example MCP Inspector")
  assert string.contains(grants_html, cimd_client_id)

  // 11. Refresh token rotation at POST /oidc/token
  let refresh_resp =
    simulate.request(http.Post, "/oidc/token")
    |> simulate.form_body([
      #("grant_type", "refresh_token"),
      #("client_id", cimd_client_id),
      #("refresh_token", rt1),
    ])
    |> dispatch
  assert refresh_resp.status == 200
  let assert #(at2, Some(rt2), Some(idt2)) = parse_token_bundle(refresh_resp)
  assert at2 != at1
  assert rt2 != rt1
  let assert Ok(refreshed_claims) =
    jwt.verify_id_token(
      keyring,
      idt2,
      test_issuer,
      cimd_client_id,
      jwt.now_unix_seconds(),
    )
  assert refreshed_claims.aud == cimd_client_id
  assert refreshed_claims.sub == claims.sub

  // 12. POST /oidc/revoke revokes the CIMD grant
  let revoke_resp =
    simulate.request(http.Post, "/oidc/revoke")
    |> simulate.form_body([
      #("client_id", cimd_client_id),
      #("token", rt2),
    ])
    |> dispatch
  assert revoke_resp.status == 200

  let revoked_uinfo =
    simulate.request(http.Get, "/oidc/userinfo")
    |> request.set_header("authorization", "Bearer " <> at2)
    |> dispatch
  assert revoked_uinfo.status == 401
}

pub fn cimd_authorize_security_rejections_never_redirect_test() {
  use tx <- test_helper.with_db

  let ssrf_url = "https://ssrf.example/oauth/metadata.json"
  let redirect_302_url = "https://redirect302.example/oauth/metadata.json"
  let mismatch_url = "https://mismatch.example/oauth/metadata.json"
  let has_secret_url = "https://confidential-cimd.example/oauth/metadata.json"
  let valid_cimd_url = "https://valid-cimd.example/oauth/metadata.json"
  let valid_cb = "https://valid-cimd.example/oauth/callback"

  let fetch_log = process.new_subject()
  let fetcher = fn(url: String) {
    process.send(fetch_log, url)
    case url {
      u if u == ssrf_url -> Error(cimd.BlockedAddress("127.0.0.1"))
      u if u == redirect_302_url ->
        Ok(
          cimd.FetchResponse(
            status: 302,
            content_type: "text/html",
            cache_control: None,
            body: <<"redirecting":utf8>>,
          ),
        )
      u if u == mismatch_url ->
        Ok(
          json_fetch_response(
            valid_metadata_json(
              "https://other.example/oauth/metadata.json",
              "Wrong ID",
              [
                "https://other.example/cb",
              ],
            ),
          ),
        )
      u if u == has_secret_url -> {
        let bad_doc =
          json.object([
            #("client_id", json.string(has_secret_url)),
            #("client_name", json.string("Secret CIMD")),
            #(
              "redirect_uris",
              json.array(["https://confidential-cimd.example/cb"], json.string),
            ),
            #("token_endpoint_auth_method", json.string("none")),
            #("client_secret", json.string("forbidden_secret")),
          ])
          |> json.to_string
        Ok(json_fetch_response(bad_doc))
      }
      u if u == valid_cimd_url ->
        Ok(
          json_fetch_response(
            valid_metadata_json(valid_cimd_url, "Valid CIMD App", [valid_cb]),
          ),
        )
      _ -> Error(cimd.InvalidHttpResponse("unexpected fetch: " <> url))
    }
  }

  let keyring = jwt.new_keyring(jwt.generate_signing_key(), [])
  let dispatch =
    setup_dispatch(tx, keyring, rate_limit.disabled(), fetcher, "198.51.100.55")
  let challenge = token.compute_pkce_s256_challenge(valid_verifier)

  let assert_400_no_redirect = fn(cid: String, redir: String) {
    let resp =
      dispatch(simulate.browser_request(
        http.Get,
        "/oidc/authorize?client_id="
          <> uri.percent_encode(cid)
          <> "&redirect_uri="
          <> uri.percent_encode(redir)
          <> "&response_type=code&scope=openid&code_challenge="
          <> challenge
          <> "&code_challenge_method=S256&state=attack",
      ))
    assert resp.status == 400
    assert response.get_header(resp, "location") == Error(Nil)
    let assert Ok(csp) = response.get_header(resp, "content-security-policy")
    assert string.contains(csp, "frame-ancestors 'none'")
  }

  // Invalid CIMD URLs are rejected before any outbound network fetch
  list.each(
    [
      "http://mcp-client.example/oauth/metadata.json",
      "https://mcp-client.example/oauth/metadata.json#frag",
      "https://127.0.0.1/client.json",
      "https://[::1]/client.json",
      "https://mcp-client.example",
    ],
    fn(bad_cid) {
      assert_400_no_redirect(bad_cid, "https://evil.example/steal")
    },
  )
  assert drain_subject(fetch_log) == []

  // Fetch & document validation failures return 400 HTML without redirecting
  assert_400_no_redirect(ssrf_url, "https://evil.example/steal")
  assert_400_no_redirect(redirect_302_url, "https://evil.example/steal")
  assert_400_no_redirect(mismatch_url, "https://other.example/cb")
  assert_400_no_redirect(has_secret_url, "https://confidential-cimd.example/cb")
  // Unregistered redirect_uri on an otherwise valid CIMD client also returns 400 without redirecting
  assert_400_no_redirect(valid_cimd_url, "https://evil.example/steal")
}

pub fn cimd_outbound_fetch_ip_rate_limit_blocks_uncached_flood_with_429_test() {
  use tx <- test_helper.with_db

  let assert Ok(limiter) = rate_limit.start_memory(test_secret)
  let fetch_log = process.new_subject()
  let fetcher = fn(url: String) {
    process.send(fetch_log, url)
    let cb = url <> "/callback"
    Ok(json_fetch_response(valid_metadata_json(url, "App", [cb])))
  }

  let keyring = jwt.new_keyring(jwt.generate_signing_key(), [])
  let dispatch = setup_dispatch(tx, keyring, limiter, fetcher, "198.51.100.200")
  let challenge = token.compute_pkce_s256_challenge(valid_verifier)

  let make_authz_url = fn(idx: Int) {
    let cid =
      "https://rate" <> int.to_string(idx) <> ".example/oauth/client.json"
    let cb = cid <> "/callback"
    "/oidc/authorize?client_id="
    <> uri.percent_encode(cid)
    <> "&redirect_uri="
    <> uri.percent_encode(cb)
    <> "&response_type=code&scope=openid&code_challenge="
    <> challenge
    <> "&code_challenge_method=S256"
  }

  // Burst of 10 uncached CIMD metadata lookups from the same IP succeeds
  list.each([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], fn(i) {
    let resp = dispatch(simulate.browser_request(http.Get, make_authz_url(i)))
    assert resp.status == 303
  })
  assert list.length(drain_subject(fetch_log)) == 10

  // 11th uncached CIMD lookup from the same IP is blocked with 429 BEFORE calling fetcher!
  let blocked_resp =
    dispatch(simulate.browser_request(http.Get, make_authz_url(11)))
  assert blocked_resp.status == 429
  assert response.get_header(blocked_resp, "location") == Error(Nil)
  let assert Ok(retry_after_str) =
    response.get_header(blocked_resp, "retry-after")
  let assert Ok(retry_after_secs) = int.parse(retry_after_str)
  assert retry_after_secs >= 1
  let assert Ok(csp) =
    response.get_header(blocked_resp, "content-security-policy")
  assert string.contains(csp, "frame-ancestors 'none'")
  assert string.contains(
    simulate.read_body(blocked_resp),
    "Too many client metadata lookups",
  )
  assert drain_subject(fetch_log) == []

  // Meanwhile, already-cached CIMD client #1 still resolves without hitting outbound rate limit!
  let cached_resp =
    dispatch(simulate.browser_request(http.Get, make_authz_url(1)))
  assert cached_resp.status == 303
  assert drain_subject(fetch_log) == []

  rate_limit.stop_memory(limiter)
}

pub fn cimd_token_revalidates_expired_metadata_shrinks_scopes_and_handles_takedown_test() {
  use tx <- test_helper.with_db

  let assert Ok(alice) = user.create(tx, "CimdRevalAlice")
  let login_init = simulate.browser_request(http.Post, "/auth/password/login")
  let assert Ok(alice_login) =
    session.create(wisp.ok(), login_init, tx, test_secret, alice)

  let cid = "https://evolving-client.example/oauth/metadata.json"
  let cb = "https://evolving-client.example/oauth/callback"

  let doc_v1 = valid_metadata_json(cid, "Evolving App", [cb])
  let doc_v2_shrunk =
    json.object([
      #("client_id", json.string(cid)),
      #("client_name", json.string("Evolving App v2")),
      #("redirect_uris", json.array([cb], json.string)),
      #(
        "grant_types",
        json.array(["authorization_code", "refresh_token"], json.string),
      ),
      #("response_types", json.array(["code"], json.string)),
      #("token_endpoint_auth_method", json.string("none")),
      #("scope", json.string("openid posts:read offline_access")),
    ])
    |> json.to_string

  let keyring = jwt.new_keyring(jwt.generate_signing_key(), [])
  let challenge = token.compute_pkce_s256_challenge(valid_verifier)

  let dispatch_with_doc = fn(resp: Result(cimd.FetchResponse, cimd.FetchError)) {
    setup_dispatch(
      tx,
      keyring,
      rate_limit.disabled(),
      fn(_url) { resp },
      "198.51.100.70",
    )
  }

  let dispatch_v1 = dispatch_with_doc(Ok(json_fetch_response(doc_v1)))

  // 1. Authorize v1 with `openid posts:read posts:write offline_access`
  let authz_url =
    "/oidc/authorize?client_id="
    <> uri.percent_encode(cid)
    <> "&redirect_uri="
    <> uri.percent_encode(cb)
    <> "&response_type=code&scope="
    <> uri.percent_encode("openid posts:read posts:write offline_access")
    <> "&code_challenge="
    <> challenge
    <> "&code_challenge_method=S256"

  let get_req =
    simulate.browser_request(http.Get, authz_url)
    |> simulate.session(login_init, alice_login)
  let get_resp = dispatch_v1(get_req)
  assert get_resp.status == 200
  let csrf_tok = extract_form_csrf_token(simulate.read_body(get_resp))

  let approve_resp =
    simulate.browser_request(http.Post, "/oidc/authorize")
    |> simulate.session(get_req, get_resp)
    |> simulate.form_body([
      #(csrf.form_field_name, csrf_tok),
      #("client_id", cid),
      #("redirect_uri", cb),
      #("response_type", "code"),
      #("scope", "openid posts:read posts:write offline_access"),
      #("code_challenge", challenge),
      #("code_challenge_method", "S256"),
      #("decision", "approve"),
    ])
    |> dispatch_v1
  assert approve_resp.status == 303
  let assert Ok(code) =
    list.key_find(parse_location_query(approve_resp), "code")

  let tok1_resp =
    simulate.request(http.Post, "/oidc/token")
    |> simulate.form_body([
      #("grant_type", "authorization_code"),
      #("client_id", cid),
      #("code", code),
      #("redirect_uri", cb),
      #("code_verifier", valid_verifier),
    ])
    |> dispatch_v1
  assert tok1_resp.status == 200
  let assert #(_at1, Some(rt1), Some(_idt1)) = parse_token_bundle(tok1_resp)

  // 2. Expire cimd_expires_at and shrink metadata scopes (removing posts:write)
  let assert Ok(_) =
    pog.query(
      "UPDATE oidc_clients SET cimd_expires_at = NOW() - INTERVAL '10 seconds' WHERE client_id = $1",
    )
    |> pog.parameter(pog.text(cid))
    |> pog.execute(tx)

  let dispatch_v2 = dispatch_with_doc(Ok(json_fetch_response(doc_v2_shrunk)))

  // Refreshing without explicit `scope` narrows the issued access_token to the shrunk allowed_scopes!
  let refresh_resp =
    simulate.request(http.Post, "/oidc/token")
    |> simulate.form_body([
      #("grant_type", "refresh_token"),
      #("client_id", cid),
      #("refresh_token", rt1),
    ])
    |> dispatch_v2
  assert refresh_resp.status == 200
  let assert #(at2, Some(rt2), Some(_idt2)) = parse_token_bundle(refresh_resp)

  assert dispatch_v2(
      simulate.request(http.Get, "/api/v1/posts")
      |> request.set_header("authorization", "Bearer " <> at2),
    ).status
    == 200

  let blocked_write =
    simulate.request(http.Post, "/api/v1/posts")
    |> request.set_header("authorization", "Bearer " <> at2)
    |> simulate.json_body(json.object([#("body", json.string("denied"))]))
    |> dispatch_v2
  assert blocked_write.status == 403

  // 3. Expire cimd_expires_at again and simulate 404 takedown of the metadata document
  let assert Ok(_) =
    pog.query(
      "UPDATE oidc_clients SET cimd_expires_at = NOW() - INTERVAL '10 seconds' WHERE client_id = $1",
    )
    |> pog.parameter(pog.text(cid))
    |> pog.execute(tx)

  let dispatch_404 =
    dispatch_with_doc(
      Ok(
        cimd.FetchResponse(
          status: 404,
          content_type: "application/json",
          cache_control: None,
          body: <<"{\"error\":\"not_found\"}":utf8>>,
        ),
      ),
    )

  // Refresh token rotation is blocked with 401 invalid_client when expired metadata returns 404!
  let takedown_refresh =
    simulate.request(http.Post, "/oidc/token")
    |> simulate.form_body([
      #("grant_type", "refresh_token"),
      #("client_id", cid),
      #("refresh_token", rt2),
    ])
    |> dispatch_404
  assert takedown_refresh.status == 401

  // Meanwhile, POST /oidc/revoke STILL works offline without requiring a live metadata fetch!
  let offline_revoke =
    simulate.request(http.Post, "/oidc/revoke")
    |> simulate.form_body([
      #("client_id", cid),
      #("token", rt2),
    ])
    |> dispatch_404
  assert offline_revoke.status == 200

  assert dispatch_404(
      simulate.request(http.Get, "/api/v1/posts")
      |> request.set_header("authorization", "Bearer " <> at2),
    ).status
    == 401
}

pub fn cimd_port_aware_origin_warning_and_bdi_isolation_test() {
  use tx <- test_helper.with_db

  let assert Ok(alice) = user.create(tx, "PortWarnAlice")
  let login_init = simulate.browser_request(http.Post, "/auth/password/login")
  let assert Ok(alice_login) =
    session.create(wisp.ok(), login_init, tx, test_secret, alice)

  let shared_8443_cid = "https://shared.example:8443/evil/client.json"
  let shared_443_cb = "https://shared.example/callback"
  let same_8443_cid = "https://sameport.example:8443/oauth/client.json"
  let same_8443_cb = "https://sameport.example:8443/callback"

  let fetcher = fn(url: String) {
    case url == shared_8443_cid {
      True ->
        Ok(
          json_fetch_response(
            valid_metadata_json(shared_8443_cid, "Unpriv Port App", [
              shared_443_cb,
            ]),
          ),
        )
      False ->
        Ok(
          json_fetch_response(
            valid_metadata_json(same_8443_cid, "Same Port App", [same_8443_cb]),
          ),
        )
    }
  }

  let keyring = jwt.new_keyring(jwt.generate_signing_key(), [])
  let dispatch =
    setup_dispatch(tx, keyring, rate_limit.disabled(), fetcher, "198.51.100.71")
  let challenge = token.compute_pkce_s256_challenge(valid_verifier)

  // Case 1: `:8443` client_id vs `:443` redirect_uri MUST display `shared.example:8443` AND cross-origin warning + `<bdi>`
  let mismatch_port_resp =
    simulate.browser_request(
      http.Get,
      "/oidc/authorize?client_id="
        <> uri.percent_encode(shared_8443_cid)
        <> "&redirect_uri="
        <> uri.percent_encode(shared_443_cb)
        <> "&response_type=code&scope=openid&code_challenge="
        <> challenge
        <> "&code_challenge_method=S256",
    )
    |> simulate.session(login_init, alice_login)
    |> dispatch
  assert mismatch_port_resp.status == 200
  let mismatch_html = simulate.read_body(mismatch_port_resp)
  assert string.contains(mismatch_html, "shared.example:8443")
  assert string.contains(mismatch_html, "differs from client domain")
  assert string.contains(mismatch_html, "<bdi>Unpriv Port App</bdi>")

  // Case 2: `:8443` client_id vs `:8443` redirect_uri has matching origin -> NO false cross-origin warning!
  let same_port_resp =
    simulate.browser_request(
      http.Get,
      "/oidc/authorize?client_id="
        <> uri.percent_encode(same_8443_cid)
        <> "&redirect_uri="
        <> uri.percent_encode(same_8443_cb)
        <> "&response_type=code&scope=openid&code_challenge="
        <> challenge
        <> "&code_challenge_method=S256",
    )
    |> simulate.session(login_init, alice_login)
    |> dispatch
  assert same_port_resp.status == 200
  let same_html = simulate.read_body(same_port_resp)
  assert string.contains(same_html, "sameport.example:8443")
  assert !string.contains(same_html, "differs from client domain")
}
