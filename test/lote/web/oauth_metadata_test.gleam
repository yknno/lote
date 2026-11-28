import gleam/dynamic/decode
import gleam/http
import gleam/http/request
import gleam/http/response
import gleam/json
import gleam/option.{None}
import gleam/set
import gleam/string
import lote/auth.{Auth, Password}
import lote/auth/user
import lote/oidc
import lote/oidc/client
import lote/oidc/jwt
import lote/oidc/scope
import lote/rate_limit
import lote/realtime/pubsub
import lote/test_helper
import lote/web/oidc/discovery_handler
import lote/web/router
import pog
import wisp
import wisp/simulate

const test_secret =
  "oauth_metadata_test_secret_key_base_0123456789abcdefghijklmnop"

fn setup_dispatch(
  tx: pog.Connection,
  issuer: String,
) -> fn(wisp.Request) -> wisp.Response {
  let assert Ok(session_revocations) = pubsub.start()
  let assert Ok(grant_revocations) = pubsub.start()
  let assert Ok(post_pubsub) = pubsub.start()
  let limiter = rate_limit.disabled()
  let keyring = jwt.new_keyring(jwt.generate_signing_key(), [])

  let auth_ctx =
    Auth(
      db: tx,
      secret_key_base: test_secret,
      methods: [Password],
      session_revocations:,
      rate_limiter: limiter,
    )
  let oidc_ctx =
    oidc.new_with_keyring(tx, issuer, keyring, grant_revocations, limiter)

  fn(req: wisp.Request) {
    router.handle_request_with_oidc(
      req,
      auth_ctx,
      oidc_ctx,
      post_pubsub,
      "198.51.100.90",
    )
  }
}

pub fn rfc9728_protected_resource_and_rfc8414_as_metadata_root_issuer_test() {
  use tx <- test_helper.with_db
  let issuer = "https://lote.example"
  let dispatch = setup_dispatch(tx, issuer)

  assert discovery_handler.resource_metadata_url(issuer)
    == "https://lote.example/.well-known/oauth-protected-resource"

  // 1. GET /.well-known/oauth-protected-resource (RFC 9728)
  let prm_resp =
    dispatch(simulate.request(http.Get, "/.well-known/oauth-protected-resource"))
  assert prm_resp.status == 200
  assert response.get_header(prm_resp, "cache-control")
    == Ok("public, max-age=300")
  assert response.get_header(prm_resp, "access-control-allow-origin") == Ok("*")

  let prm_decoder = {
    use resource <- decode.field("resource", decode.string)
    use auth_servers <- decode.field(
      "authorization_servers",
      decode.list(decode.string),
    )
    use jwks_uri <- decode.field("jwks_uri", decode.string)
    use scopes <- decode.field("scopes_supported", decode.list(decode.string))
    use bearer_methods <- decode.field(
      "bearer_methods_supported",
      decode.list(decode.string),
    )
    decode.success(#(resource, auth_servers, jwks_uri, scopes, bearer_methods))
  }
  let assert Ok(#(resource, auth_servers, jwks_uri, scopes, bearer_methods)) =
    json.parse(simulate.read_body(prm_resp), prm_decoder)
  assert resource == issuer
  assert auth_servers == [issuer]
  assert jwks_uri == issuer <> "/.well-known/jwks.json"
  assert bearer_methods == ["header"]
  assert scopes
    == [
      "openid",
      "profile",
      "offline_access",
      "posts:read",
      "posts:write",
      "posts:delete",
    ]

  // 2. GET /.well-known/oauth-authorization-server (RFC 8414)
  let asm_resp =
    dispatch(simulate.request(
      http.Get,
      "/.well-known/oauth-authorization-server",
    ))
  assert asm_resp.status == 200
  assert response.get_header(asm_resp, "access-control-allow-origin") == Ok("*")
  let asm_decoder = {
    use iss <- decode.field("issuer", decode.string)
    use authz <- decode.field("authorization_endpoint", decode.string)
    use tok <- decode.field("token_endpoint", decode.string)
    use pkce <- decode.field(
      "code_challenge_methods_supported",
      decode.list(decode.string),
    )
    use cimd_sup <- decode.field(
      "client_id_metadata_document_supported",
      decode.bool,
    )
    decode.success(#(iss, authz, tok, pkce, cimd_sup))
  }
  assert json.parse(simulate.read_body(asm_resp), asm_decoder)
    == Ok(#(
      issuer,
      issuer <> "/oidc/authorize",
      issuer <> "/oidc/token",
      ["S256"],
      True,
    ))

  // 3. Browser MCP CORS preflight OPTIONS works with 204; POST returns 405
  let opt_resp =
    simulate.request(http.Options, "/.well-known/oauth-protected-resource")
    |> request.set_header("origin", "https://inspector.mcp.example")
    |> request.set_header(
      "access-control-request-headers",
      "mcp-protocol-version",
    )
    |> dispatch
  assert opt_resp.status == 204
  assert response.get_header(opt_resp, "access-control-allow-origin") == Ok("*")
  let assert Ok(allow_headers) =
    response.get_header(opt_resp, "access-control-allow-headers")
  assert string.contains(allow_headers, "mcp-protocol-version")

  assert dispatch(simulate.request(
      http.Post,
      "/.well-known/oauth-protected-resource",
    )).status
    == 405
}

pub fn rfc9728_and_rfc8414_subpath_issuer_and_www_authenticate_discovery_flow_test() {
  use tx <- test_helper.with_db
  let sub_issuer = "https://lote.example:8443/idp"
  let dispatch = setup_dispatch(tx, sub_issuer)

  // RFC 9728 §3.1 inserts /.well-known/oauth-protected-resource between authority and path
  let expected_meta_url =
    "https://lote.example:8443/.well-known/oauth-protected-resource/idp"
  assert discovery_handler.resource_metadata_url(sub_issuer)
    == expected_meta_url

  // Step 1: Unauthenticated client hits GET /api/v1/posts -> 401 WWW-Authenticate points to expected_meta_url
  let unauth_api = dispatch(simulate.request(http.Get, "/api/v1/posts"))
  assert unauth_api.status == 401
  assert response.get_header(unauth_api, "www-authenticate")
    == Ok(
      "Bearer realm=\"lote\", resource_metadata=\"" <> expected_meta_url <> "\"",
    )

  // Step 2: Client fetches `/.well-known/oauth-protected-resource/idp` (and `/idp/.well-known/oauth-protected-resource`)
  let prm_inserted =
    dispatch(simulate.request(
      http.Get,
      "/.well-known/oauth-protected-resource/idp",
    ))
  assert prm_inserted.status == 200
  let resource_decoder = {
    use resource <- decode.field("resource", decode.string)
    use auth_servers <- decode.field(
      "authorization_servers",
      decode.list(decode.string),
    )
    decode.success(#(resource, auth_servers))
  }
  assert json.parse(simulate.read_body(prm_inserted), resource_decoder)
    == Ok(#(sub_issuer, [sub_issuer]))

  assert dispatch(simulate.request(
      http.Get,
      "/idp/.well-known/oauth-protected-resource",
    )).status
    == 200
  assert dispatch(simulate.request(
      http.Get,
      "/.well-known/oauth-protected-resource/wrong",
    )).status
    == 404

  // Step 3: Client discovers AS metadata at RFC 8414 path-inserted URL `/.well-known/oauth-authorization-server/idp`
  let asm_inserted =
    dispatch(simulate.request(
      http.Get,
      "/.well-known/oauth-authorization-server/idp",
    ))
  assert asm_inserted.status == 200
  let iss_decoder = decode.field("issuer", decode.string, decode.success)
  assert json.parse(simulate.read_body(asm_inserted), iss_decoder)
    == Ok(sub_issuer)
  assert dispatch(simulate.request(
      http.Get,
      "/idp/.well-known/oauth-authorization-server",
    )).status
    == 200
  assert dispatch(simulate.request(
      http.Get,
      "/.well-known/oauth-authorization-server/wrong",
    )).status
    == 404

  // Step 4: Verify 403 insufficient_scope & /oidc/userinfo 400 invalid_request also include resource_metadata
  let assert Ok(alice) = user.create(tx, "MetaAlice")
  let assert Ok(bot) =
    client.create_subordinate_bot(
      tx,
      alice.id,
      "ReadOnly Bot",
      set.from_list([scope.PostsRead]),
      "default",
      None,
    )
  let tok_resp =
    simulate.request(http.Post, "/idp/oidc/token")
    |> simulate.form_body([
      #("grant_type", "client_credentials"),
      #("client_id", bot.client.client_id),
      #("client_secret", bot.secret.secret),
    ])
    |> dispatch
  assert tok_resp.status == 200
  let assert Ok(at) =
    json.parse(
      simulate.read_body(tok_resp),
      decode.field("access_token", decode.string, decode.success),
    )

  let insufficient_resp =
    simulate.request(http.Get, "/idp/oidc/userinfo")
    |> request.set_header("authorization", "Bearer " <> at)
    |> dispatch
  assert insufficient_resp.status == 403
  assert response.get_header(insufficient_resp, "www-authenticate")
    == Ok(
      "Bearer realm=\"lote\", error=\"insufficient_scope\", scope=\"openid\", resource_metadata=\""
      <> expected_meta_url
      <> "\"",
    )

  let query_tok_resp =
    dispatch(simulate.request(
      http.Get,
      "/idp/oidc/userinfo?access_token=" <> at,
    ))
  assert query_tok_resp.status == 400
  assert response.get_header(query_tok_resp, "www-authenticate")
    == Ok(
      "Bearer realm=\"lote\", error=\"invalid_request\", resource_metadata=\""
      <> expected_meta_url
      <> "\"",
    )
}
