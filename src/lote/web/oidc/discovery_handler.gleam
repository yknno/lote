import gleam/http
import gleam/http/response
import gleam/json
import gleam/option.{None}
import gleam/uri
import wisp

const discovery_cache_control = "public, max-age=300"

pub fn handle_well_known(
  req: wisp.Request,
  segments: List(String),
  issuer: String,
  jwks_json: String,
) -> wisp.Response {
  let issuer_segments = issuer_path_segments(issuer)

  case segments {
    ["openid-configuration"] | ["oauth-authorization-server"] ->
      serve_discovery_doc(req, fn() { metadata_json(issuer) })

    ["openid-configuration", ..tail]
      | ["oauth-authorization-server", ..tail]
      if tail != [] && tail == issuer_segments
    -> serve_discovery_doc(req, fn() { metadata_json(issuer) })

    ["oauth-protected-resource"] ->
      serve_discovery_doc(req, fn() { protected_resource_metadata_json(issuer) })

    ["oauth-protected-resource", ..tail]
      if tail != [] && tail == issuer_segments
    ->
      serve_discovery_doc(req, fn() { protected_resource_metadata_json(issuer) })

    ["jwks.json"] -> serve_discovery_doc(req, fn() { jwks_json })

    ["jwks.json", ..tail] if tail != [] && tail == issuer_segments ->
      serve_discovery_doc(req, fn() { jwks_json })

    _ -> wisp.not_found()
  }
}

pub fn issuer_path_segments(issuer: String) -> List(String) {
  case uri.parse(issuer) {
    Ok(parsed) -> uri.path_segments(parsed.path)
    Error(_) -> []
  }
}

/// Constructs the RFC 9728 §3.1 Protected Resource Metadata URL by inserting
/// `/.well-known/oauth-protected-resource` between the origin and any path.
pub fn resource_metadata_url(issuer: String) -> String {
  case uri.parse(issuer) {
    Ok(parsed) -> {
      let origin =
        uri.Uri(..parsed, path: "", query: None, fragment: None)
        |> uri.to_string
      origin <> "/.well-known/oauth-protected-resource" <> parsed.path
    }
    Error(_) -> issuer <> "/.well-known/oauth-protected-resource"
  }
}

fn serve_discovery_doc(
  req: wisp.Request,
  render_json: fn() -> String,
) -> wisp.Response {
  case req.method {
    http.Get ->
      render_json()
      |> wisp.json_response(200)
      |> response.set_header("cache-control", discovery_cache_control)
      |> response.set_header("access-control-allow-origin", "*")
    http.Options ->
      wisp.response(204)
      |> response.set_header("access-control-allow-origin", "*")
      |> response.set_header(
        "access-control-allow-methods",
        "GET, HEAD, OPTIONS",
      )
      |> response.set_header(
        "access-control-allow-headers",
        "authorization, content-type, mcp-protocol-version",
      )
      |> response.set_header("access-control-max-age", "86400")
    _ -> wisp.method_not_allowed([http.Get, http.Head, http.Options])
  }
}

pub fn protected_resource_metadata_json(issuer: String) -> String {
  json.object([
    #("resource", json.string(issuer)),
    #("authorization_servers", json.array([issuer], json.string)),
    #("jwks_uri", json.string(issuer <> "/.well-known/jwks.json")),
    #(
      "scopes_supported",
      json.array(
        [
          "openid",
          "profile",
          "offline_access",
          "posts:read",
          "posts:write",
          "posts:delete",
        ],
        json.string,
      ),
    ),
    #("bearer_methods_supported", json.array(["header"], json.string)),
  ])
  |> json.to_string
}

pub fn metadata_json(issuer: String) -> String {
  json.object([
    #("issuer", json.string(issuer)),
    #("authorization_endpoint", json.string(issuer <> "/oidc/authorize")),
    #("token_endpoint", json.string(issuer <> "/oidc/token")),
    #("userinfo_endpoint", json.string(issuer <> "/oidc/userinfo")),
    #("jwks_uri", json.string(issuer <> "/.well-known/jwks.json")),
    #("revocation_endpoint", json.string(issuer <> "/oidc/revoke")),
    #("introspection_endpoint", json.string(issuer <> "/oidc/introspect")),
    #("response_types_supported", json.array(["code"], json.string)),
    #("response_modes_supported", json.array(["query"], json.string)),
    #(
      "grant_types_supported",
      json.array(
        ["authorization_code", "refresh_token", "client_credentials"],
        json.string,
      ),
    ),
    #("subject_types_supported", json.array(["public"], json.string)),
    #(
      "id_token_signing_alg_values_supported",
      json.array(["ES256"], json.string),
    ),
    #(
      "scopes_supported",
      json.array(
        [
          "openid",
          "profile",
          "offline_access",
          "posts:read",
          "posts:write",
          "posts:delete",
        ],
        json.string,
      ),
    ),
    #(
      "token_endpoint_auth_methods_supported",
      json.array(
        ["client_secret_basic", "client_secret_post", "none"],
        json.string,
      ),
    ),
    #(
      "revocation_endpoint_auth_methods_supported",
      json.array(
        ["client_secret_basic", "client_secret_post", "none"],
        json.string,
      ),
    ),
    #(
      "introspection_endpoint_auth_methods_supported",
      json.array(["client_secret_basic", "client_secret_post"], json.string),
    ),
    #(
      "claims_supported",
      json.array(
        ["iss", "sub", "aud", "exp", "iat", "nonce", "at_hash", "name"],
        json.string,
      ),
    ),
    #("code_challenge_methods_supported", json.array(["S256"], json.string)),
    #("authorization_response_iss_parameter_supported", json.bool(True)),
    #("client_id_metadata_document_supported", json.bool(False)),
    #("claims_parameter_supported", json.bool(False)),
    #("request_parameter_supported", json.bool(False)),
    #("request_uri_parameter_supported", json.bool(False)),
  ])
  |> json.to_string
}
