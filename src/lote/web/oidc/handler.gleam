import gleam/bit_array
import gleam/http
import gleam/http/request
import gleam/http/response
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/set.{type Set}
import gleam/string
import gleam/uri
import lote/oidc.{type Oidc}
import lote/oidc/client.{type Client}
import lote/oidc/scope.{type Scope}
import lote/oidc/token
import lote/rate_limit
import lote/web/client_ip
import lote/web/rate_policy
import wisp

pub const ip_endpoint_policy = rate_policy.oidc_ip_policy

pub const client_auth_fail_policy = rate_policy.oidc_client_auth_policy

const basic_www_authenticate = "Basic realm=\"lote\", charset=\"UTF-8\""

const max_oauth_form_bytes = 16_384

type ExtractedCredentials {
  ExtractedCredentials(
    client_id: Option(String),
    client_secret: Option(String),
    used_basic: Bool,
  )
}

type CredentialExtractError {
  MalformedBasicHeader
  InvalidCredentialRequest
}

type ClientAuthOutcome {
  ClientAuthenticated(Client)
  ClientAuthRejected(wisp.Response)
}

pub fn handle_request(
  req: wisp.Request,
  segments: List(String),
  oidc_ctx: Oidc,
  client_ip: String,
) -> wisp.Response {
  let resp = case req.method, segments {
    http.Post, ["token"] -> handle_token(req, oidc_ctx, client_ip)
    _, ["token"] -> wisp.method_not_allowed([http.Post])

    http.Post, ["revoke"] -> handle_revoke(req, oidc_ctx, client_ip)
    _, ["revoke"] -> wisp.method_not_allowed([http.Post])

    http.Post, ["introspect"] -> handle_introspect(req, oidc_ctx, client_ip)
    _, ["introspect"] -> wisp.method_not_allowed([http.Post])

    _, _ -> wisp.not_found()
  }

  with_no_store_headers(resp)
}

fn handle_token(
  req: wisp.Request,
  oidc_ctx: Oidc,
  client_ip: String,
) -> wisp.Response {
  use form_values <- require_oauth_form(req)
  use creds <- require_extracted_credentials(req, form_values)

  case list.key_find(form_values, "grant_type") {
    Error(_) | Ok("") -> oauth_error(400, "invalid_request", None)

    Ok("client_credentials") -> {
      use client_id <- require_valid_client_id(creds)
      let ip_bucket = client_ip.rate_limit_bucket(client_ip)
      use <- require_ip_endpoint_limit(oidc_ctx.rate_limiter, ip_bucket)
      use authed_client <- with_authenticated_client(
        oidc_ctx,
        client_id,
        creds,
        ip_bucket,
        True,
      )
      handle_client_credentials_grant(req, oidc_ctx, authed_client, form_values)
    }

    Ok("authorization_code") -> {
      use client_id <- require_valid_client_id(creds)
      let ip_bucket = client_ip.rate_limit_bucket(client_ip)
      use <- require_ip_endpoint_limit(oidc_ctx.rate_limiter, ip_bucket)
      use authed_client <- with_authenticated_client(
        oidc_ctx,
        client_id,
        creds,
        ip_bucket,
        False,
      )
      handle_authorization_code_grant(oidc_ctx, authed_client, form_values)
    }

    Ok("refresh_token") -> {
      use client_id <- require_valid_client_id(creds)
      let ip_bucket = client_ip.rate_limit_bucket(client_ip)
      use <- require_ip_endpoint_limit(oidc_ctx.rate_limiter, ip_bucket)
      use authed_client <- with_authenticated_client(
        oidc_ctx,
        client_id,
        creds,
        ip_bucket,
        False,
      )
      handle_refresh_token_grant(oidc_ctx, authed_client, form_values)
    }

    Ok(_) -> oauth_error(400, "unsupported_grant_type", None)
  }
}

fn handle_client_credentials_grant(
  req: wisp.Request,
  oidc_ctx: Oidc,
  authed_client: Client,
  form_values: List(#(String, String)),
) -> wisp.Response {
  let result = {
    use requested_scopes <- result.try(parse_optional_scopes(form_values))
    let requested_resource = optional_non_empty_param(form_values, "resource")
    let user_agent = request.get_header(req, "user-agent") |> result.unwrap("")

    token.issue_client_credentials_for_client(
      oidc_ctx,
      authed_client,
      requested_scopes,
      requested_resource,
      user_agent,
    )
  }

  case result {
    Ok(issued) -> token_success_response(issued)
    Error(err) -> token_error_response(err)
  }
}

fn handle_authorization_code_grant(
  oidc_ctx: Oidc,
  authed_client: Client,
  form_values: List(#(String, String)),
) -> wisp.Response {
  let result = {
    use _ <- result.try(case authed_client.kind {
      client.SubordinateBot -> Error(token.UnauthorizedClient)
      _ -> Ok(Nil)
    })
    use code <- result.try(require_non_empty_param(form_values, "code"))
    use redirect_uri <- result.try(require_non_empty_param(
      form_values,
      "redirect_uri",
    ))
    use code_verifier <- result.try(require_non_empty_param(
      form_values,
      "code_verifier",
    ))
    let requested_resource = optional_non_empty_param(form_values, "resource")

    token.exchange_authorization_code(
      oidc_ctx,
      authed_client,
      code,
      redirect_uri,
      code_verifier,
      requested_resource,
    )
  }

  case result {
    Ok(issued) -> token_success_response(issued)
    Error(err) -> token_error_response(err)
  }
}

fn handle_refresh_token_grant(
  oidc_ctx: Oidc,
  authed_client: Client,
  form_values: List(#(String, String)),
) -> wisp.Response {
  let result = {
    use _ <- result.try(case authed_client.kind {
      client.SubordinateBot -> Error(token.UnauthorizedClient)
      _ -> Ok(Nil)
    })
    use raw_refresh_token <- result.try(require_non_empty_param(
      form_values,
      "refresh_token",
    ))
    use requested_scopes <- result.try(parse_optional_scopes(form_values))
    let requested_resource = optional_non_empty_param(form_values, "resource")

    token.rotate_refresh_token(
      oidc_ctx,
      authed_client,
      raw_refresh_token,
      requested_scopes,
      requested_resource,
    )
  }

  case result {
    Ok(issued) -> token_success_response(issued)
    Error(err) -> token_error_response(err)
  }
}

fn handle_revoke(
  req: wisp.Request,
  oidc_ctx: Oidc,
  client_ip: String,
) -> wisp.Response {
  use form_values <- require_oauth_form(req)
  use creds <- require_extracted_credentials(req, form_values)
  use client_id <- require_valid_client_id(creds)

  let ip_bucket = client_ip.rate_limit_bucket(client_ip)
  use authed_client <- with_authenticated_client(
    oidc_ctx,
    client_id,
    creds,
    ip_bucket,
    False,
  )

  case require_non_empty_param(form_values, "token") {
    Error(err) -> token_error_response(err)
    Ok(raw_token) ->
      case token.revoke_by_raw_token(oidc_ctx, authed_client, raw_token) {
        Ok(Nil) -> wisp.json_response("{}", 200)
        Error(_) -> oauth_error(500, "server_error", None)
      }
  }
}

fn handle_introspect(
  req: wisp.Request,
  oidc_ctx: Oidc,
  client_ip: String,
) -> wisp.Response {
  use form_values <- require_oauth_form(req)
  use creds <- require_extracted_credentials(req, form_values)
  use client_id <- require_valid_client_id(creds)

  let ip_bucket = client_ip.rate_limit_bucket(client_ip)
  use <- require_ip_endpoint_limit(oidc_ctx.rate_limiter, ip_bucket)
  use authed_client <- with_authenticated_client(
    oidc_ctx,
    client_id,
    creds,
    ip_bucket,
    True,
  )

  case require_non_empty_param(form_values, "token") {
    Error(err) -> token_error_response(err)
    Ok(raw_token) ->
      case token.introspect_raw_token(oidc_ctx.db, authed_client, raw_token) {
        Error(_) -> oauth_error(500, "server_error", None)
        Ok(token.Inactive) ->
          json.object([#("active", json.bool(False))])
          |> json.to_string
          |> wisp.json_response(200)
        Ok(token.Active(principal:, exp:, iat:)) ->
          json.object([
            #("active", json.bool(True)),
            #(
              "scope",
              json.string(scope.format_space_delimited(principal.scopes)),
            ),
            #("client_id", json.string(principal.client_id)),
            #("sub", json.string(principal.sub)),
            #("aud", json.string(principal.audience)),
            #("iss", json.string(oidc_ctx.issuer)),
            #("exp", json.int(exp)),
            #("iat", json.int(iat)),
            #("token_type", json.string("Bearer")),
          ])
          |> json.to_string
          |> wisp.json_response(200)
      }
  }
}

fn require_valid_client_id(
  creds: ExtractedCredentials,
  next: fn(String) -> wisp.Response,
) -> wisp.Response {
  case creds.client_id {
    Some(cid) ->
      case client.is_valid_client_id_format(cid) {
        True -> next(cid)
        False -> invalid_client_response()
      }
    None -> invalid_client_response()
  }
}

fn require_ip_endpoint_limit(
  limiter: rate_limit.Limiter,
  ip_bucket: String,
  next: fn() -> wisp.Response,
) -> wisp.Response {
  let key = rate_policy.oidc_ip_key(ip_bucket)
  case rate_limit.check(limiter, key, ip_endpoint_policy) {
    rate_limit.Allowed(_) -> next()
    rate_limit.Limited(retry_after_seconds:) ->
      rate_limited_response(retry_after_seconds)
  }
}

fn with_authenticated_client(
  oidc_ctx: Oidc,
  client_id: String,
  creds: ExtractedCredentials,
  ip_bucket: String,
  require_confidential: Bool,
  next: fn(Client) -> wisp.Response,
) -> wisp.Response {
  case
    authenticate_client_with_limits(
      oidc_ctx,
      client_id,
      creds,
      ip_bucket,
      require_confidential,
    )
  {
    ClientAuthenticated(authed) -> next(authed)
    ClientAuthRejected(resp) -> resp
  }
}

fn authenticate_client_with_limits(
  oidc_ctx: Oidc,
  client_id: String,
  creds: ExtractedCredentials,
  ip_bucket: String,
  require_confidential: Bool,
) -> ClientAuthOutcome {
  case client.find_by_client_id(oidc_ctx.db, client_id) {
    Error(_) -> ClientAuthRejected(oauth_error(500, "server_error", None))

    Ok(None) -> ClientAuthRejected(invalid_client_response())

    Ok(Some(found)) ->
      case found.kind {
        client.SubordinateBot | client.ConfidentialApp -> {
          let ip_client_key =
            rate_policy.oidc_client_auth_key(ip_bucket, found.client_id)
          case
            rate_limit.check(
              oidc_ctx.rate_limiter,
              ip_client_key,
              client_auth_fail_policy,
            )
          {
            rate_limit.Limited(retry_after_seconds:) ->
              ClientAuthRejected(rate_limited_response(retry_after_seconds))

            rate_limit.Allowed(_) ->
              case creds.client_secret {
                None -> ClientAuthRejected(invalid_client_response())

                Some(raw_secret) ->
                  case client.is_valid_secret_format(raw_secret) {
                    False -> ClientAuthRejected(invalid_client_response())

                    True ->
                      case
                        client.authenticate_secret_for_client(
                          oidc_ctx.db,
                          found,
                          raw_secret,
                        )
                      {
                        Ok(authed) -> {
                          rate_limit.reset(oidc_ctx.rate_limiter, ip_client_key)
                          ClientAuthenticated(authed)
                        }
                        Error(client.InvalidClientCredentials) ->
                          ClientAuthRejected(invalid_client_response())
                        Error(_) ->
                          ClientAuthRejected(oauth_error(
                            500,
                            "server_error",
                            None,
                          ))
                      }
                  }
              }
          }
        }

        client.PublicApp | client.Cimd ->
          case require_confidential, creds.client_secret, creds.used_basic {
            True, _, _ | _, Some(_), _ | _, _, True ->
              ClientAuthRejected(invalid_client_response())
            False, None, False -> ClientAuthenticated(found)
          }
      }
  }
}

fn rate_limited_response(retry_after_seconds: Int) -> wisp.Response {
  oauth_error(429, "temporarily_unavailable", Some("Too many requests"))
  |> response.set_header("retry-after", int.to_string(retry_after_seconds))
}

fn require_oauth_form(
  req: wisp.Request,
  next: fn(List(#(String, String))) -> wisp.Response,
) -> wisp.Response {
  case has_form_urlencoded_content_type(req) {
    False -> oauth_error(400, "invalid_request", None)
    True ->
      case wisp.read_body_bits(req) {
        Error(_) -> oauth_error(400, "invalid_request", None)
        Ok(bits) ->
          case bit_array.byte_size(bits) > max_oauth_form_bytes {
            True -> oauth_error(400, "invalid_request", None)
            False ->
              case bit_array.to_string(bits) {
                Error(_) -> oauth_error(400, "invalid_request", None)
                Ok(body_str) ->
                  case uri.parse_query(body_str) {
                    Error(_) -> oauth_error(400, "invalid_request", None)
                    Ok(values) ->
                      case has_duplicate_keys(values) {
                        True -> oauth_error(400, "invalid_request", None)
                        False -> next(values)
                      }
                  }
              }
          }
      }
  }
}

fn has_form_urlencoded_content_type(req: wisp.Request) -> Bool {
  case request.get_header(req, "content-type") {
    Error(_) -> False
    Ok(raw) -> {
      let media_type = case string.split_once(raw, ";") {
        Ok(#(base, _)) -> base
        Error(_) -> raw
      }
      string.lowercase(string.trim(media_type))
      == "application/x-www-form-urlencoded"
    }
  }
}

fn has_duplicate_keys(pairs: List(#(String, String))) -> Bool {
  let keys = list.map(pairs, fn(pair) { pair.0 })
  list.length(keys) != list.length(list.unique(keys))
}

fn require_extracted_credentials(
  req: wisp.Request,
  form_values: List(#(String, String)),
  next: fn(ExtractedCredentials) -> wisp.Response,
) -> wisp.Response {
  case extract_credentials(req, form_values) {
    Ok(creds) -> next(creds)
    Error(MalformedBasicHeader) -> invalid_client_response()
    Error(InvalidCredentialRequest) -> oauth_error(400, "invalid_request", None)
  }
}

fn extract_credentials(
  req: wisp.Request,
  form_values: List(#(String, String)),
) -> Result(ExtractedCredentials, CredentialExtractError) {
  let form_client_id =
    list.key_find(form_values, "client_id") |> option.from_result
  let form_client_secret =
    list.key_find(form_values, "client_secret") |> option.from_result

  let auth_headers =
    list.filter_map(req.headers, fn(header) {
      case string.lowercase(header.0) == "authorization" {
        True -> Ok(header.1)
        False -> Error(Nil)
      }
    })

  case auth_headers {
    [] ->
      Ok(ExtractedCredentials(
        client_id: form_client_id,
        client_secret: form_client_secret,
        used_basic: False,
      ))

    [raw_auth] -> {
      let trimmed = string.trim(raw_auth)
      case string.split_once(trimmed, " ") {
        Ok(#(scheme, rest)) ->
          case string.lowercase(scheme) == "basic" {
            False -> Error(InvalidCredentialRequest)
            True ->
              case form_client_secret {
                Some(_) -> Error(InvalidCredentialRequest)
                None -> {
                  use #(basic_id, basic_secret) <- result.try(
                    decode_basic_credentials(string.trim(rest)),
                  )
                  case form_client_id {
                    Some(fcid) if fcid != basic_id ->
                      Error(InvalidCredentialRequest)
                    _ ->
                      Ok(ExtractedCredentials(
                        client_id: Some(basic_id),
                        client_secret: Some(basic_secret),
                        used_basic: True,
                      ))
                  }
                }
              }
          }

        Error(_) ->
          case string.lowercase(trimmed) == "basic" {
            True ->
              case form_client_secret {
                Some(_) -> Error(InvalidCredentialRequest)
                None -> Error(MalformedBasicHeader)
              }
            False -> Error(InvalidCredentialRequest)
          }
      }
    }

    _ -> Error(InvalidCredentialRequest)
  }
}

fn decode_basic_credentials(
  encoded: String,
) -> Result(#(String, String), CredentialExtractError) {
  use _ <- result.try(case encoded != "" {
    True -> Ok(Nil)
    False -> Error(MalformedBasicHeader)
  })
  use decoded_bits <- result.try(
    bit_array.base64_decode(encoded)
    |> result.replace_error(MalformedBasicHeader),
  )
  use decoded_str <- result.try(
    bit_array.to_string(decoded_bits)
    |> result.replace_error(MalformedBasicHeader),
  )
  use #(raw_id, raw_secret) <- result.try(
    string.split_once(decoded_str, ":")
    |> result.replace_error(MalformedBasicHeader),
  )
  use client_id <- result.try(
    strict_percent_decode(raw_id)
    |> result.replace_error(MalformedBasicHeader),
  )
  use client_secret <- result.try(
    strict_percent_decode(raw_secret)
    |> result.replace_error(MalformedBasicHeader),
  )

  case client_id != "" {
    True -> Ok(#(client_id, client_secret))
    False -> Error(MalformedBasicHeader)
  }
}

fn strict_percent_decode(raw: String) -> Result(String, Nil) {
  case has_valid_percent_escapes(raw) {
    False -> Error(Nil)
    True -> uri.percent_decode(raw)
  }
}

fn has_valid_percent_escapes(raw: String) -> Bool {
  case string.split(raw, "%") {
    [] | [_] -> True
    [_first, ..rest] ->
      list.all(rest, fn(part) {
        case string.to_utf_codepoints(part) {
          [c1, c2, ..] -> is_hex_codepoint(c1) && is_hex_codepoint(c2)
          _ -> False
        }
      })
  }
}

fn is_hex_codepoint(cp: UtfCodepoint) -> Bool {
  case string.utf_codepoint_to_int(cp) {
    n if n >= 0x30 && n <= 0x39 -> True
    n if n >= 0x41 && n <= 0x46 -> True
    n if n >= 0x61 && n <= 0x66 -> True
    _ -> False
  }
}

fn parse_optional_scopes(
  form_values: List(#(String, String)),
) -> Result(Option(Set(Scope)), token.TokenError) {
  case list.key_find(form_values, "scope") {
    Error(_) -> Ok(None)
    Ok(raw) ->
      case string.trim(raw) {
        "" -> Ok(None)
        trimmed ->
          case scope.parse_space_delimited(trimmed) {
            Ok(scopes) -> Ok(Some(scopes))
            Error(_) -> Error(token.InvalidScope)
          }
      }
  }
}

fn require_non_empty_param(
  form_values: List(#(String, String)),
  key: String,
) -> Result(String, token.TokenError) {
  case list.key_find(form_values, key) {
    Ok(val) if val != "" -> Ok(val)
    _ -> Error(token.InvalidRequest("Missing parameter: " <> key))
  }
}

fn optional_non_empty_param(
  form_values: List(#(String, String)),
  key: String,
) -> Option(String) {
  case list.key_find(form_values, key) {
    Ok(val) if val != "" -> Some(val)
    _ -> None
  }
}

fn token_success_response(issued: token.IssuedTokens) -> wisp.Response {
  let base_fields = [
    #("access_token", json.string(issued.access_token)),
    #("token_type", json.string(issued.token_type)),
    #("expires_in", json.int(issued.expires_in)),
    #("scope", json.string(scope.format_space_delimited(issued.scopes))),
  ]
  let fields = case issued.refresh_token {
    Some(rt) -> list.append(base_fields, [#("refresh_token", json.string(rt))])
    None -> base_fields
  }

  json.object(fields)
  |> json.to_string
  |> wisp.json_response(200)
}

fn token_error_response(err: token.TokenError) -> wisp.Response {
  case err {
    token.InvalidClient -> invalid_client_response()
    token.InvalidRequest(desc) ->
      case desc {
        "" -> oauth_error(400, "invalid_request", None)
        _ -> oauth_error(400, "invalid_request", Some(desc))
      }
    token.InvalidGrant -> oauth_error(400, "invalid_grant", None)
    token.UnauthorizedClient -> oauth_error(400, "unauthorized_client", None)
    token.UnsupportedGrantType ->
      oauth_error(400, "unsupported_grant_type", None)
    token.InvalidScope -> oauth_error(400, "invalid_scope", None)
    token.InvalidTarget -> oauth_error(400, "invalid_target", None)
    token.InternalError -> oauth_error(500, "server_error", None)
  }
}

fn invalid_client_response() -> wisp.Response {
  oauth_error(401, "invalid_client", None)
  |> response.set_header("www-authenticate", basic_www_authenticate)
}

fn oauth_error(
  status: Int,
  code: String,
  description: Option(String),
) -> wisp.Response {
  let fields = case description {
    None -> [#("error", json.string(code))]
    Some(desc) -> [
      #("error", json.string(code)),
      #("error_description", json.string(desc)),
    ]
  }

  json.object(fields)
  |> json.to_string
  |> wisp.json_response(status)
}

fn with_no_store_headers(resp: wisp.Response) -> wisp.Response {
  resp
  |> response.set_header("cache-control", "no-store")
  |> response.set_header("pragma", "no-cache")
}
