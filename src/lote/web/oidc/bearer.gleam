import gleam/http/response
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{Some}
import gleam/string
import lote/oidc.{type Oidc, type Principal}
import lote/oidc/scope.{type Scope}
import lote/oidc/token
import lote/rate_limit.{type Limiter}
import lote/web/http_rate_limit
import wisp

pub const client_read_policy =
  rate_limit.Policy(limit: 120, window_ms: 60_000, burst: 60)

pub const user_read_policy =
  rate_limit.Policy(limit: 300, window_ms: 60_000, burst: 100)

pub const client_write_policy =
  rate_limit.Policy(limit: 20, window_ms: 60_000, burst: 5)

const bearer_realm = "Bearer realm=\"lote\""

const bearer_invalid_token = "Bearer realm=\"lote\", error=\"invalid_token\""

pub fn authenticate(
  req: wisp.Request,
  oidc_ctx: Oidc,
  next: fn(Principal) -> wisp.Response,
) -> wisp.Response {
  let auth_headers =
    list.filter_map(req.headers, fn(header) {
      case string.lowercase(header.0) == "authorization" {
        True -> Ok(header.1)
        False -> Error(Nil)
      }
    })

  case auth_headers {
    [raw_auth] -> {
      let trimmed = string.trim(raw_auth)
      case string.split_once(trimmed, " ") {
        Ok(#(scheme, rest)) ->
          case string.lowercase(scheme) == "bearer" {
            False -> unauthorized_response()
            True -> {
              let raw_token = string.trim(rest)
              case raw_token {
                "" -> unauthorized_response()
                _ ->
                  case
                    token.authenticate_access_token(
                      oidc_ctx.db,
                      raw_token,
                      Some(oidc_ctx.issuer),
                    )
                  {
                    Ok(principal) -> next(principal)
                    Error(_) -> invalid_token_response()
                  }
              }
            }
          }
        Error(_) -> unauthorized_response()
      }
    }

    _ -> unauthorized_response()
  }
}

pub fn require_scope(
  principal: Principal,
  required: Scope,
  next: fn() -> wisp.Response,
) -> wisp.Response {
  case oidc.has_scope(principal, required) {
    True -> next()
    False -> {
      let scope_str = scope.to_string(required)
      let www_auth =
        "Bearer realm=\"lote\", error=\"insufficient_scope\", scope=\""
        <> scope_str
        <> "\""

      json.object([
        #("error", json.string("insufficient_scope")),
        #("scope", json.string(scope_str)),
      ])
      |> json.to_string
      |> wisp.json_response(403)
      |> response.set_header("www-authenticate", www_auth)
    }
  }
}

pub fn require_read_rate_limit(
  limiter: Limiter,
  principal: Principal,
  next: fn() -> wisp.Response,
) -> wisp.Response {
  case
    rate_limit.check(
      limiter,
      "api:read:client:" <> principal.client_id,
      client_read_policy,
    )
  {
    rate_limit.Limited(retry_after_seconds:) ->
      too_many_requests(retry_after_seconds)
    rate_limit.Allowed(_) ->
      case
        rate_limit.check(
          limiter,
          "api:read:user:" <> int.to_string(principal.user.id),
          user_read_policy,
        )
      {
        rate_limit.Limited(retry_after_seconds:) ->
          too_many_requests(retry_after_seconds)
        rate_limit.Allowed(_) -> next()
      }
  }
}

pub fn require_write_rate_limit(
  limiter: Limiter,
  principal: Principal,
  next: fn() -> wisp.Response,
) -> wisp.Response {
  case
    rate_limit.check(
      limiter,
      "api:write:client:" <> principal.client_id,
      client_write_policy,
    )
  {
    rate_limit.Limited(retry_after_seconds:) ->
      too_many_requests(retry_after_seconds)
    rate_limit.Allowed(_) ->
      case
        rate_limit.check(
          limiter,
          "http:write:user:" <> int.to_string(principal.user.id),
          http_rate_limit.write_policy,
        )
      {
        rate_limit.Limited(retry_after_seconds:) ->
          too_many_requests(retry_after_seconds)
        rate_limit.Allowed(_) -> next()
      }
  }
}

pub fn too_many_requests(retry_after_seconds: Int) -> wisp.Response {
  json.object([
    #("error", json.string("too_many_requests")),
    #("retry_after", json.int(retry_after_seconds)),
  ])
  |> json.to_string
  |> wisp.json_response(429)
  |> response.set_header("retry-after", int.to_string(retry_after_seconds))
}

fn unauthorized_response() -> wisp.Response {
  json.object([#("error", json.string("unauthorized"))])
  |> json.to_string
  |> wisp.json_response(401)
  |> response.set_header("www-authenticate", bearer_realm)
}

fn invalid_token_response() -> wisp.Response {
  json.object([#("error", json.string("invalid_token"))])
  |> json.to_string
  |> wisp.json_response(401)
  |> response.set_header("www-authenticate", bearer_invalid_token)
}
