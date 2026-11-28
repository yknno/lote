import gleam/http/response
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{Some}
import gleam/string
import lote/oidc.{type Oidc, type Principal}
import lote/oidc/scope.{type Scope}
import lote/oidc/token
import lote/rate_limit.{type Limiter, type Policy}
import lote/web/oidc/discovery_handler
import lote/web/rate_policy
import wisp

pub const client_read_policy = rate_policy.api_read_client_policy

pub const user_read_policy = rate_policy.api_read_user_policy

pub const client_write_policy = rate_policy.api_write_client_policy

pub const user_write_policy = rate_policy.http_write_user_policy

pub const client_post_create_policy = rate_policy.post_create_client_policy

pub const user_post_create_policy = rate_policy.post_create_user_policy

/// Rate-limit tier enforced automatically by `authorize` for every `/api/*`
/// endpoint after Bearer token verification and scope check.
pub type ApiTier {
  Read
  Write
  PostCreate
}

/// Unified Bearer API entrypoint: authenticates the `Authorization: Bearer`
/// token, verifies `required_scope`, enforces the two-tier (`client_id` then
/// `user_id`) rate-limit policy for `tier`, and attaches `ratelimit-limit` and
/// `ratelimit-remaining` headers to the response.
pub fn authorize(
  req: wisp.Request,
  oidc_ctx: Oidc,
  required_scope: Scope,
  tier: ApiTier,
  next: fn(Principal) -> wisp.Response,
) -> wisp.Response {
  use principal <- authenticate(req, oidc_ctx)
  use <- require_scope_for_issuer(principal, required_scope, oidc_ctx.issuer)
  enforce_tier_rate_limit(oidc_ctx.rate_limiter, principal, tier, fn() {
    next(principal)
  })
}

pub fn authenticate(
  req: wisp.Request,
  oidc_ctx: Oidc,
  next: fn(Principal) -> wisp.Response,
) -> wisp.Response {
  let issuer = oidc_ctx.issuer
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
            False -> unauthorized_response(issuer)
            True -> {
              let raw_token = string.trim(rest)
              case raw_token {
                "" -> unauthorized_response(issuer)
                _ ->
                  case token.is_valid_token_format("lote_at_", raw_token) {
                    False -> invalid_token_response(issuer)
                    True ->
                      case
                        token.authenticate_access_token(
                          oidc_ctx.db,
                          raw_token,
                          Some(issuer),
                        )
                      {
                        Ok(principal) -> next(principal)
                        Error(_) -> invalid_token_response(issuer)
                      }
                  }
              }
            }
          }
        Error(_) -> unauthorized_response(issuer)
      }
    }

    _ -> unauthorized_response(issuer)
  }
}

pub fn require_scope(
  principal: Principal,
  required: Scope,
  next: fn() -> wisp.Response,
) -> wisp.Response {
  require_scope_for_issuer(principal, required, principal.audience, next)
}

fn require_scope_for_issuer(
  principal: Principal,
  required: Scope,
  issuer: String,
  next: fn() -> wisp.Response,
) -> wisp.Response {
  case oidc.has_scope(principal, required) {
    True -> next()
    False -> {
      let scope_str = scope.to_string(required)
      let meta_url = discovery_handler.resource_metadata_url(issuer)
      let www_auth =
        "Bearer realm=\"lote\", error=\"insufficient_scope\", scope=\""
        <> scope_str
        <> "\", resource_metadata=\""
        <> meta_url
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

fn enforce_tier_rate_limit(
  limiter: Limiter,
  principal: Principal,
  tier: ApiTier,
  next: fn() -> wisp.Response,
) -> wisp.Response {
  let #(client_key, client_policy, user_key, user_policy) =
    tier_specs(principal, tier)
  let effective_limit = int.min(client_policy.limit, user_policy.limit)

  case rate_limit.check(limiter, client_key, client_policy) {
    rate_limit.Limited(retry_after_seconds:) ->
      too_many_requests_with_limit(effective_limit, retry_after_seconds)

    rate_limit.Allowed(remaining: client_remaining) ->
      case rate_limit.check(limiter, user_key, user_policy) {
        rate_limit.Limited(retry_after_seconds:) ->
          too_many_requests_with_limit(effective_limit, retry_after_seconds)

        rate_limit.Allowed(remaining: user_remaining) ->
          next()
          |> with_ratelimit_headers(
            effective_limit,
            int.min(client_remaining, user_remaining),
          )
      }
  }
}

fn tier_specs(
  principal: Principal,
  tier: ApiTier,
) -> #(String, Policy, String, Policy) {
  case tier {
    Read -> #(
      rate_policy.api_read_client_key(principal.client_id),
      client_read_policy,
      rate_policy.api_read_user_key(principal.user.id),
      user_read_policy,
    )
    Write -> #(
      rate_policy.api_write_client_key(principal.client_id),
      client_write_policy,
      rate_policy.http_write_user_key(principal.user.id),
      user_write_policy,
    )
    PostCreate -> #(
      rate_policy.post_create_client_key(principal.client_id),
      client_post_create_policy,
      rate_policy.post_create_user_key(principal.user.id),
      user_post_create_policy,
    )
  }
}

pub fn with_ratelimit_headers(
  resp: wisp.Response,
  limit: Int,
  remaining: Int,
) -> wisp.Response {
  resp
  |> response.set_header("ratelimit-limit", int.to_string(limit))
  |> response.set_header("ratelimit-remaining", int.to_string(remaining))
}

pub fn too_many_requests_with_limit(
  limit: Int,
  retry_after_seconds: Int,
) -> wisp.Response {
  too_many_requests(retry_after_seconds)
  |> with_ratelimit_headers(limit, 0)
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

fn unauthorized_response(issuer: String) -> wisp.Response {
  let meta_url = discovery_handler.resource_metadata_url(issuer)
  json.object([#("error", json.string("unauthorized"))])
  |> json.to_string
  |> wisp.json_response(401)
  |> response.set_header(
    "www-authenticate",
    "Bearer realm=\"lote\", resource_metadata=\"" <> meta_url <> "\"",
  )
}

fn invalid_token_response(issuer: String) -> wisp.Response {
  let meta_url = discovery_handler.resource_metadata_url(issuer)
  json.object([#("error", json.string("invalid_token"))])
  |> json.to_string
  |> wisp.json_response(401)
  |> response.set_header(
    "www-authenticate",
    "Bearer realm=\"lote\", error=\"invalid_token\", resource_metadata=\""
      <> meta_url
      <> "\"",
  )
}
