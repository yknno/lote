import gleam/bit_array
import gleam/http
import gleam/http/request
import gleam/http/response
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/set.{type Set}
import gleam/string
import gleam/uri
import lote/auth.{type Auth}
import lote/auth/session
import lote/auth/user.{type AuthUser}
import lote/oidc.{type Oidc}
import lote/oidc/cimd
import lote/oidc/client.{type Client}
import lote/oidc/grant
import lote/oidc/scope.{type Scope}
import lote/oidc/token
import lote/rate_limit
import lote/web/auth/return_to
import lote/web/client_ip
import lote/web/csrf
import lote/web/http_rate_limit
import lote/web/oidc/authorize_view.{ConsentParams}
import lote/web/rate_policy
import wisp

const authorize_csp =
  "default-src 'self'; script-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"

type PreRedirectValidated {
  PreRedirectValidated(
    client: Client,
    redirect_uri: String,
    state: Option(String),
  )
}

type PostRedirectValidated {
  PostRedirectValidated(
    requested_scopes: Set(Scope),
    code_challenge: String,
    code_challenge_method: String,
    audience: String,
    resource: Option(String),
    nonce: Option(String),
  )
}

type PromptMode {
  PromptDefault
  PromptConsent
  PromptNone
}

pub fn handle_request(
  req: wisp.Request,
  auth_ctx: Auth,
  oidc_ctx: Oidc,
) -> wisp.Response {
  handle_request_with_ip(req, auth_ctx, oidc_ctx, "127.0.0.1")
}

pub fn handle_request_with_ip(
  req: wisp.Request,
  auth_ctx: Auth,
  oidc_ctx: Oidc,
  client_ip: String,
) -> wisp.Response {
  let is_head = request.get_header(req, "x-original-method") == Ok("HEAD")
  let resp = case req.method, is_head {
    _, True -> wisp.method_not_allowed([http.Get, http.Post])
    http.Get, False -> handle_get(req, auth_ctx, oidc_ctx, client_ip)
    http.Post, False -> handle_post(req, auth_ctx, oidc_ctx, client_ip)
    _, False -> wisp.method_not_allowed([http.Get, http.Post])
  }

  with_security_headers(resp)
}

pub fn build_redirect_url(
  base_redirect_uri: String,
  extra_params: List(#(String, String)),
) -> String {
  let base = case string.split_once(base_redirect_uri, "#") {
    Ok(#(before_hash, _)) -> before_hash
    Error(_) -> base_redirect_uri
  }
  let encoded_extra = uri.query_to_string(extra_params)
  case encoded_extra {
    "" -> base
    _ ->
      case uri.parse(base) {
        Ok(parsed) ->
          case parsed.query {
            None -> base <> "?" <> encoded_extra
            Some("") -> base <> encoded_extra
            Some(_) ->
              case string.ends_with(base, "&") {
                True -> base <> encoded_extra
                False -> base <> "&" <> encoded_extra
              }
          }
        Error(_) ->
          case string.contains(base, "?") {
            True -> base <> "&" <> encoded_extra
            False -> base <> "?" <> encoded_extra
          }
      }
  }
}

pub fn build_error_redirect(
  redirect_uri: String,
  error: String,
  error_description: Option(String),
  state: Option(String),
  issuer: String,
) -> String {
  let params =
    [#("error", error)]
    |> append_optional_param("error_description", error_description)
    |> list.append([#("iss", issuer)])
    |> append_optional_param("state", state)

  build_redirect_url(redirect_uri, params)
}

fn build_success_redirect(
  redirect_uri: String,
  code: String,
  state: Option(String),
  issuer: String,
) -> String {
  let params =
    [#("code", code), #("iss", issuer)]
    |> append_optional_param("state", state)

  build_redirect_url(redirect_uri, params)
}

fn append_optional_param(
  params: List(#(String, String)),
  key: String,
  value: Option(String),
) -> List(#(String, String)) {
  case value {
    Some(v) if v != "" -> list.append(params, [#(key, v)])
    _ -> params
  }
}

fn handle_get(
  req: wisp.Request,
  auth_ctx: Auth,
  oidc_ctx: Oidc,
  client_ip: String,
) -> wisp.Response {
  case parse_get_query(req) {
    Error(resp) -> resp
    Ok(params) ->
      case validate_pre_redirect(oidc_ctx, params, client_ip) {
        Error(resp) -> resp
        Ok(pre) ->
          case validate_oauth_params(oidc_ctx, pre, params) {
            Error(resp) -> resp
            Ok(validated) -> {
              case parse_prompt_mode(list.key_find(params, "prompt")) {
                Error(err_code) ->
                  wisp.redirect(to: build_error_redirect(
                    pre.redirect_uri,
                    err_code,
                    None,
                    pre.state,
                    oidc_ctx.issuer,
                  ))

                Ok(prompt_mode) ->
                  case
                    session.current_session(
                      req,
                      auth_ctx.db,
                      auth_ctx.secret_key_base,
                    )
                  {
                    None ->
                      case prompt_mode {
                        PromptNone ->
                          wisp.redirect(to: build_error_redirect(
                            pre.redirect_uri,
                            "login_required",
                            None,
                            pre.state,
                            oidc_ctx.issuer,
                          ))
                        PromptDefault | PromptConsent -> {
                          let target = case req.query {
                            Some(q) if q != "" -> "/oidc/authorize?" <> q
                            _ -> "/oidc/authorize"
                          }
                          wisp.redirect(to: return_to.login_redirect_path(
                            target,
                          ))
                        }
                      }

                    Some(active) ->
                      handle_authenticated_get(
                        req,
                        auth_ctx,
                        oidc_ctx,
                        active.user,
                        pre,
                        validated,
                        prompt_mode,
                      )
                  }
              }
            }
          }
      }
  }
}

fn handle_authenticated_get(
  req: wisp.Request,
  auth_ctx: Auth,
  oidc_ctx: Oidc,
  auth_user: AuthUser,
  pre: PreRedirectValidated,
  validated: PostRedirectValidated,
  prompt_mode: PromptMode,
) -> wisp.Response {
  case validate_client_visibility(oidc_ctx, pre, auth_user.id) {
    Error(resp) -> resp
    Ok(Nil) ->
      case
        grant.find_consent_for_audience(
          oidc_ctx.db,
          auth_user.id,
          pre.client.id,
          validated.audience,
          oidc_ctx.issuer,
        )
      {
        Error(_) -> wisp.internal_server_error()
        Ok(found) -> {
          let existing_scopes = case found {
            Some(#(_, _, s)) -> set.intersection(s, pre.client.allowed_scopes)
            None -> set.new()
          }
          case found, prompt_mode {
            Some(#(consent_id, _, _)), PromptDefault
            | Some(#(consent_id, _, _)), PromptNone
            ->
              case
                scope.is_subset(validated.requested_scopes, existing_scopes)
              {
                True -> {
                  use <- http_rate_limit.require_user_write(
                    auth_ctx.rate_limiter,
                    auth_user.id,
                  )
                  issue_code_and_redirect(
                    req,
                    oidc_ctx,
                    consent_id,
                    pre,
                    validated,
                  )
                }
                False ->
                  case prompt_mode {
                    PromptNone ->
                      wisp.redirect(to: build_error_redirect(
                        pre.redirect_uri,
                        "consent_required",
                        None,
                        pre.state,
                        oidc_ctx.issuer,
                      ))
                    PromptDefault | PromptConsent ->
                      render_consent(
                        req,
                        auth_ctx,
                        oidc_ctx,
                        auth_user,
                        pre,
                        validated,
                        existing_scopes,
                      )
                  }
              }

            None, PromptNone ->
              wisp.redirect(to: build_error_redirect(
                pre.redirect_uri,
                "consent_required",
                None,
                pre.state,
                oidc_ctx.issuer,
              ))

            _, PromptConsent | None, PromptDefault ->
              render_consent(
                req,
                auth_ctx,
                oidc_ctx,
                auth_user,
                pre,
                validated,
                existing_scopes,
              )
          }
        }
      }
  }
}

fn handle_post(
  req: wisp.Request,
  auth_ctx: Auth,
  oidc_ctx: Oidc,
  client_ip: String,
) -> wisp.Response {
  use form <- wisp.require_form(req)
  use _csrf <- csrf.require_form_token(
    req,
    form.values,
    auth_ctx.secret_key_base,
  )

  case session.current_session(req, auth_ctx.db, auth_ctx.secret_key_base) {
    None -> wisp.response(401)
    Some(active) ->
      case validate_pre_redirect(oidc_ctx, form.values, client_ip) {
        Error(resp) -> resp
        Ok(pre) ->
          case validate_client_visibility(oidc_ctx, pre, active.user.id) {
            Error(resp) -> resp
            Ok(Nil) ->
              case validate_oauth_params(oidc_ctx, pre, form.values) {
                Error(resp) -> resp
                Ok(validated) ->
                  case list.key_find(form.values, "decision") {
                    Ok("deny") ->
                      wisp.redirect(to: build_error_redirect(
                        pre.redirect_uri,
                        "access_denied",
                        None,
                        pre.state,
                        oidc_ctx.issuer,
                      ))

                    Ok("approve") -> {
                      use <- http_rate_limit.require_user_write(
                        auth_ctx.rate_limiter,
                        active.user.id,
                      )
                      let consent_res = case
                        validated.audience == oidc_ctx.issuer
                      {
                        True ->
                          grant.upsert_consent(
                            oidc_ctx.db,
                            active.user.id,
                            pre.client.id,
                            validated.requested_scopes,
                          )
                          |> result.map(fn(r) { r.0 })
                        False ->
                          grant.ensure_consent_row(
                            oidc_ctx.db,
                            active.user.id,
                            pre.client.id,
                          )
                          |> result.map(fn(r) { r.0 })
                      }
                      case consent_res {
                        Error(_) -> wisp.internal_server_error()
                        Ok(consent_id) ->
                          issue_code_and_redirect(
                            req,
                            oidc_ctx,
                            consent_id,
                            pre,
                            validated,
                          )
                      }
                    }

                    _ ->
                      wisp.redirect(to: build_error_redirect(
                        pre.redirect_uri,
                        "invalid_request",
                        None,
                        pre.state,
                        oidc_ctx.issuer,
                      ))
                  }
              }
          }
      }
  }
}

fn issue_code_and_redirect(
  req: wisp.Request,
  oidc_ctx: Oidc,
  consent_id: Int,
  pre: PreRedirectValidated,
  validated: PostRedirectValidated,
) -> wisp.Response {
  let user_agent = request.get_header(req, "user-agent") |> result.unwrap("")
  case
    token.issue_authorization_code(
      oidc_ctx.db,
      consent_id,
      validated.requested_scopes,
      validated.audience,
      pre.redirect_uri,
      validated.code_challenge,
      validated.nonce,
      user_agent,
    )
  {
    Ok(#(raw_code, _grant_public_id)) ->
      wisp.redirect(to: build_success_redirect(
        pre.redirect_uri,
        raw_code,
        pre.state,
        oidc_ctx.issuer,
      ))
    Error(_) -> wisp.internal_server_error()
  }
}

fn render_consent(
  req: wisp.Request,
  auth_ctx: Auth,
  oidc_ctx: Oidc,
  auth_user: AuthUser,
  pre: PreRedirectValidated,
  validated: PostRedirectValidated,
  existing_scopes: Set(Scope),
) -> wisp.Response {
  let #(csrf_token, should_set_cookie) =
    csrf.ensure_token(req, auth_ctx.secret_key_base)

  authorize_view.consent_page(ConsentParams(
    current_user: auth_user,
    client: pre.client,
    redirect_uri: pre.redirect_uri,
    requested_scopes: validated.requested_scopes,
    existing_scopes:,
    audience: validated.audience,
    default_issuer: oidc_ctx.issuer,
    code_challenge: validated.code_challenge,
    code_challenge_method: validated.code_challenge_method,
    state: pre.state,
    resource: validated.resource,
    nonce: validated.nonce,
    csrf_token:,
  ))
  |> csrf.attach_cookie(
    req,
    csrf_token,
    auth_ctx.secret_key_base,
    should_set_cookie,
  )
}

fn parse_get_query(
  req: wisp.Request,
) -> Result(List(#(String, String)), wisp.Response) {
  case req.query {
    None | Some("") -> Ok([])
    Some(raw) ->
      case uri.parse_query(raw) {
        Ok(params) -> Ok(params)
        Error(_) ->
          Error(authorize_view.error_page(
            "Invalid Authorization Request",
            "Malformed query parameters",
            400,
          ))
      }
  }
}

fn validate_pre_redirect(
  oidc_ctx: Oidc,
  params: List(#(String, String)),
  client_ip: String,
) -> Result(PreRedirectValidated, wisp.Response) {
  use _ <- result.try(case has_duplicate_keys(params, set.new()) {
    True ->
      Error(authorize_view.error_page(
        "Invalid Authorization Request",
        "Duplicate parameter",
        400,
      ))
    False -> Ok(Nil)
  })

  use client_id <- result.try(case list.key_find(params, "client_id") {
    Ok(cid) if cid != "" -> Ok(cid)
    _ ->
      Error(authorize_view.error_page(
        "Invalid Authorization Request",
        "Invalid client",
        400,
      ))
  })

  use found_client <- result.try(resolve_authorize_client(
    oidc_ctx,
    client_id,
    client_ip,
  ))

  use redirect_uri <- result.try(case list.key_find(params, "redirect_uri") {
    Ok(uri_str) if uri_str != "" ->
      case client.matches_redirect_uri(found_client, uri_str) {
        True -> Ok(uri_str)
        False ->
          Error(authorize_view.error_page(
            "Invalid Authorization Request",
            "Invalid redirect_uri",
            400,
          ))
      }
    _ ->
      Error(authorize_view.error_page(
        "Invalid Authorization Request",
        "Invalid redirect_uri",
        400,
      ))
  })

  use state <- result.map(validate_state(params))
  PreRedirectValidated(client: found_client, redirect_uri:, state:)
}

fn resolve_authorize_client(
  oidc_ctx: Oidc,
  client_id: String,
  client_ip: String,
) -> Result(Client, wisp.Response) {
  case cimd.is_cimd_client_id(client_id) {
    True -> {
      let ip_bucket = client_ip.rate_limit_bucket(client_ip)
      let on_network_fetch = fn() {
        case
          rate_limit.check(
            oidc_ctx.rate_limiter,
            rate_policy.cimd_fetch_ip_key(ip_bucket),
            rate_policy.cimd_fetch_ip_policy,
          )
        {
          rate_limit.Allowed(_) -> Ok(Nil)
          rate_limit.Limited(retry_after_seconds:) ->
            Error(
              authorize_view.error_page(
                "Too Many Requests",
                "Too many client metadata lookups. Please try again shortly.",
                429,
              )
              |> response.set_header(
                "retry-after",
                int.to_string(retry_after_seconds),
              ),
            )
        }
      }

      case
        cimd.resolve_client(
          oidc_ctx.db,
          oidc_ctx.cimd_fetcher,
          client_id,
          on_network_fetch,
        )
      {
        Error(rate_limit_resp) -> Error(rate_limit_resp)
        Ok(Ok(resolved_client)) -> Ok(resolved_client)
        Ok(Error(cimd.DatabaseError)) -> Error(wisp.internal_server_error())
        Ok(Error(_)) ->
          Error(authorize_view.error_page(
            "Invalid Authorization Request",
            "Unable to verify client metadata document",
            400,
          ))
      }
    }

    False ->
      case client.find_by_client_id(oidc_ctx.db, client_id) {
        Error(_) -> Error(wisp.internal_server_error())
        Ok(None) ->
          Error(authorize_view.error_page(
            "Invalid Authorization Request",
            "Invalid client",
            400,
          ))
        Ok(Some(c)) ->
          case c.kind {
            client.ConfidentialApp | client.PublicApp -> Ok(c)
            client.SubordinateBot | client.Cimd ->
              Error(authorize_view.error_page(
                "Invalid Authorization Request",
                "This client does not support interactive authorization",
                400,
              ))
          }
      }
  }
}

fn validate_state(
  params: List(#(String, String)),
) -> Result(Option(String), wisp.Response) {
  case list.key_find(params, "state") {
    Error(_) | Ok("") -> Ok(None)
    Ok(raw) ->
      case bit_array.byte_size(<<raw:utf8>>) <= 512 && is_printable_ascii(raw) {
        True -> Ok(Some(raw))
        False ->
          Error(authorize_view.error_page(
            "Invalid Authorization Request",
            "Invalid state parameter",
            400,
          ))
      }
  }
}

fn validate_client_visibility(
  oidc_ctx: Oidc,
  pre: PreRedirectValidated,
  user_id: Int,
) -> Result(Nil, wisp.Response) {
  case
    pre.client.visibility == client.Private
    && pre.client.owner_user_id != Some(user_id)
  {
    True ->
      Error(
        wisp.redirect(to: build_error_redirect(
          pre.redirect_uri,
          "access_denied",
          None,
          pre.state,
          oidc_ctx.issuer,
        )),
      )
    False -> Ok(Nil)
  }
}

fn validate_oauth_params(
  oidc_ctx: Oidc,
  pre: PreRedirectValidated,
  params: List(#(String, String)),
) -> Result(PostRedirectValidated, wisp.Response) {
  let err_redirect = fn(code: String) {
    wisp.redirect(to: build_error_redirect(
      pre.redirect_uri,
      code,
      None,
      pre.state,
      oidc_ctx.issuer,
    ))
  }

  use _ <- result.try(case list.key_find(params, "response_type") {
    Ok("code") -> Ok(Nil)
    Error(_) | Ok("") -> Error(err_redirect("invalid_request"))
    Ok(_) -> Error(err_redirect("unsupported_response_type"))
  })

  use _ <- result.try(case list.key_find(params, "response_mode") {
    Error(_) | Ok("query") -> Ok(Nil)
    Ok(_) -> Error(err_redirect("invalid_request"))
  })

  use _ <- result.try(case list.key_find(params, "request") {
    Error(_) -> Ok(Nil)
    Ok(_) -> Error(err_redirect("request_not_supported"))
  })

  use _ <- result.try(case list.key_find(params, "request_uri") {
    Error(_) -> Ok(Nil)
    Ok(_) -> Error(err_redirect("request_uri_not_supported"))
  })

  use _ <- result.try(case list.key_find(params, "registration") {
    Error(_) -> Ok(Nil)
    Ok(_) -> Error(err_redirect("registration_not_supported"))
  })

  use _ <- result.try(
    case list.key_find(params, "claims"), list.key_find(params, "max_age") {
      Error(_), Error(_) -> Ok(Nil)
      _, _ -> Error(err_redirect("invalid_request"))
    },
  )

  use code_challenge_method <- result.try(
    case list.key_find(params, "code_challenge_method") {
      Ok("S256") -> Ok("S256")
      _ -> Error(err_redirect("invalid_request"))
    },
  )

  use code_challenge <- result.try(
    case list.key_find(params, "code_challenge") {
      Ok(cc) ->
        case is_base64url_43(cc) {
          True -> Ok(cc)
          False -> Error(err_redirect("invalid_request"))
        }
      Error(_) -> Error(err_redirect("invalid_request"))
    },
  )

  use requested_scopes <- result.try(case list.key_find(params, "scope") {
    Error(_) -> Error(err_redirect("invalid_scope"))
    Ok(raw_scope) ->
      case string.trim(raw_scope) {
        "" -> Error(err_redirect("invalid_scope"))
        trimmed ->
          case scope.parse_space_delimited(trimmed) {
            Error(_) -> Error(err_redirect("invalid_scope"))
            Ok(parsed_scopes) ->
              case
                !set.is_empty(parsed_scopes)
                && scope.is_subset(parsed_scopes, pre.client.allowed_scopes)
              {
                True -> Ok(parsed_scopes)
                False -> Error(err_redirect("invalid_scope"))
              }
          }
      }
  })

  let resource = optional_non_empty_param(params, "resource")
  use audience <- result.try(
    case token.normalize_audience(resource, oidc_ctx.issuer) {
      Ok(aud) -> Ok(aud)
      Error(Nil) -> Error(err_redirect("invalid_target"))
    },
  )

  use nonce <- result.map(case list.key_find(params, "nonce") {
    Error(_) | Ok("") -> Ok(None)
    Ok(raw_nonce) ->
      case
        bit_array.byte_size(<<raw_nonce:utf8>>) <= 512
        && !has_control_chars(raw_nonce)
      {
        True -> Ok(Some(raw_nonce))
        False -> Error(err_redirect("invalid_request"))
      }
  })

  PostRedirectValidated(
    requested_scopes:,
    code_challenge:,
    code_challenge_method:,
    audience:,
    resource:,
    nonce:,
  )
}

fn parse_prompt_mode(
  raw_prompt: Result(String, Nil),
) -> Result(PromptMode, String) {
  case raw_prompt {
    Error(_) -> Ok(PromptDefault)
    Ok(raw) -> {
      let tokens =
        raw
        |> string.split(" ")
        |> list.filter(fn(t) { t != "" })
      let all_known =
        list.all(tokens, fn(t) {
          t == "none" || t == "consent" || t == "login" || t == "select_account"
        })
      case tokens, all_known {
        [], _ | _, False -> Error("invalid_request")
        ["none"], True -> Ok(PromptNone)
        _, True ->
          case list.contains(tokens, "none") {
            True -> Error("invalid_request")
            False ->
              case list.contains(tokens, "select_account") {
                True -> Error("account_selection_required")
                False ->
                  case list.contains(tokens, "login") {
                    True -> Error("login_required")
                    False -> Ok(PromptConsent)
                  }
              }
          }
      }
    }
  }
}

fn has_duplicate_keys(
  params: List(#(String, String)),
  seen: Set(String),
) -> Bool {
  case params {
    [] -> False
    [#(k, _), ..rest] ->
      case set.contains(seen, k) {
        True -> True
        False -> has_duplicate_keys(rest, set.insert(seen, k))
      }
  }
}

fn optional_non_empty_param(
  params: List(#(String, String)),
  key: String,
) -> Option(String) {
  case list.key_find(params, key) {
    Ok(val) if val != "" -> Some(val)
    _ -> None
  }
}

fn is_printable_ascii(s: String) -> Bool {
  s
  |> string.to_utf_codepoints
  |> list.all(fn(cp) {
    case string.utf_codepoint_to_int(cp) {
      byte if byte >= 0x20 && byte <= 0x7E -> True
      _ -> False
    }
  })
}

fn has_control_chars(s: String) -> Bool {
  s
  |> string.to_utf_codepoints
  |> list.any(fn(cp) {
    case string.utf_codepoint_to_int(cp) {
      byte if byte <= 0x1F || byte == 0x7F -> True
      _ -> False
    }
  })
}

fn is_base64url_43(s: String) -> Bool {
  string.length(s) == 43
  && s
  |> string.to_utf_codepoints
  |> list.all(fn(cp) {
    case string.utf_codepoint_to_int(cp) {
      n if n >= 0x41 && n <= 0x5A -> True
      n if n >= 0x61 && n <= 0x7A -> True
      n if n >= 0x30 && n <= 0x39 -> True
      0x2D | 0x5F -> True
      _ -> False
    }
  })
}

fn with_security_headers(resp: wisp.Response) -> wisp.Response {
  let base =
    resp
    |> response.set_header("cache-control", "no-store")
    |> response.set_header("x-frame-options", "DENY")
    |> response.set_header("referrer-policy", "no-referrer")

  case should_set_authorize_csp(base) {
    True -> response.set_header(base, "content-security-policy", authorize_csp)
    False -> base
  }
}

fn should_set_authorize_csp(resp: wisp.Response) -> Bool {
  case response.get_header(resp, "content-type") {
    Ok("text/html" <> _) -> True
    _ -> resp.status == 400 || resp.status == 403 || resp.status == 429
  }
}
