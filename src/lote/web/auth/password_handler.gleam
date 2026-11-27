import gleam/http
import gleam/http/response
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import lote/auth.{type Auth}
import lote/auth/password
import lote/auth/session
import lote/rate_limit
import lote/realtime/pubsub
import lote/web/auth/return_to
import lote/web/auth/view
import lote/web/client_ip
import lote/web/csrf
import lote/web/rate_policy
import wisp

pub const ip_policy = rate_policy.login_ip_policy

pub const account_policy = rate_policy.login_account_policy

pub fn handle(
  req: wisp.Request,
  segments: List(String),
  auth_ctx: Auth,
  client_ip: String,
) -> wisp.Response {
  case req.method, segments {
    http.Post, ["login"] -> handle_login(req, auth_ctx, client_ip)
    _, _ -> wisp.not_found()
  }
}

fn handle_login(
  req: wisp.Request,
  auth_ctx: Auth,
  client_ip: String,
) -> wisp.Response {
  use form <- wisp.require_form(req)
  use csrf_token <- csrf.require_form_token(
    req,
    form.values,
    auth_ctx.secret_key_base,
  )

  let safe_return_to =
    list.key_find(form.values, "return_to")
    |> option.from_result
    |> return_to.sanitize
  let login_id = list.key_find(form.values, "login_id")
  let pass = list.key_find(form.values, "password")

  case login_id, pass {
    Ok(login_id), Ok(pass) -> {
      let ip_bucket = client_ip.rate_limit_bucket(client_ip)
      let ip_key = rate_policy.login_ip_key(ip_bucket)

      case password.normalize_login_id(login_id) {
        Error(_) ->
          case rate_limit.check(auth_ctx.rate_limiter, ip_key, ip_policy) {
            rate_limit.Limited(retry_after_seconds:) ->
              too_many_requests_login(
                auth_ctx,
                csrf_token,
                safe_return_to,
                retry_after_seconds,
              )
            rate_limit.Allowed(_) ->
              view.login_page_with_return_to(
                auth_ctx.methods,
                Some("ID またはパスワードが正しくありません"),
                csrf_token,
                safe_return_to,
                200,
              )
          }

        Ok(normalized_id) -> {
          let account_key =
            rate_policy.login_account_key(ip_bucket, normalized_id)

          case check_login_limits(auth_ctx.rate_limiter, ip_key, account_key) {
            rate_limit.Limited(retry_after_seconds:) ->
              too_many_requests_login(
                auth_ctx,
                csrf_token,
                safe_return_to,
                retry_after_seconds,
              )
            rate_limit.Allowed(_) ->
              case password.authenticate(auth_ctx.db, normalized_id, pass) {
                Ok(auth_user) -> {
                  rate_limit.reset(auth_ctx.rate_limiter, account_key)
                  let previous_session_id =
                    session.session_id(req, auth_ctx.secret_key_base)
                  let _ =
                    session.destroy(
                      wisp.ok(),
                      req,
                      auth_ctx.db,
                      auth_ctx.secret_key_base,
                    )
                  let destination = option.unwrap(safe_return_to, "/")
                  case
                    session.create(
                      wisp.redirect(to: destination),
                      req,
                      auth_ctx.db,
                      auth_ctx.secret_key_base,
                      auth_user,
                    )
                  {
                    Ok(resp) -> {
                      case previous_session_id {
                        Some(prev_id) ->
                          pubsub.publish(auth_ctx.session_revocations, prev_id)
                        None -> Nil
                      }
                      csrf.rotate_cookie(resp, req, auth_ctx.secret_key_base)
                    }
                    Error(_) -> wisp.internal_server_error()
                  }
                }
                Error(password.InvalidCredentials) ->
                  view.login_page_with_return_to(
                    auth_ctx.methods,
                    Some("ID またはパスワードが正しくありません"),
                    csrf_token,
                    safe_return_to,
                    200,
                  )
                Error(_) -> wisp.internal_server_error()
              }
          }
        }
      }
    }
    _, _ ->
      view.login_page_with_return_to(
        auth_ctx.methods,
        Some("入力が不足しています"),
        csrf_token,
        safe_return_to,
        200,
      )
  }
}

fn check_login_limits(
  limiter: rate_limit.Limiter,
  ip_key: String,
  account_key: String,
) -> rate_limit.Decision {
  case rate_limit.check(limiter, ip_key, ip_policy) {
    rate_limit.Limited(retry_after_seconds:) ->
      rate_limit.Limited(retry_after_seconds:)
    rate_limit.Allowed(_) ->
      rate_limit.check(limiter, account_key, account_policy)
  }
}

fn too_many_requests_login(
  auth_ctx: Auth,
  csrf_token: String,
  return_to: Option(String),
  retry_after_seconds: Int,
) -> wisp.Response {
  view.login_page_with_return_to(
    auth_ctx.methods,
    Some("ログイン試行回数が上限に達しました。しばらく待ってから再度お試しください。"),
    csrf_token,
    return_to,
    429,
  )
  |> response.set_header("retry-after", int.to_string(retry_after_seconds))
}
