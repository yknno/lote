import gleam/http
import gleam/list
import gleam/option.{None, Some}
import lote/auth.{type Auth}
import lote/auth/password
import lote/auth/session
import lote/realtime/pubsub
import lote/web/auth/view
import lote/web/csrf
import wisp

pub fn handle(
  req: wisp.Request,
  segments: List(String),
  auth_ctx: Auth,
) -> wisp.Response {
  case req.method, segments {
    http.Post, ["login"] -> handle_login(req, auth_ctx)
    _, _ -> wisp.not_found()
  }
}

fn handle_login(req: wisp.Request, auth_ctx: Auth) -> wisp.Response {
  use form <- wisp.require_form(req)
  use csrf_token <- csrf.require_form_token(
    req,
    form.values,
    auth_ctx.secret_key_base,
  )

  let login_id = list.key_find(form.values, "login_id")
  let pass = list.key_find(form.values, "password")

  case login_id, pass {
    Ok(login_id), Ok(pass) ->
      case password.authenticate(auth_ctx.db, login_id, pass) {
        Ok(auth_user) -> {
          let previous_session_id =
            session.session_id(req, auth_ctx.secret_key_base)
          let _ =
            session.destroy(
              wisp.ok(),
              req,
              auth_ctx.db,
              auth_ctx.secret_key_base,
            )
          case
            session.create(
              wisp.redirect(to: "/"),
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
          view.login_page(
            auth_ctx.methods,
            Some("ID またはパスワードが正しくありません"),
            csrf_token,
          )
        Error(_) -> wisp.internal_server_error()
      }
    _, _ -> view.login_page(auth_ctx.methods, Some("入力が不足しています"), csrf_token)
  }
}
