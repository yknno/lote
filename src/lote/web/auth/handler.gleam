import gleam/http
import gleam/list
import gleam/option.{None, Some}
import lote/auth.{type Auth, Password}
import lote/auth/session
import lote/realtime/pubsub
import lote/web/auth/password_handler
import lote/web/auth/view
import lote/web/csrf
import wisp

pub fn handle_request(
  req: wisp.Request,
  segments: List(String),
  auth_ctx: Auth,
) -> wisp.Response {
  case req.method, segments {
    http.Get, ["login"] -> {
      let #(csrf_token, should_set_cookie) =
        csrf.ensure_token(req, auth_ctx.secret_key_base)
      view.login_page(auth_ctx.methods, None, csrf_token)
      |> csrf.attach_cookie(
        req,
        csrf_token,
        auth_ctx.secret_key_base,
        should_set_cookie,
      )
    }

    http.Post, ["logout"] -> {
      use form <- wisp.require_form(req)
      use _token <- csrf.require_form_token(
        req,
        form.values,
        auth_ctx.secret_key_base,
      )
      let revoked_id = session.session_id(req, auth_ctx.secret_key_base)
      let resp =
        wisp.redirect(to: "/")
        |> session.destroy(req, auth_ctx.db, auth_ctx.secret_key_base)
        |> csrf.rotate_cookie(req, auth_ctx.secret_key_base)
      case revoked_id {
        Some(id) -> pubsub.publish(auth_ctx.session_revocations, id)
        None -> Nil
      }
      resp
    }

    _, ["password", ..rest] ->
      case list.contains(auth_ctx.methods, Password) {
        True -> password_handler.handle(req, rest, auth_ctx)
        False -> wisp.not_found()
      }

    _, _ -> wisp.not_found()
  }
}
