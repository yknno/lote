import gleam/http
import gleam/list
import gleam/option.{None}
import lote/auth.{type Auth, Password}
import lote/auth/session
import lote/web/auth/password_handler
import lote/web/auth/view
import wisp

pub fn handle_request(
  req: wisp.Request,
  segments: List(String),
  auth_ctx: Auth,
) -> wisp.Response {
  case req.method, segments {
    http.Get, ["login"] -> view.login_page(auth_ctx.methods, None)

    http.Post, ["logout"] ->
      wisp.redirect(to: "/")
      |> session.destroy(req, auth_ctx.db, auth_ctx.secret_key_base)

    _, ["password", ..rest] ->
      case list.contains(auth_ctx.methods, Password) {
        True -> password_handler.handle(req, rest, auth_ctx)
        False -> wisp.not_found()
      }

    _, _ -> wisp.not_found()
  }
}
