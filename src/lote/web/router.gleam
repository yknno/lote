import gleam/http
import gleam/option.{None, Some}
import lote/auth.{type Auth}
import lote/db/post_repo
import lote/web/auth/handler as auth_handler
import lote/web/csrf
import lote/web/post/view as post_view
import lustre/attribute
import lustre/element
import lustre/element/html
import lustre/server_component
import wisp.{type Request, type Response}

pub fn handle_request(req: Request, auth_ctx: Auth) -> Response {
  use req <- middleware(req)

  case req.method, wisp.path_segments(req) {
    _, [] -> {
      let #(csrf_token, should_set_cookie) =
        csrf.ensure_token(req, auth_ctx.secret_key_base)
      wisp.html_response(index_html(), 200)
      |> csrf.attach_cookie(
        req,
        csrf_token,
        auth_ctx.secret_key_base,
        should_set_cookie,
      )
    }
    http.Get, ["posts", id] ->
      case post_repo.find_by_id(auth_ctx.db, id) {
        Ok(Some(post)) -> post_view.show_page(post)
        Ok(None) -> wisp.not_found()
        Error(_) -> wisp.internal_server_error()
      }
    _, ["posts", _] -> wisp.method_not_allowed([http.Get, http.Head])
    _, ["auth", ..rest] -> auth_handler.handle_request(req, rest, auth_ctx)
    _, ["health"] -> wisp.response(200) |> wisp.string_body("ok")
    _, _ -> wisp.not_found()
  }
}

fn index_html() -> String {
  html.html([attribute.lang("ja"), attribute.class("bg-white")], [
    html.head([], [
      html.meta([attribute.charset("utf-8")]),
      html.meta([
        attribute.name("viewport"),
        attribute.content("width=device-width, initial-scale=1"),
      ]),
      html.title([], "lote"),
      html.link([
        attribute.rel("stylesheet"),
        attribute.href("/static/app.css"),
      ]),
      server_component.script(),
      html.script(
        [attribute.type_("module"), attribute.src("/static/lote-time.js")],
        "",
      ),
    ]),
    html.body([attribute.class("min-h-screen bg-white text-neutral-950")], [
      server_component.element([server_component.route("/ws")], []),
    ]),
  ])
  |> element.to_document_string
}

fn middleware(
  req: Request,
  handle_request: fn(Request) -> Response,
) -> Response {
  let req = wisp.method_override(req)
  use <- wisp.log_request(req)
  use <- wisp.rescue_crashes
  use req <- wisp.handle_head(req)
  use req <- wisp.csrf_known_header_protection(req)

  let static_dir = case wisp.priv_directory("lote") {
    Ok(priv) -> priv <> "/static"
    Error(_) -> "priv/static"
  }
  use <- wisp.serve_static(req, under: "/static", from: static_dir)

  handle_request(req)
}
