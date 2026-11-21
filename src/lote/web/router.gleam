import gleam/option.{type Option, None, Some}
import lote/auth.{type Auth}
import lote/auth/session
import lote/auth/user.{type AuthUser}
import lote/web/auth/handler as auth_handler
import lustre/attribute
import lustre/element
import lustre/element/html
import lustre/server_component
import wisp.{type Request, type Response}

pub fn handle_request(req: Request, auth_ctx: Auth) -> Response {
  use req <- middleware(req)

  case wisp.path_segments(req) {
    [] -> {
      let current_user =
        session.current_user(req, auth_ctx.db, auth_ctx.secret_key_base)
      wisp.html_response(index_html(current_user), 200)
    }
    ["auth", ..rest] -> auth_handler.handle_request(req, rest, auth_ctx)
    ["health"] -> wisp.response(200) |> wisp.string_body("ok")
    _ -> wisp.not_found()
  }
}

fn index_html(current_user: Option(AuthUser)) -> String {
  let auth_nav = case current_user {
    Some(u) ->
      html.div([], [
        html.span([], [html.text("Logged in as " <> u.name <> " ")]),
        html.form(
          [attribute.method("post"), attribute.action("/auth/logout")],
          [html.button([attribute.type_("submit")], [html.text("Logout")])],
        ),
      ])
    None ->
      html.div([], [
        html.a([attribute.href("/auth/login")], [html.text("Login")]),
      ])
  }

  html.html([attribute.lang("ja")], [
    html.head([], [
      html.meta([attribute.charset("utf-8")]),
      html.title([], "lote"),
      server_component.script(),
    ]),
    html.body([], [
      html.header([], [
        html.h1([], [html.text("lote")]),
        auth_nav,
      ]),
      server_component.element([server_component.route("/ws")], []),
    ]),
  ])
  |> element.to_document_string
}

fn middleware(req: Request, handle_request: fn(Request) -> Response) -> Response {
  let req = wisp.method_override(req)
  use <- wisp.log_request(req)
  use <- wisp.rescue_crashes
  use req <- wisp.handle_head(req)

  handle_request(req)
}
