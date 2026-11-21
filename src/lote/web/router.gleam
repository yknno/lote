import lustre/attribute
import lustre/element
import lustre/element/html
import lustre/server_component
import wisp.{type Request, type Response}

pub fn handle_request(req: Request) -> Response {
  use req <- middleware(req)

  case wisp.path_segments(req) {
    [] -> wisp.html_response(index_html(), 200)
    ["health"] -> wisp.response(200) |> wisp.string_body("ok")
    _ -> wisp.not_found()
  }
}

fn index_html() -> String {
  html.html([attribute.lang("ja")], [
    html.head([], [
      html.meta([attribute.charset("utf-8")]),
      html.title([], "lote"),
      server_component.script(),
    ]),
    html.body([], [
      html.h1([], [html.text("lote")]),
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
