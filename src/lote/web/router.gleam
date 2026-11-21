import wisp.{type Request, type Response}

pub fn handle_request(req: Request) -> Response {
  use req <- middleware(req)

  case wisp.path_segments(req) {
    [] -> wisp.html_response("<h1>Hello, lote!</h1>", 200)
    ["health"] -> wisp.response(200) |> wisp.string_body("ok")
    _ -> wisp.not_found()
  }
}

fn middleware(req: Request, handle_request: fn(Request) -> Response) -> Response {
  let req = wisp.method_override(req)
  use <- wisp.log_request(req)
  use <- wisp.rescue_crashes
  use req <- wisp.handle_head(req)

  handle_request(req)
}
