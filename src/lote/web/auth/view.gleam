import gleam/list
import gleam/option.{type Option, None, Some}
import lote/auth.{type Method, Password}
import lustre/attribute
import lustre/element
import lustre/element/html
import wisp

pub fn login_page(methods: List(Method), error: Option(String)) -> wisp.Response {
  let error_el = case error {
    Some(msg) -> html.p([], [html.text(msg)])
    None -> element.none()
  }

  let sections = case methods {
    [] -> [html.p([], [html.text("利用可能な認証方法がありません。")])]
    _ -> list.map(methods, method_section)
  }

  let doc =
    html.html([attribute.lang("ja")], [
      html.head([], [
        html.meta([attribute.charset("utf-8")]),
        html.title([], "Login - lote"),
      ]),
      html.body([], [html.h1([], [html.text("lote")]), error_el, ..sections]),
    ])
    |> element.to_document_string

  wisp.html_response(doc, 200)
}

fn method_section(method: Method) -> element.Element(Nil) {
  case method {
    Password ->
      html.section([], [
        html.h2([], [html.text("Login")]),
        html.form(
          [attribute.method("post"), attribute.action("/auth/password/login")],
          [
            html.input([
              attribute.type_("text"),
              attribute.name("login_id"),
              attribute.placeholder("Login ID"),
              attribute.required(True),
            ]),
            html.input([
              attribute.type_("password"),
              attribute.name("password"),
              attribute.placeholder("Password"),
              attribute.required(True),
            ]),
            html.button([attribute.type_("submit")], [html.text("Login")]),
          ],
        ),
      ])
  }
}
