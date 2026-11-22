import gleam/list
import gleam/option.{type Option, None, Some}
import lote/auth.{type Method, Password}
import lote/web/csrf
import lustre/attribute
import lustre/element
import lustre/element/html
import wisp

pub fn login_page(
  methods: List(Method),
  error: Option(String),
  csrf_token: String,
) -> wisp.Response {
  let error_el = case error {
    Some(msg) ->
      html.p(
        [
          attribute.class(
            "mb-3 border border-red-300 bg-red-50 px-3 py-2 text-xs text-red-700",
          ),
        ],
        [html.text(msg)],
      )
    None -> element.none()
  }

  let sections = case methods {
    [] -> [
      html.p([attribute.class("text-xs text-neutral-500")], [
        html.text("No login methods enabled."),
      ]),
    ]
    _ -> list.map(methods, method_section(_, csrf_token))
  }

  let doc =
    html.html([attribute.lang("ja"), attribute.class("bg-white")], [
      html.head([], [
        html.meta([attribute.charset("utf-8")]),
        html.meta([
          attribute.name("viewport"),
          attribute.content("width=device-width, initial-scale=1"),
        ]),
        html.title([], "Log in - lote"),
        html.link([
          attribute.rel("stylesheet"),
          attribute.href("/static/app.css"),
        ]),
      ]),
      html.body([attribute.class("min-h-screen bg-white text-neutral-950")], [
        html.div(
          [
            attribute.class(
              "mx-auto min-h-screen max-w-2xl border-x border-neutral-200",
            ),
          ],
          [
            html.header(
              [
                attribute.class(
                  "flex h-11 items-center justify-between border-b border-neutral-200 px-4",
                ),
              ],
              [
                html.a(
                  [
                    attribute.href("/"),
                    attribute.class(
                      "font-mono text-sm font-bold tracking-tight text-neutral-950",
                    ),
                  ],
                  [html.text("lote")],
                ),
              ],
            ),
            html.main([attribute.class("max-w-xs px-4 py-6")], [
              html.h1(
                [attribute.class("mb-4 text-sm font-semibold text-neutral-950")],
                [html.text("Log in")],
              ),
              error_el,
              ..sections
            ]),
          ],
        ),
      ]),
    ])
    |> element.to_document_string

  wisp.html_response(doc, 200)
}

fn method_section(method: Method, csrf_token: String) -> element.Element(Nil) {
  case method {
    Password ->
      html.form(
        [
          attribute.method("post"),
          attribute.action("/auth/password/login"),
          attribute.class("flex flex-col gap-3"),
        ],
        [
          html.input([
            attribute.type_("hidden"),
            attribute.name(csrf.form_field_name),
            attribute.value(csrf_token),
          ]),
          html.div([attribute.class("flex flex-col gap-1")], [
            html.label(
              [
                attribute.for("login_id"),
                attribute.class("text-xs text-neutral-600"),
              ],
              [html.text("Login ID")],
            ),
            html.input([
              attribute.id("login_id"),
              attribute.type_("text"),
              attribute.name("login_id"),
              attribute.required(True),
              attribute.class(
                "w-full border border-neutral-300 px-2.5 py-1.5 text-sm text-neutral-950 focus:border-neutral-950 focus:outline-none",
              ),
            ]),
          ]),
          html.div([attribute.class("flex flex-col gap-1")], [
            html.label(
              [
                attribute.for("password"),
                attribute.class("text-xs text-neutral-600"),
              ],
              [html.text("Password")],
            ),
            html.input([
              attribute.id("password"),
              attribute.type_("password"),
              attribute.name("password"),
              attribute.required(True),
              attribute.class(
                "w-full border border-neutral-300 px-2.5 py-1.5 text-sm text-neutral-950 focus:border-neutral-950 focus:outline-none",
              ),
            ]),
          ]),
          html.button(
            [
              attribute.type_("submit"),
              attribute.class(
                "mt-1 w-fit cursor-pointer bg-neutral-950 px-4 py-1.5 text-xs font-medium text-white hover:bg-neutral-800",
              ),
            ],
            [html.text("Log in")],
          ),
        ],
      )
  }
}
