import gleam/option.{type Option, None, Some}
import gleam/string
import lote/db/post_repo.{type PostRow}
import lote/web/csrf
import lote/web/time as web_time
import lustre/attribute
import lustre/element
import lustre/element/html
import wisp

pub fn show_page(
  post: PostRow,
  delete_csrf_token: Option(String),
) -> wisp.Response {
  let page_title = post.author_name <> " - lote"
  let og_description = truncate(post.body, 160)

  let delete_form = case delete_csrf_token {
    Some(token) ->
      html.form(
        [
          attribute.method("post"),
          attribute.action("/posts/" <> post.id <> "/delete"),
        ],
        [
          html.input([
            attribute.type_("hidden"),
            attribute.name(csrf.form_field_name),
            attribute.value(token),
          ]),
          html.button(
            [
              attribute.type_("submit"),
              attribute.class(
                "cursor-pointer text-xs text-neutral-400 underline-offset-2 hover:text-red-600 hover:underline",
              ),
            ],
            [html.text("Delete")],
          ),
        ],
      )
    None -> element.none()
  }

  let doc =
    html.html([attribute.lang("ja"), attribute.class("bg-white")], [
      html.head([], [
        html.meta([attribute.charset("utf-8")]),
        html.meta([
          attribute.name("viewport"),
          attribute.content("width=device-width, initial-scale=1"),
        ]),
        html.title([], page_title),
        html.meta([
          attribute.attribute("property", "og:title"),
          attribute.content(page_title),
        ]),
        html.meta([
          attribute.attribute("property", "og:description"),
          attribute.content(og_description),
        ]),
        html.link([
          attribute.rel("stylesheet"),
          attribute.href("/static/app.css"),
        ]),
        html.script(
          [attribute.type_("module"), attribute.src("/static/lote-time.js")],
          "",
        ),
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
                html.a(
                  [
                    attribute.href("/"),
                    attribute.class(
                      "text-xs text-neutral-500 underline-offset-2 hover:text-neutral-950 hover:underline",
                    ),
                  ],
                  [html.text("Timeline")],
                ),
              ],
            ),
            html.main([attribute.class("px-4 py-6")], [
              html.article([], [
                html.div(
                  [attribute.class("flex items-baseline gap-2 text-xs")],
                  [
                    html.span(
                      [attribute.class("font-semibold text-neutral-950")],
                      [html.text(post.author_name)],
                    ),
                    web_time.lote_time(
                      post.created_at,
                      "ml-auto shrink-0 font-mono text-xs text-neutral-400 tabular-nums",
                    ),
                  ],
                ),
                html.p(
                  [
                    attribute.class(
                      "mt-3 whitespace-pre-wrap break-words text-base leading-relaxed text-neutral-900",
                    ),
                  ],
                  [html.text(post.body)],
                ),
                html.div(
                  [
                    attribute.class(
                      "mt-6 flex items-center justify-between border-t border-neutral-200 pt-3",
                    ),
                  ],
                  [
                    html.span(
                      [attribute.class("font-mono text-xs text-neutral-400")],
                      [html.text(post.id)],
                    ),
                    delete_form,
                  ],
                ),
              ]),
            ]),
          ],
        ),
      ]),
    ])
    |> element.to_document_string

  wisp.html_response(doc, 200)
}

fn truncate(text: String, max_len: Int) -> String {
  case string.length(text) > max_len {
    True -> string.slice(text, at_index: 0, length: max_len) <> "…"
    False -> text
  }
}
