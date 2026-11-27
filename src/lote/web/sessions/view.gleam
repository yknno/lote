import gleam/int
import gleam/list
import gleam/string
import lote/auth/session.{type SessionInfo}
import lote/auth/user.{type AuthUser}
import lote/web/csrf
import lote/web/time as web_time
import lustre/attribute
import lustre/element
import lustre/element/html
import wisp

pub fn index_page(
  current_user: AuthUser,
  sessions: List(SessionInfo),
  csrf_token: String,
) -> wisp.Response {
  let has_other_sessions = list.any(sessions, fn(s) { !s.is_current })
  let count_label = case list.length(sessions) {
    1 -> "1 active session"
    n -> int.to_string(n) <> " active sessions"
  }

  let revoke_others_form = case has_other_sessions {
    True ->
      html.form(
        [
          attribute.method("post"),
          attribute.action("/sessions/revoke-others"),
        ],
        [
          html.input([
            attribute.type_("hidden"),
            attribute.name(csrf.form_field_name),
            attribute.value(csrf_token),
          ]),
          html.button(
            [
              attribute.type_("submit"),
              attribute.class(
                "cursor-pointer border border-neutral-300 bg-white px-2.5 py-1 text-xs font-medium text-neutral-700 hover:border-red-600 hover:text-red-600",
              ),
            ],
            [html.text("Revoke other sessions")],
          ),
        ],
      )
    False -> element.none()
  }

  let doc =
    html.html([attribute.lang("ja"), attribute.class("bg-white")], [
      html.head([], [
        html.meta([attribute.charset("utf-8")]),
        html.meta([
          attribute.name("viewport"),
          attribute.content("width=device-width, initial-scale=1"),
        ]),
        html.title([], "Sessions - lote"),
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
                html.div([attribute.class("flex items-center gap-3 text-xs")], [
                  html.span([attribute.class("font-medium text-neutral-900")], [
                    html.text(current_user.name),
                  ]),
                  html.a(
                    [
                      attribute.href("/"),
                      attribute.class(
                        "text-neutral-500 underline-offset-2 hover:text-neutral-950 hover:underline",
                      ),
                    ],
                    [html.text("Timeline")],
                  ),
                  html.a(
                    [
                      attribute.href("/settings/clients"),
                      attribute.class(
                        "text-neutral-500 underline-offset-2 hover:text-neutral-950 hover:underline",
                      ),
                    ],
                    [html.text("Clients")],
                  ),
                  html.a(
                    [
                      attribute.href("/settings/grants"),
                      attribute.class(
                        "text-neutral-500 underline-offset-2 hover:text-neutral-950 hover:underline",
                      ),
                    ],
                    [html.text("Grants")],
                  ),
                  html.form(
                    [
                      attribute.method("post"),
                      attribute.action("/auth/logout"),
                    ],
                    [
                      html.input([
                        attribute.type_("hidden"),
                        attribute.name(csrf.form_field_name),
                        attribute.value(csrf_token),
                      ]),
                      html.button(
                        [
                          attribute.type_("submit"),
                          attribute.class(
                            "cursor-pointer text-neutral-500 underline-offset-2 hover:text-neutral-950 hover:underline",
                          ),
                        ],
                        [html.text("Log out")],
                      ),
                    ],
                  ),
                ]),
              ],
            ),
            html.main([attribute.class("px-4 py-6")], [
              html.div(
                [
                  attribute.class(
                    "mb-4 flex flex-wrap items-center justify-between gap-2",
                  ),
                ],
                [
                  html.div([], [
                    html.h1(
                      [
                        attribute.class(
                          "text-sm font-semibold text-neutral-950",
                        ),
                      ],
                      [html.text("Sessions")],
                    ),
                    html.p(
                      [
                        attribute.class(
                          "mt-0.5 font-mono text-xs text-neutral-400",
                        ),
                      ],
                      [html.text(count_label)],
                    ),
                  ]),
                  revoke_others_form,
                ],
              ),
              html.ul(
                [
                  attribute.class(
                    "divide-y divide-neutral-200 border-y border-neutral-200",
                  ),
                ],
                list.map(sessions, session_row(_, csrf_token)),
              ),
            ]),
          ],
        ),
      ]),
    ])
    |> element.to_document_string

  wisp.html_response(doc, 200)
}

fn session_row(s: SessionInfo, csrf_token: String) -> element.Element(Nil) {
  let device_label = summarize_user_agent(s.user_agent)
  let device_title = case s.user_agent {
    "" -> []
    ua -> [attribute.title(ua)]
  }

  let badge = case s.is_current {
    True ->
      html.span(
        [
          attribute.class(
            "border border-neutral-950 bg-neutral-950 px-1.5 py-0.5 font-mono text-[10px] font-medium text-white",
          ),
        ],
        [html.text("Current")],
      )
    False -> element.none()
  }

  let action = case s.is_current {
    True -> element.none()
    False ->
      html.form(
        [
          attribute.method("post"),
          attribute.action("/sessions/" <> s.public_id <> "/revoke"),
        ],
        [
          html.input([
            attribute.type_("hidden"),
            attribute.name(csrf.form_field_name),
            attribute.value(csrf_token),
          ]),
          html.button(
            [
              attribute.type_("submit"),
              attribute.class(
                "cursor-pointer text-xs text-neutral-400 underline-offset-2 hover:text-red-600 hover:underline",
              ),
            ],
            [html.text("Revoke")],
          ),
        ],
      )
  }

  html.li([attribute.class("py-3")], [
    html.div([attribute.class("flex items-center justify-between gap-2")], [
      html.div([attribute.class("flex min-w-0 items-center gap-2")], [
        html.span(
          [
            attribute.class("truncate text-sm font-medium text-neutral-950"),
            ..device_title
          ],
          [html.text(device_label)],
        ),
        badge,
      ]),
      action,
    ]),
    html.div(
      [
        attribute.class(
          "mt-1 flex flex-wrap items-baseline gap-x-3 gap-y-1 font-mono text-xs text-neutral-400 tabular-nums",
        ),
      ],
      [
        html.span([attribute.title(s.public_id)], [
          html.text("#" <> short_id(s.public_id)),
        ]),
        html.span([], [
          html.text("Signed in "),
          web_time.lote_time(s.created_at, ""),
        ]),
        html.span([], [
          html.text("Expires "),
          web_time.lote_time(s.expires_at, ""),
        ]),
      ],
    ),
  ])
}

pub fn summarize_user_agent(ua: String) -> String {
  let trimmed = string.trim(ua)
  case trimmed {
    "" -> "Unknown device"
    _ -> {
      let browser = detect_browser(trimmed)
      let os = detect_os(trimmed)
      case browser, os {
        Ok(b), Ok(o) -> b <> " on " <> o
        Ok(b), Error(_) -> b
        Error(_), Ok(o) -> o
        Error(_), Error(_) ->
          case string.length(trimmed) > 64 {
            True -> string.slice(trimmed, at_index: 0, length: 64) <> "…"
            False -> trimmed
          }
      }
    }
  }
}

fn detect_browser(ua: String) -> Result(String, Nil) {
  case
    string.contains(ua, "Edg/"),
    string.contains(ua, "OPR/"),
    string.contains(ua, "Firefox/"),
    string.contains(ua, "Chrome/") || string.contains(ua, "CriOS/"),
    string.contains(ua, "Safari/"),
    string.starts_with(ua, "curl/")
  {
    True, _, _, _, _, _ -> Ok("Edge")
    _, True, _, _, _, _ -> Ok("Opera")
    _, _, True, _, _, _ -> Ok("Firefox")
    _, _, _, True, _, _ -> Ok("Chrome")
    _, _, _, _, True, _ -> Ok("Safari")
    _, _, _, _, _, True -> Ok("curl")
    _, _, _, _, _, _ -> Error(Nil)
  }
}

fn detect_os(ua: String) -> Result(String, Nil) {
  case
    string.contains(ua, "iPhone") || string.contains(ua, "iPad"),
    string.contains(ua, "Android"),
    string.contains(ua, "Windows"),
    string.contains(ua, "Macintosh") || string.contains(ua, "Mac OS X"),
    string.contains(ua, "Linux")
  {
    True, _, _, _, _ -> Ok("iOS")
    _, True, _, _, _ -> Ok("Android")
    _, _, True, _, _ -> Ok("Windows")
    _, _, _, True, _ -> Ok("macOS")
    _, _, _, _, True -> Ok("Linux")
    _, _, _, _, _ -> Error(Nil)
  }
}

fn short_id(id: String) -> String {
  case string.length(id) >= 8 {
    True -> string.slice(id, at_index: string.length(id) - 8, length: 8)
    False -> id
  }
}
