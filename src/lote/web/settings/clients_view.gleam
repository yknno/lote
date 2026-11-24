import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/string
import lote/auth/user.{type AuthUser}
import lote/oidc/client.{type Client, type SecretInfo}
import lote/oidc/scope
import lote/web/csrf
import lote/web/time as web_time
import lustre/attribute
import lustre/element
import lustre/element/html
import wisp

pub type RevealedSecret {
  RevealedSecret(
    heading: String,
    client_name: Option(String),
    client_id: String,
    secret_label: String,
    raw_secret: String,
  )
}

pub fn index_page(
  current_user: AuthUser,
  clients: List(#(Client, List(SecretInfo))),
  revealed: Option(RevealedSecret),
  error: Option(String),
  csrf_token: String,
  status: Int,
) -> wisp.Response {
  let count_label = case list.length(clients) {
    1 -> "1 registered client"
    n -> int.to_string(n) <> " registered clients"
  }

  let error_el = case error {
    Some(msg) ->
      html.div(
        [
          attribute.role("alert"),
          attribute.class(
            "mb-4 border border-red-300 bg-red-50 px-3 py-2 text-xs text-red-700",
          ),
        ],
        [html.text(msg)],
      )
    None -> element.none()
  }

  let revealed_el = case revealed {
    Some(rev) -> revealed_secret_banner(rev)
    None -> element.none()
  }

  let clients_list = case clients {
    [] ->
      html.p(
        [
          attribute.class(
            "border-y border-neutral-200 py-6 text-xs text-neutral-400",
          ),
        ],
        [html.text("No clients registered yet.")],
      )
    _ ->
      html.ul(
        [
          attribute.class(
            "divide-y divide-neutral-200 border-y border-neutral-200",
          ),
        ],
        list.map(clients, fn(pair) { client_row(pair.0, pair.1, csrf_token) }),
      )
  }

  let doc =
    html.html([attribute.lang("ja"), attribute.class("bg-white")], [
      html.head([], [
        html.meta([attribute.charset("utf-8")]),
        html.meta([
          attribute.name("viewport"),
          attribute.content("width=device-width, initial-scale=1"),
        ]),
        html.title([], "Clients - lote"),
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
                      attribute.href("/sessions"),
                      attribute.class(
                        "text-neutral-500 underline-offset-2 hover:text-neutral-950 hover:underline",
                      ),
                    ],
                    [html.text("Sessions")],
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
              html.div([attribute.class("mb-5")], [
                html.h1(
                  [attribute.class("text-sm font-semibold text-neutral-950")],
                  [html.text("Subordinate Bots & Apps")],
                ),
                html.p(
                  [attribute.class("mt-0.5 font-mono text-xs text-neutral-400")],
                  [html.text(count_label)],
                ),
              ]),
              error_el,
              revealed_el,
              create_bot_section(csrf_token),
              clients_list,
            ]),
          ],
        ),
      ]),
    ])
    |> element.to_document_string

  wisp.html_response(doc, status)
}

fn revealed_secret_banner(rev: RevealedSecret) -> element.Element(Nil) {
  let name_line = case rev.client_name {
    Some(name) ->
      html.div([attribute.class("flex flex-col gap-0.5")], [
        html.span([attribute.class("text-[11px] text-neutral-500")], [
          html.text("Client Name"),
        ]),
        html.span([attribute.class("text-xs font-medium text-neutral-950")], [
          html.text(name),
        ]),
      ])
    None -> element.none()
  }

  let label_suffix = case rev.secret_label {
    "" -> ""
    l -> " (" <> l <> ")"
  }

  html.section(
    [
      attribute.role("region"),
      attribute.attribute("aria-label", "One-time client secret"),
      attribute.class("mb-6 border-2 border-neutral-950 bg-neutral-50 p-4"),
    ],
    [
      html.p([attribute.class("text-xs font-semibold text-neutral-950")], [
        html.text(rev.heading),
      ]),
      html.p([attribute.class("mt-1 text-xs text-neutral-600")], [
        html.text(
          "Copy and store this client secret now. It is displayed only once and cannot be viewed again.",
        ),
      ]),
      html.div([attribute.class("mt-3 flex flex-col gap-2.5")], [
        name_line,
        html.div([attribute.class("flex flex-col gap-0.5")], [
          html.span([attribute.class("text-[11px] text-neutral-500")], [
            html.text("Client ID"),
          ]),
          html.code(
            [
              attribute.attribute("data-client-id", rev.client_id),
              attribute.class(
                "block break-all border border-neutral-300 bg-white px-2.5 py-1.5 font-mono text-xs text-neutral-950",
              ),
            ],
            [html.text(rev.client_id)],
          ),
        ]),
        html.div([attribute.class("flex flex-col gap-0.5")], [
          html.span([attribute.class("text-[11px] text-neutral-500")], [
            html.text("Client Secret" <> label_suffix),
          ]),
          html.code(
            [
              attribute.attribute("data-client-secret", rev.raw_secret),
              attribute.class(
                "block break-all border border-neutral-950 bg-white px-2.5 py-1.5 font-mono text-xs font-medium text-neutral-950",
              ),
            ],
            [html.text(rev.raw_secret)],
          ),
        ]),
      ]),
    ],
  )
}

fn create_bot_section(csrf_token: String) -> element.Element(Nil) {
  let scope_checkboxes =
    list.map(scope.bot_assignable(), fn(sc) {
      let sc_str = scope.to_string(sc)
      let default_checked = sc == scope.PostsRead
      html.label(
        [
          attribute.class(
            "inline-flex cursor-pointer items-center gap-1.5 border border-neutral-300 bg-white px-2.5 py-1 font-mono text-xs text-neutral-800 hover:border-neutral-950",
          ),
        ],
        [
          html.input([
            attribute.type_("checkbox"),
            attribute.name("scopes"),
            attribute.value(sc_str),
            attribute.checked(default_checked),
            attribute.class("accent-neutral-950"),
          ]),
          html.span([], [html.text(sc_str)]),
        ],
      )
    })

  html.section(
    [attribute.class("mb-6 border border-neutral-200 bg-neutral-50/60 p-4")],
    [
      html.h2([attribute.class("text-xs font-semibold text-neutral-950")], [
        html.text("Create subordinate bot"),
      ]),
      html.p([attribute.class("mt-0.5 text-xs text-neutral-500")], [
        html.text(
          "Subordinate bots authenticate via OAuth 2.0 client_credentials and act on your personal account within the selected scopes.",
        ),
      ]),
      html.form(
        [
          attribute.method("post"),
          attribute.action("/settings/clients/bots"),
          attribute.class("mt-3 flex flex-col gap-3"),
        ],
        [
          html.input([
            attribute.type_("hidden"),
            attribute.name(csrf.form_field_name),
            attribute.value(csrf_token),
          ]),
          html.div([attribute.class("grid grid-cols-1 gap-3 sm:grid-cols-2")], [
            html.div([attribute.class("flex flex-col gap-1")], [
              html.label(
                [
                  attribute.for("bot_name"),
                  attribute.class("text-xs text-neutral-600"),
                ],
                [html.text("Bot name")],
              ),
              html.input([
                attribute.id("bot_name"),
                attribute.type_("text"),
                attribute.name("name"),
                attribute.required(True),
                attribute.maxlength(100),
                attribute.placeholder("Release notifier"),
                attribute.class(
                  "w-full border border-neutral-300 bg-white px-2.5 py-1.5 text-sm text-neutral-950 placeholder:text-neutral-400 focus:border-neutral-950 focus:outline-none",
                ),
              ]),
            ]),
            html.div([attribute.class("flex flex-col gap-1")], [
              html.label(
                [
                  attribute.for("bot_secret_label"),
                  attribute.class("text-xs text-neutral-600"),
                ],
                [html.text("Secret label (optional)")],
              ),
              html.input([
                attribute.id("bot_secret_label"),
                attribute.type_("text"),
                attribute.name("secret_label"),
                attribute.maxlength(100),
                attribute.placeholder("default"),
                attribute.class(
                  "w-full border border-neutral-300 bg-white px-2.5 py-1.5 text-sm text-neutral-950 placeholder:text-neutral-400 focus:border-neutral-950 focus:outline-none",
                ),
              ]),
            ]),
          ]),
          html.div([attribute.class("flex flex-col gap-1.5")], [
            html.span([attribute.class("text-xs text-neutral-600")], [
              html.text("Scopes"),
            ]),
            html.div(
              [attribute.class("flex flex-wrap gap-2")],
              scope_checkboxes,
            ),
          ]),
          html.div([], [
            html.button(
              [
                attribute.type_("submit"),
                attribute.class(
                  "cursor-pointer bg-neutral-950 px-4 py-1.5 text-xs font-medium text-white hover:bg-neutral-800",
                ),
              ],
              [html.text("Create subordinate bot")],
            ),
          ]),
        ],
      ),
    ],
  )
}

fn client_row(
  c: Client,
  secrets: List(SecretInfo),
  csrf_token: String,
) -> element.Element(Nil) {
  let kind_badge =
    html.span(
      [
        attribute.class(
          "border border-neutral-300 bg-neutral-50 px-1.5 py-0.5 font-mono text-[10px] font-medium text-neutral-700",
        ),
      ],
      [html.text(kind_label(c.kind))],
    )

  let scope_str = scope.format_space_delimited(c.allowed_scopes)

  let secrets_section = case supports_secrets(c.kind) {
    False -> element.none()
    True ->
      html.div([attribute.class("mt-3 border-t border-neutral-100 pt-2.5")], [
        html.div(
          [
            attribute.class(
              "flex flex-wrap items-center justify-between gap-2 text-xs",
            ),
          ],
          [
            html.span([attribute.class("font-medium text-neutral-700")], [
              html.text("Client secrets"),
            ]),
            add_secret_form(c.client_id, csrf_token),
          ],
        ),
        case secrets {
          [] ->
            html.p(
              [attribute.class("mt-1.5 font-mono text-xs text-neutral-400")],
              [html.text("No active secrets.")],
            )
          _ ->
            html.ul(
              [attribute.class("mt-2 divide-y divide-neutral-100")],
              list.map(secrets, fn(s) { secret_row(c.client_id, s, csrf_token) }),
            )
        },
      ])
  }

  html.li([attribute.class("py-4")], [
    html.div([attribute.class("flex items-center justify-between gap-2")], [
      html.div([attribute.class("flex min-w-0 items-center gap-2")], [
        html.span(
          [attribute.class("truncate text-sm font-medium text-neutral-950")],
          [html.text(c.name)],
        ),
        kind_badge,
      ]),
      html.form(
        [
          attribute.method("post"),
          attribute.action("/settings/clients/" <> c.client_id <> "/delete"),
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
            [html.text("Delete")],
          ),
        ],
      ),
    ]),
    html.div(
      [
        attribute.class(
          "mt-1 flex flex-wrap items-baseline gap-x-3 gap-y-1 font-mono text-xs text-neutral-500 tabular-nums",
        ),
      ],
      [
        html.span([attribute.class("text-neutral-900")], [
          html.text(c.client_id),
        ]),
        html.span([], [html.text("scopes: " <> scope_str)]),
        html.span([attribute.class("text-neutral-400")], [
          html.text("Created "),
          web_time.lote_time(c.created_at, ""),
        ]),
      ],
    ),
    secrets_section,
  ])
}

fn secret_row(
  client_id: String,
  s: SecretInfo,
  csrf_token: String,
) -> element.Element(Nil) {
  let label_el = case s.label {
    "" -> element.none()
    lbl ->
      html.span([attribute.class("text-xs text-neutral-700")], [html.text(lbl)])
  }

  let used_el = case s.last_used_at {
    Some(ts) ->
      html.span([], [
        html.text("Last used "),
        web_time.lote_time(ts, ""),
      ])
    None -> html.span([], [html.text("Never used")])
  }

  let expires_el = case s.expires_at {
    Some(ts) ->
      html.span([], [
        html.text("Expires "),
        web_time.lote_time(ts, ""),
      ])
    None -> element.none()
  }

  html.li(
    [
      attribute.class(
        "flex flex-wrap items-center justify-between gap-2 py-1.5 font-mono text-xs text-neutral-400 tabular-nums",
      ),
    ],
    [
      html.div([attribute.class("flex flex-wrap items-baseline gap-x-3")], [
        html.span([attribute.class("text-neutral-900")], [
          html.text(s.secret_prefix <> "…"),
        ]),
        label_el,
        html.span([attribute.title(s.public_id)], [
          html.text("#" <> short_id(s.public_id)),
        ]),
        html.span([], [
          html.text("Created "),
          web_time.lote_time(s.created_at, ""),
        ]),
        used_el,
        expires_el,
      ]),
      html.form(
        [
          attribute.method("post"),
          attribute.action(
            "/settings/clients/"
            <> client_id
            <> "/secrets/"
            <> s.public_id
            <> "/revoke",
          ),
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
                "cursor-pointer font-sans text-xs text-neutral-400 underline-offset-2 hover:text-red-600 hover:underline",
              ),
            ],
            [html.text("Revoke")],
          ),
        ],
      ),
    ],
  )
}

fn add_secret_form(
  client_id: String,
  csrf_token: String,
) -> element.Element(Nil) {
  html.form(
    [
      attribute.method("post"),
      attribute.action("/settings/clients/" <> client_id <> "/secrets"),
      attribute.class("flex items-center gap-1.5"),
    ],
    [
      html.input([
        attribute.type_("hidden"),
        attribute.name(csrf.form_field_name),
        attribute.value(csrf_token),
      ]),
      html.input([
        attribute.type_("text"),
        attribute.name("label"),
        attribute.maxlength(100),
        attribute.placeholder("Secret label"),
        attribute.class(
          "w-28 border border-neutral-300 bg-white px-2 py-0.5 text-xs text-neutral-950 placeholder:text-neutral-400 focus:border-neutral-950 focus:outline-none",
        ),
      ]),
      html.button(
        [
          attribute.type_("submit"),
          attribute.class(
            "cursor-pointer border border-neutral-300 bg-white px-2.5 py-0.5 text-xs font-medium text-neutral-700 hover:border-neutral-950 hover:text-neutral-950",
          ),
        ],
        [html.text("Add secret")],
      ),
    ],
  )
}

fn supports_secrets(kind: client.Kind) -> Bool {
  case kind {
    client.SubordinateBot | client.ConfidentialApp -> True
    client.PublicApp | client.Cimd -> False
  }
}

fn kind_label(kind: client.Kind) -> String {
  case kind {
    client.SubordinateBot -> "Subordinate Bot"
    client.ConfidentialApp -> "Confidential App"
    client.PublicApp -> "Public App"
    client.Cimd -> "CIMD"
  }
}

fn short_id(id: String) -> String {
  case string.length(id) >= 8 {
    True -> string.slice(id, at_index: string.length(id) - 8, length: 8)
    False -> id
  }
}
