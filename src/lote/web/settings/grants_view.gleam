import gleam/dict
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/set
import gleam/string
import lote/auth/user.{type AuthUser}
import lote/oidc/client
import lote/oidc/grant.{type ConsentInfo, type GrantInfo}
import lote/oidc/scope
import lote/web/csrf
import lote/web/time as web_time
import lustre/attribute
import lustre/element
import lustre/element/html
import wisp

pub fn index_page(
  current_user: AuthUser,
  consents: List(ConsentInfo),
  active_grants: List(GrantInfo),
  csrf_token: String,
) -> wisp.Response {
  let active_consent_ids =
    list.fold(active_grants, set.new(), fn(acc, g) {
      set.insert(acc, g.consent_public_id)
    })

  let app_consents =
    list.filter(consents, fn(c) {
      c.client_kind != client.SubordinateBot
      && {
        !set.is_empty(c.scopes) || set.contains(active_consent_ids, c.public_id)
      }
    })

  let consent_kinds =
    list.fold(consents, dict.new(), fn(acc, c) {
      dict.insert(acc, c.public_id, c.client_kind)
    })

  let apps_count_label = case list.length(app_consents) {
    1 -> "1 connected app"
    n -> int.to_string(n) <> " connected apps"
  }

  let grants_count_label = case list.length(active_grants) {
    1 -> "1 active grant"
    n -> int.to_string(n) <> " active grants"
  }

  let connected_apps_list = case app_consents {
    [] ->
      html.p(
        [
          attribute.class(
            "border-y border-neutral-200 py-6 text-xs text-neutral-400",
          ),
        ],
        [html.text("No connected apps.")],
      )
    _ ->
      html.ul(
        [
          attribute.class(
            "divide-y divide-neutral-200 border-y border-neutral-200",
          ),
        ],
        list.map(app_consents, consent_row(_, csrf_token)),
      )
  }

  let active_grants_list = case active_grants {
    [] ->
      html.p(
        [
          attribute.class(
            "border-y border-neutral-200 py-6 text-xs text-neutral-400",
          ),
        ],
        [html.text("No active grants.")],
      )
    _ ->
      html.ul(
        [
          attribute.class(
            "divide-y divide-neutral-200 border-y border-neutral-200",
          ),
        ],
        list.map(active_grants, fn(g) {
          let kind =
            dict.get(consent_kinds, g.consent_public_id)
            |> option.from_result
          grant_row(g, kind, csrf_token)
        }),
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
        html.title([], "Grants - lote"),
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
              html.section([attribute.class("mb-8")], [
                html.div([attribute.class("mb-4")], [
                  html.h1(
                    [attribute.class("text-sm font-semibold text-neutral-950")],
                    [html.text("Connected Apps")],
                  ),
                  html.p(
                    [
                      attribute.class(
                        "mt-0.5 font-mono text-xs text-neutral-400",
                      ),
                    ],
                    [html.text(apps_count_label)],
                  ),
                ]),
                connected_apps_list,
              ]),
              html.section([], [
                html.div([attribute.class("mb-4")], [
                  html.h2(
                    [attribute.class("text-sm font-semibold text-neutral-950")],
                    [html.text("Active Grants & Token Sessions")],
                  ),
                  html.p(
                    [
                      attribute.class(
                        "mt-0.5 font-mono text-xs text-neutral-400",
                      ),
                    ],
                    [html.text(grants_count_label)],
                  ),
                ]),
                active_grants_list,
              ]),
            ]),
          ],
        ),
      ]),
    ])
    |> element.to_document_string

  wisp.html_response(doc, 200)
}

fn consent_row(c: ConsentInfo, csrf_token: String) -> element.Element(Nil) {
  let scope_str = scope.format_space_delimited(c.scopes)

  html.li([attribute.class("py-3.5")], [
    html.div([attribute.class("flex items-center justify-between gap-2")], [
      html.div([attribute.class("flex min-w-0 flex-wrap items-center gap-2")], [
        html.span(
          [attribute.class("truncate text-sm font-medium text-neutral-950")],
          [html.text(c.client_name)],
        ),
        badge_span(kind_label(c.client_kind)),
      ]),
      html.form(
        [
          attribute.method("post"),
          attribute.action(
            "/settings/grants/consents/" <> c.public_id <> "/revoke",
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
                "cursor-pointer text-xs text-neutral-400 underline-offset-2 hover:text-red-600 hover:underline",
              ),
            ],
            [html.text("Revoke access")],
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
          html.text("Updated "),
          web_time.lote_time(c.updated_at, ""),
        ]),
      ],
    ),
  ])
}

fn grant_row(
  g: GrantInfo,
  kind: Option(client.Kind),
  csrf_token: String,
) -> element.Element(Nil) {
  let kind_badge = case kind {
    Some(k) -> badge_span(kind_label(k))
    None -> element.none()
  }

  let scope_str = scope.format_space_delimited(g.scopes)

  let ua_trimmed = string.trim(g.user_agent)
  let ua_label = case ua_trimmed {
    "" -> "Unknown client"
    _ -> ua_trimmed
  }

  let used_el = case g.last_used_at {
    Some(ts) ->
      html.span([], [
        html.text("Last used "),
        web_time.lote_time(ts, ""),
      ])
    None -> html.span([], [html.text("Never used")])
  }

  html.li([attribute.class("py-3.5")], [
    html.div([attribute.class("flex items-center justify-between gap-2")], [
      html.div([attribute.class("flex min-w-0 flex-wrap items-center gap-2")], [
        html.span(
          [attribute.class("truncate text-sm font-medium text-neutral-950")],
          [html.text(g.client_name)],
        ),
        kind_badge,
      ]),
      html.form(
        [
          attribute.method("post"),
          attribute.action("/settings/grants/" <> g.public_id <> "/revoke"),
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
          html.text(g.client_id),
        ]),
        html.span([attribute.title(g.public_id)], [
          html.text("#" <> short_id(g.public_id)),
        ]),
        html.span([], [html.text("scopes: " <> scope_str)]),
        html.span([attribute.class("break-all")], [
          html.text("audience: " <> g.audience),
        ]),
      ],
    ),
    html.div(
      [
        attribute.class(
          "mt-1 flex flex-wrap items-baseline gap-x-3 gap-y-1 font-mono text-xs text-neutral-400 tabular-nums",
        ),
      ],
      [
        html.span([attribute.class("break-all text-neutral-600")], [
          html.text(ua_label),
        ]),
        html.span([], [
          html.text("Created "),
          web_time.lote_time(g.created_at, ""),
        ]),
        used_el,
        html.span([], [
          html.text("Expires "),
          web_time.lote_time(g.expires_at, ""),
        ]),
      ],
    ),
  ])
}

fn badge_span(label: String) -> element.Element(Nil) {
  html.span(
    [
      attribute.class(
        "border border-neutral-300 bg-neutral-50 px-1.5 py-0.5 font-mono text-[10px] font-medium text-neutral-700",
      ),
    ],
    [html.text(label)],
  )
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
