import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/set.{type Set}
import gleam/string
import gleam/uri
import lote/auth/user.{type AuthUser}
import lote/oidc/cimd
import lote/oidc/client.{type Client}
import lote/oidc/scope.{type Scope}
import lote/web/csrf
import lustre/attribute
import lustre/element
import lustre/element/html
import wisp

pub type ConsentParams {
  ConsentParams(
    current_user: AuthUser,
    client: Client,
    redirect_uri: String,
    requested_scopes: Set(Scope),
    existing_scopes: Set(Scope),
    audience: String,
    default_issuer: String,
    code_challenge: String,
    code_challenge_method: String,
    state: Option(String),
    resource: Option(String),
    nonce: Option(String),
    csrf_token: String,
  )
}

pub fn consent_page(params: ConsentParams) -> wisp.Response {
  let kind_label = client_kind_label(params.client.kind)
  let redirect_host = redirect_host_label(params.redirect_uri)
  let cimd_callout = render_cimd_callout(params, redirect_host)
  let audience_row = case
    params.resource != None || params.audience != params.default_issuer
  {
    True ->
      html.div(
        [
          attribute.class(
            "flex items-baseline justify-between gap-3 border-t border-neutral-200 pt-2 text-xs",
          ),
        ],
        [
          html.span([attribute.class("text-neutral-500")], [
            html.text("Target resource"),
          ]),
          html.span([attribute.class("break-all font-mono text-neutral-900")], [
            html.text(params.audience),
          ]),
        ],
      )
    False -> element.none()
  }

  let scopes_section =
    render_scopes_section(params.requested_scopes, params.existing_scopes)

  let doc =
    html.html([attribute.lang("ja"), attribute.class("bg-white")], [
      html.head([], [
        html.meta([attribute.charset("utf-8")]),
        html.meta([
          attribute.name("viewport"),
          attribute.content("width=device-width, initial-scale=1"),
        ]),
        html.title([], "Authorize application - lote"),
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
                html.div([attribute.class("flex items-center gap-3 text-xs")], [
                  html.span([attribute.class("font-medium text-neutral-900")], [
                    html.bdi([], [html.text(params.current_user.name)]),
                  ]),
                  html.a(
                    [
                      attribute.href("/settings/grants"),
                      attribute.class(
                        "text-neutral-500 underline-offset-2 hover:text-neutral-950 hover:underline",
                      ),
                    ],
                    [html.text("Grants")],
                  ),
                ]),
              ],
            ),
            html.main([attribute.class("mx-auto max-w-md px-4 py-6")], [
              html.div([attribute.class("mb-4")], [
                html.p(
                  [
                    attribute.class(
                      "font-mono text-[11px] uppercase tracking-wider text-neutral-500",
                    ),
                  ],
                  [html.text(kind_label)],
                ),
                html.h1(
                  [
                    attribute.class(
                      "mt-1 text-base font-semibold text-neutral-950",
                    ),
                  ],
                  [
                    html.bdi([], [html.text(params.client.name)]),
                    html.span(
                      [attribute.class("font-normal text-neutral-600")],
                      [html.text(" wants access to your account")],
                    ),
                  ],
                ),
              ]),
              cimd_callout,
              html.div(
                [
                  attribute.class(
                    "mb-4 border border-neutral-200 bg-neutral-50 px-3 py-2.5 text-xs text-neutral-700",
                  ),
                ],
                [
                  html.p([], [
                    html.text("Signed in as "),
                    html.span(
                      [attribute.class("font-semibold text-neutral-950")],
                      [html.bdi([], [html.text(params.current_user.name)])],
                    ),
                    html.text(
                      ". Issued tokens will act on behalf of your personal account. You can revoke access anytime in ",
                    ),
                    html.a(
                      [
                        attribute.href("/settings/grants"),
                        attribute.class(
                          "font-medium text-neutral-950 underline underline-offset-2",
                        ),
                      ],
                      [html.text("Authorized Grants")],
                    ),
                    html.text("."),
                  ]),
                ],
              ),
              html.div(
                [
                  attribute.class(
                    "mb-4 flex flex-col gap-2 border border-neutral-200 px-3 py-2.5",
                  ),
                ],
                [
                  html.div(
                    [
                      attribute.class(
                        "flex items-baseline justify-between gap-3 text-xs",
                      ),
                    ],
                    [
                      html.span([attribute.class("text-neutral-500")], [
                        html.text("Redirects to"),
                      ]),
                      html.span(
                        [
                          attribute.class(
                            "break-all font-mono text-neutral-900",
                          ),
                        ],
                        [html.text(redirect_host)],
                      ),
                    ],
                  ),
                  audience_row,
                ],
              ),
              scopes_section,
              html.form(
                [
                  attribute.method("post"),
                  attribute.action("/oidc/authorize"),
                  attribute.class("mt-5 flex items-center gap-2"),
                ],
                [
                  hidden_input(csrf.form_field_name, params.csrf_token),
                  hidden_input("client_id", params.client.client_id),
                  hidden_input("redirect_uri", params.redirect_uri),
                  hidden_input("response_type", "code"),
                  hidden_input(
                    "scope",
                    scope.format_space_delimited(params.requested_scopes),
                  ),
                  hidden_input("code_challenge", params.code_challenge),
                  hidden_input(
                    "code_challenge_method",
                    params.code_challenge_method,
                  ),
                  optional_hidden_input("state", params.state),
                  optional_hidden_input("resource", params.resource),
                  optional_hidden_input("nonce", params.nonce),
                  html.button(
                    [
                      attribute.type_("submit"),
                      attribute.name("decision"),
                      attribute.value("approve"),
                      attribute.class(
                        "cursor-pointer bg-neutral-950 px-4 py-1.5 text-xs font-medium text-white hover:bg-neutral-800",
                      ),
                    ],
                    [html.text("Authorize")],
                  ),
                  html.button(
                    [
                      attribute.type_("submit"),
                      attribute.name("decision"),
                      attribute.value("deny"),
                      attribute.class(
                        "cursor-pointer border border-neutral-300 bg-white px-4 py-1.5 text-xs font-medium text-neutral-700 hover:border-neutral-950 hover:text-neutral-950",
                      ),
                    ],
                    [html.text("Deny")],
                  ),
                ],
              ),
            ]),
          ],
        ),
      ]),
    ])
    |> element.to_document_string

  wisp.html_response(doc, 200)
}

pub fn error_page(
  title: String,
  message: String,
  status: Int,
) -> wisp.Response {
  let doc =
    html.html([attribute.lang("ja"), attribute.class("bg-white")], [
      html.head([], [
        html.meta([attribute.charset("utf-8")]),
        html.meta([
          attribute.name("viewport"),
          attribute.content("width=device-width, initial-scale=1"),
        ]),
        html.title([], title <> " - lote"),
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
            html.main([attribute.class("max-w-md px-4 py-6")], [
              html.h1(
                [attribute.class("mb-2 text-sm font-semibold text-neutral-950")],
                [html.text(title)],
              ),
              html.p(
                [
                  attribute.class(
                    "border border-red-300 bg-red-50 px-3 py-2 text-xs text-red-700",
                  ),
                ],
                [html.text(message)],
              ),
            ]),
          ],
        ),
      ]),
    ])
    |> element.to_document_string

  wisp.html_response(doc, status)
}

fn render_scopes_section(
  requested_scopes: Set(Scope),
  existing_scopes: Set(Scope),
) -> element.Element(Nil) {
  let ordered_requested =
    scope.all()
    |> list.filter(fn(s) { set.contains(requested_scopes, s) })

  case set.is_empty(existing_scopes) {
    True ->
      html.div([], [
        html.h2(
          [attribute.class("mb-2 text-xs font-semibold text-neutral-950")],
          [html.text("Requested permissions")],
        ),
        html.ul(
          [
            attribute.class(
              "divide-y divide-neutral-200 border border-neutral-200",
            ),
          ],
          list.map(ordered_requested, render_scope_row(_, None)),
        ),
      ])

    False -> {
      let newly_requested =
        list.filter(ordered_requested, fn(s) {
          !set.contains(existing_scopes, s)
        })
      let already_approved =
        scope.all()
        |> list.filter(fn(s) { set.contains(existing_scopes, s) })

      let new_block = case newly_requested {
        [] -> element.none()
        items ->
          html.div([attribute.class("mb-3")], [
            html.h2(
              [attribute.class("mb-2 text-xs font-semibold text-neutral-950")],
              [html.text("Additional permissions requested")],
            ),
            html.ul(
              [
                attribute.class(
                  "divide-y divide-neutral-200 border border-neutral-950",
                ),
              ],
              list.map(items, render_scope_row(_, Some(BadgeNew))),
            ),
          ])
      }

      html.div([], [
        new_block,
        html.div([], [
          html.h2(
            [attribute.class("mb-2 text-xs font-semibold text-neutral-600")],
            [html.text("Previously approved permissions")],
          ),
          html.ul(
            [
              attribute.class(
                "divide-y divide-neutral-200 border border-neutral-200",
              ),
            ],
            list.map(already_approved, render_scope_row(_, Some(BadgeApproved))),
          ),
        ]),
      ])
    }
  }
}

type ScopeBadge {
  BadgeNew
  BadgeApproved
}

fn render_scope_row(
  s: Scope,
  badge: Option(ScopeBadge),
) -> element.Element(Nil) {
  let badge_el = case badge {
    None -> element.none()
    Some(BadgeNew) ->
      html.span(
        [
          attribute.class(
            "border border-neutral-950 bg-neutral-950 px-1.5 py-0.5 font-mono text-[10px] font-medium text-white",
          ),
        ],
        [html.text("New")],
      )
    Some(BadgeApproved) ->
      html.span(
        [
          attribute.class(
            "border border-neutral-300 bg-neutral-100 px-1.5 py-0.5 font-mono text-[10px] text-neutral-600",
          ),
        ],
        [html.text("Approved")],
      )
  }

  html.li([attribute.class("px-3 py-2.5")], [
    html.div([attribute.class("flex items-center justify-between gap-2")], [
      html.span(
        [attribute.class("font-mono text-xs font-medium text-neutral-950")],
        [
          html.text(scope.to_string(s)),
        ],
      ),
      badge_el,
    ]),
    html.p([attribute.class("mt-0.5 text-xs text-neutral-600")], [
      html.text(scope_description(s)),
    ]),
  ])
}

fn scope_description(s: Scope) -> String {
  case s {
    scope.OpenId -> "Verify your identity (subject identifier)"
    scope.Profile -> "Read your profile information (display name)"
    scope.OfflineAccess ->
      "Maintain access when you are offline (issue refresh tokens)"
    scope.PostsRead -> "Read posts"
    scope.PostsWrite -> "Create new posts on your behalf"
    scope.PostsDelete -> "Delete your posts"
  }
}

fn render_cimd_callout(
  params: ConsentParams,
  redirect_host: String,
) -> element.Element(Nil) {
  case params.client.kind {
    client.Cimd -> {
      let cimd_authority =
        cimd.client_id_authority(params.client.client_id)
        |> option.unwrap(params.client.client_id)
      let cimd_origin = "https://" <> string.lowercase(cimd_authority)
      let cross_domain_warning = case
        normalized_web_origin(params.redirect_uri) == Some(cimd_origin)
      {
        True -> element.none()
        False ->
          html.p(
            [
              attribute.class(
                "border-t border-neutral-300 pt-2 text-xs font-medium text-neutral-950",
              ),
            ],
            [
              html.text(
                "Callback origin ("
                <> redirect_host
                <> ") differs from client domain ("
                <> cimd_authority
                <> ").",
              ),
            ],
          )
      }

      html.div(
        [
          attribute.role("region"),
          attribute.attribute("aria-label", "External client metadata notice"),
          attribute.class(
            "mb-4 border-2 border-neutral-950 bg-neutral-50 px-3 py-2.5",
          ),
        ],
        [
          html.p([attribute.class("text-xs font-semibold text-neutral-950")], [
            html.text("Unregistered external client"),
          ]),
          html.p([attribute.class("mt-1 text-xs text-neutral-700")], [
            html.text(
              "This application was loaded dynamically from its domain metadata document rather than pre-registered on lote. Verify you trust this domain before authorizing.",
            ),
          ]),
          html.div(
            [
              attribute.class(
                "mt-2.5 flex flex-col gap-1.5 border-t border-neutral-300 pt-2 text-xs",
              ),
            ],
            [
              html.div(
                [
                  attribute.class("flex items-baseline justify-between gap-3"),
                ],
                [
                  html.span([attribute.class("shrink-0 text-neutral-600")], [
                    html.text("Client domain"),
                  ]),
                  html.span(
                    [
                      attribute.class(
                        "break-all font-mono font-bold text-neutral-950",
                      ),
                    ],
                    [html.text(cimd_authority)],
                  ),
                ],
              ),
              html.div(
                [
                  attribute.class("flex items-baseline justify-between gap-3"),
                ],
                [
                  html.span([attribute.class("shrink-0 text-neutral-600")], [
                    html.text("Metadata URL"),
                  ]),
                  html.span(
                    [
                      attribute.class("break-all font-mono text-neutral-900"),
                    ],
                    [html.text(params.client.client_id)],
                  ),
                ],
              ),
              cross_domain_warning,
            ],
          ),
        ],
      )
    }
    _ -> element.none()
  }
}

fn client_kind_label(kind: client.Kind) -> String {
  case kind {
    client.ConfidentialApp -> "Confidential App"
    client.PublicApp -> "Public App"
    client.SubordinateBot -> "Subordinate Bot"
    client.Cimd -> "Client ID Metadata Document"
  }
}

fn redirect_host_label(redirect_uri: String) -> String {
  case uri.parse(redirect_uri) {
    Ok(parsed) ->
      case parsed.scheme, parsed.host, parsed.port {
        Some(scheme), Some(host), Some(port) ->
          scheme <> "://" <> format_host(host) <> ":" <> int.to_string(port)
        Some(scheme), Some(host), None -> scheme <> "://" <> format_host(host)
        _, Some(host), _ -> format_host(host)
        _, None, _ -> redirect_uri
      }
    Error(_) -> redirect_uri
  }
}

fn normalized_web_origin(raw_uri: String) -> Option(String) {
  case uri.parse(raw_uri) {
    Ok(parsed) ->
      case parsed.scheme, parsed.host {
        Some(raw_scheme), Some(raw_host) -> {
          let scheme = string.lowercase(raw_scheme)
          let host = string.lowercase(format_host(raw_host))
          case scheme, parsed.port {
            "https", None | "https", Some(443) -> Some("https://" <> host)
            "http", None | "http", Some(80) -> Some("http://" <> host)
            _, Some(port) ->
              Some(scheme <> "://" <> host <> ":" <> int.to_string(port))
            _, None -> Some(scheme <> "://" <> host)
          }
        }
        _, _ -> None
      }
    Error(_) -> None
  }
}

fn format_host(host: String) -> String {
  case string.contains(host, ":") && !string.starts_with(host, "[") {
    True -> "[" <> host <> "]"
    False -> host
  }
}

fn hidden_input(name: String, value: String) -> element.Element(Nil) {
  html.input([
    attribute.type_("hidden"),
    attribute.name(name),
    attribute.value(value),
  ])
}

fn optional_hidden_input(
  name: String,
  value: Option(String),
) -> element.Element(Nil) {
  case value {
    Some(v) if v != "" -> hidden_input(name, v)
    _ -> element.none()
  }
}
