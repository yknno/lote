import gleam/erlang/process
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/string
import gleam/time/calendar
import gleam/time/timestamp.{type Timestamp}
import lote/auth/user.{type AuthUser}
import lote/db/post_repo
import lote/realtime/pubsub.{type PubSub}
import lote/web/csrf
import lustre
import lustre/attribute
import lustre/effect.{type Effect}
import lustre/element.{type Element}
import lustre/element/html
import lustre/element/keyed
import lustre/event
import lustre/server_component
import pog

const recent_posts_limit = 50

pub type Post {
  Post(id: Int, author_name: String, body: String, created_at: Timestamp)
}

pub type Flags {
  Flags(
    db: pog.Connection,
    pubsub: PubSub(Post),
    user: Option(AuthUser),
    csrf_token: String,
  )
}

pub type Model {
  Model(
    db: pog.Connection,
    pubsub: PubSub(Post),
    user: Option(AuthUser),
    csrf_token: String,
    posts: List(Post),
    pending_count: Int,
    auto_refresh: Bool,
    form_key: Int,
  )
}

pub type Msg {
  UserSubmittedForm(List(#(String, String)))
  UserClickedRefresh
  UserToggledAutoRefresh
  PostsReloaded(List(Post))
  PostCreated(Post)
}

pub fn app() -> lustre.App(Flags, Model, Msg) {
  lustre.application(init:, update:, view:)
}

fn load_recent_posts(db: pog.Connection) -> Result(List(Post), pog.QueryError) {
  case post_repo.list_recent(db, recent_posts_limit) {
    Ok(rows) ->
      Ok(
        list.map(rows, fn(row) {
          Post(
            id: row.id,
            author_name: row.author_name,
            body: row.body,
            created_at: row.created_at,
          )
        }),
      )
    Error(err) -> Error(err)
  }
}

fn latest_post_id(posts: List(Post)) -> Int {
  case posts {
    [first, ..] -> first.id
    [] -> 0
  }
}

fn init(flags: Flags) -> #(Model, Effect(Msg)) {
  let posts = case load_recent_posts(flags.db) {
    Ok(posts) -> posts
    Error(_) -> []
  }

  let subscribe_effect =
    server_component.select(fn(_dispatch, subject) {
      pubsub.subscribe(flags.pubsub, subject)
      process.new_selector()
      |> process.select_map(subject, PostCreated)
    })

  #(
    Model(
      db: flags.db,
      pubsub: flags.pubsub,
      user: flags.user,
      csrf_token: flags.csrf_token,
      posts:,
      pending_count: 0,
      auto_refresh: False,
      form_key: 0,
    ),
    subscribe_effect,
  )
}

fn update(model: Model, msg: Msg) -> #(Model, Effect(Msg)) {
  case msg {
    UserSubmittedForm(fields) -> {
      case model.user {
        None -> #(model, effect.none())
        Some(auth_user) -> {
          let body = case list.key_find(fields, "body") {
            Ok(value) -> string.trim(value)
            Error(_) -> ""
          }

          case body {
            "" -> #(model, effect.none())
            _ -> {
              let save_and_publish =
                effect.from(fn(dispatch) {
                  case post_repo.create(model.db, auth_user.id, body) {
                    Ok(row) -> {
                      let post =
                        Post(
                          id: row.id,
                          author_name: auth_user.name,
                          body: row.body,
                          created_at: row.created_at,
                        )
                      case load_recent_posts(model.db) {
                        Ok(posts) -> dispatch(PostsReloaded(posts))
                        Error(_) -> Nil
                      }
                      pubsub.publish(model.pubsub, post)
                    }
                    Error(_) -> Nil
                  }
                })
              #(Model(..model, form_key: model.form_key + 1), save_and_publish)
            }
          }
        }
      }
    }

    UserClickedRefresh ->
      case load_recent_posts(model.db) {
        Ok(posts) -> #(Model(..model, posts:, pending_count: 0), effect.none())
        Error(_) -> #(model, effect.none())
      }

    UserToggledAutoRefresh ->
      case model.auto_refresh {
        True -> #(Model(..model, auto_refresh: False), effect.none())
        False ->
          case model.pending_count > 0 {
            True ->
              case load_recent_posts(model.db) {
                Ok(posts) -> #(
                  Model(..model, posts:, pending_count: 0, auto_refresh: True),
                  effect.none(),
                )
                Error(_) -> #(Model(..model, auto_refresh: True), effect.none())
              }
            False -> #(Model(..model, auto_refresh: True), effect.none())
          }
      }

    PostsReloaded(posts) -> #(
      Model(..model, posts:, pending_count: 0),
      effect.none(),
    )

    PostCreated(post) ->
      case post.id <= latest_post_id(model.posts) {
        True -> #(model, effect.none())
        False ->
          case model.auto_refresh {
            True -> #(
              Model(
                ..model,
                posts: list.take([post, ..model.posts], recent_posts_limit),
                pending_count: 0,
              ),
              effect.none(),
            )
            False -> #(
              Model(..model, pending_count: model.pending_count + 1),
              effect.none(),
            )
          }
      }
  }
}

fn view(model: Model) -> Element(Msg) {
  let sidebar =
    html.aside(
      [
        attribute.class(
          "flex w-full shrink-0 flex-col border-b border-neutral-200 bg-neutral-50/60 md:sticky md:top-0 md:h-screen md:w-80 md:border-r md:border-b-0",
        ),
      ],
      [
        html.div(
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
            account_bar(model.user, model.csrf_token),
          ],
        ),
        composer_pane(model),
      ],
    )

  let timeline_pane =
    html.main([attribute.class("flex min-w-0 flex-1 flex-col")], [
      html.div(
        [
          attribute.class(
            "sticky top-0 z-10 flex h-11 items-center justify-between border-b border-neutral-200 bg-white px-4",
          ),
        ],
        [
          html.h1(
            [
              attribute.class(
                "text-xs font-semibold uppercase tracking-wider text-neutral-600",
              ),
            ],
            [html.text("Timeline")],
          ),
          html.div([attribute.class("flex items-center gap-3")], [
            auto_refresh_toggle(model.auto_refresh),
            html.span([attribute.class("font-mono text-xs text-neutral-400")], [
              html.text(int.to_string(list.length(model.posts)) <> " posts"),
            ]),
          ]),
        ],
      ),
      pending_banner(model.pending_count),
      feed(model.posts),
    ])

  html.div([attribute.class("flex min-h-screen flex-col md:flex-row")], [
    sidebar,
    timeline_pane,
  ])
}

fn auto_refresh_toggle(enabled: Bool) -> Element(Msg) {
  let #(button_class, dot_class, pressed) = case enabled {
    True -> #(
      "inline-flex cursor-pointer items-center gap-1.5 border border-neutral-950 bg-neutral-950 px-2 py-0.5 text-xs font-medium text-white hover:bg-neutral-800",
      "inline-block h-1.5 w-1.5 rounded-full bg-emerald-400",
      "true",
    )
    False -> #(
      "inline-flex cursor-pointer items-center gap-1.5 border border-neutral-300 bg-white px-2 py-0.5 text-xs font-medium text-neutral-600 hover:border-neutral-950 hover:text-neutral-950",
      "inline-block h-1.5 w-1.5 rounded-full bg-neutral-300",
      "false",
    )
  }

  html.button(
    [
      attribute.type_("button"),
      attribute.attribute("aria-pressed", pressed),
      event.on_click(UserToggledAutoRefresh),
      attribute.class(button_class),
    ],
    [
      html.span([attribute.class(dot_class)], []),
      html.text("Live"),
    ],
  )
}

fn pending_banner(pending_count: Int) -> Element(Msg) {
  case pending_count {
    count if count > 0 -> {
      let label = case count {
        1 -> "Show 1 new post"
        n -> "Show " <> int.to_string(n) <> " new posts"
      }
      html.button(
        [
          attribute.type_("button"),
          event.on_click(UserClickedRefresh),
          attribute.class(
            "w-full cursor-pointer border-b border-neutral-200 bg-neutral-50 px-4 py-2 text-center text-xs font-medium text-neutral-900 hover:bg-neutral-100",
          ),
        ],
        [html.text(label)],
      )
    }
    _ -> element.none()
  }
}

fn account_bar(
  current_user: Option(AuthUser),
  csrf_token: String,
) -> Element(Msg) {
  case current_user {
    Some(u) ->
      html.div([attribute.class("flex items-center gap-3 text-xs")], [
        html.span([attribute.class("font-medium text-neutral-900")], [
          html.text(u.name),
        ]),
        html.form([attribute.method("post"), attribute.action("/auth/logout")], [
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
        ]),
      ])
    None ->
      html.a(
        [
          attribute.href("/auth/login"),
          attribute.class(
            "text-xs font-medium text-neutral-950 underline-offset-2 hover:underline",
          ),
        ],
        [html.text("Log in")],
      )
  }
}

fn composer_pane(model: Model) -> Element(Msg) {
  case model.user {
    Some(_) ->
      keyed.fragment([
        #(
          "post-form-" <> int.to_string(model.form_key),
          html.form(
            [
              event.on_submit(UserSubmittedForm),
              attribute.class("flex flex-col gap-3 p-4"),
            ],
            [
              html.textarea(
                [
                  attribute.name("body"),
                  attribute.rows(4),
                  attribute.placeholder("What is on your mind?"),
                  attribute.required(True),
                  attribute.class(
                    "block w-full resize-none border border-neutral-300 bg-white p-2.5 text-sm leading-normal text-neutral-950 placeholder:text-neutral-400 focus:border-neutral-950 focus:outline-none",
                  ),
                ],
                "",
              ),
              html.div([attribute.class("flex justify-end")], [
                html.button(
                  [
                    attribute.type_("submit"),
                    attribute.class(
                      "cursor-pointer bg-neutral-950 px-4 py-1.5 text-xs font-medium text-white hover:bg-neutral-800",
                    ),
                  ],
                  [html.text("Post")],
                ),
              ]),
            ],
          ),
        ),
      ])

    None ->
      html.div([attribute.class("p-4 text-xs text-neutral-600")], [
        html.p([], [html.text("Sign in to publish posts.")]),
        html.a(
          [
            attribute.href("/auth/login"),
            attribute.class(
              "mt-3 inline-block bg-neutral-950 px-3.5 py-1.5 font-medium text-white hover:bg-neutral-800",
            ),
          ],
          [html.text("Log in")],
        ),
      ])
  }
}

fn feed(posts: List(Post)) -> Element(Msg) {
  case posts {
    [] ->
      html.p([attribute.class("px-4 py-8 text-xs text-neutral-400")], [
        html.text("No posts yet."),
      ])

    _ ->
      html.ul(
        [attribute.class("divide-y divide-neutral-200")],
        list.map(posts, post_row),
      )
  }
}

fn post_row(post: Post) -> Element(Msg) {
  let created_iso = timestamp.to_rfc3339(post.created_at, calendar.utc_offset)

  html.li([attribute.class("px-4 py-3 hover:bg-neutral-50/70")], [
    html.div([attribute.class("flex items-baseline gap-2 text-xs")], [
      html.span([attribute.class("font-semibold text-neutral-950")], [
        html.text(post.author_name),
      ]),
      html.span([attribute.class("font-mono text-neutral-400")], [
        html.text("#" <> int.to_string(post.id)),
      ]),
      element.element(
        "lote-time",
        [
          attribute.attribute("datetime", created_iso),
          attribute.class(
            "ml-auto shrink-0 font-mono text-xs text-neutral-400 tabular-nums",
          ),
        ],
        [
          html.time([attribute.datetime(created_iso)], [
            html.text(format_utc_fallback(post.created_at)),
          ]),
        ],
      ),
    ]),
    html.p(
      [
        attribute.class(
          "mt-1 whitespace-pre-wrap break-words text-sm leading-relaxed text-neutral-800",
        ),
      ],
      [html.text(post.body)],
    ),
  ])
}

fn format_utc_fallback(ts: Timestamp) -> String {
  let #(date, time) = timestamp.to_calendar(ts, calendar.utc_offset)
  int.to_string(date.year)
  <> "-"
  <> pad2(calendar.month_to_int(date.month))
  <> "-"
  <> pad2(date.day)
  <> " "
  <> pad2(time.hours)
  <> ":"
  <> pad2(time.minutes)
  <> " UTC"
}

fn pad2(n: Int) -> String {
  case n < 10 {
    True -> "0" <> int.to_string(n)
    False -> int.to_string(n)
  }
}
