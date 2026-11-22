import gleam/erlang/process
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/string
import lote/auth/user.{type AuthUser}
import lote/db/post_repo
import lote/realtime/pubsub.{type PubSub}
import lustre
import lustre/attribute
import lustre/effect.{type Effect}
import lustre/element.{type Element}
import lustre/element/html
import lustre/element/keyed
import lustre/event
import lustre/server_component
import pog

pub type Post {
  Post(id: Int, author_name: String, body: String)
}

pub type Flags {
  Flags(db: pog.Connection, pubsub: PubSub(Post), user: Option(AuthUser))
}

pub type Model {
  Model(
    db: pog.Connection,
    pubsub: PubSub(Post),
    user: Option(AuthUser),
    posts: List(Post),
    form_key: Int,
  )
}

pub type Msg {
  UserSubmittedForm(List(#(String, String)))
  PostCreated(Post)
}

pub fn app() -> lustre.App(Flags, Model, Msg) {
  lustre.application(init:, update:, view:)
}

fn init(flags: Flags) -> #(Model, Effect(Msg)) {
  let posts = case post_repo.list_recent(flags.db, 50) {
    Ok(rows) ->
      list.map(rows, fn(row) {
        Post(id: row.id, author_name: row.author_name, body: row.body)
      })
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
      posts:,
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
                effect.from(fn(_dispatch) {
                  case post_repo.create(model.db, auth_user.id, body) {
                    Ok(row) -> {
                      let post =
                        Post(
                          id: row.id,
                          author_name: auth_user.name,
                          body: row.body,
                        )
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

    PostCreated(post) -> #(
      Model(..model, posts: [post, ..model.posts]),
      effect.none(),
    )
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
            account_bar(model.user),
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
          html.span([attribute.class("font-mono text-xs text-neutral-400")], [
            html.text(int.to_string(list.length(model.posts)) <> " posts"),
          ]),
        ],
      ),
      feed(model.posts),
    ])

  html.div([attribute.class("flex min-h-screen flex-col md:flex-row")], [
    sidebar,
    timeline_pane,
  ])
}

fn account_bar(current_user: Option(AuthUser)) -> Element(Msg) {
  case current_user {
    Some(u) ->
      html.div([attribute.class("flex items-center gap-3 text-xs")], [
        html.span([attribute.class("font-medium text-neutral-900")], [
          html.text(u.name),
        ]),
        html.form([attribute.method("post"), attribute.action("/auth/logout")], [
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
  html.li([attribute.class("px-4 py-3 hover:bg-neutral-50/70")], [
    html.div([attribute.class("flex items-baseline gap-2 text-xs")], [
      html.span([attribute.class("font-semibold text-neutral-950")], [
        html.text(post.author_name),
      ]),
      html.span([attribute.class("font-mono text-neutral-400")], [
        html.text("#" <> int.to_string(post.id)),
      ]),
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
