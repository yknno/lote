import gleam/dynamic/decode
import gleam/erlang/process
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/order
import gleam/result
import gleam/string
import gleam/time/timestamp.{type Timestamp}
import lote/auth/user.{type AuthUser}
import lote/db/post_repo
import lote/realtime/pubsub.{type PubSub}
import lote/web/csrf
import lote/web/time as web_time
import lustre
import lustre/attribute
import lustre/effect.{type Effect}
import lustre/element.{type Element}
import lustre/element/html
import lustre/element/keyed
import lustre/event
import lustre/server_component
import pog

pub const page_size = 20

pub type Post {
  Post(
    id: String,
    user_id: Int,
    author_name: String,
    body: String,
    created_at: Timestamp,
  )
}

pub type PostEvent {
  Created(Post)
  Deleted(String)
}

pub fn encode_post_event(event: PostEvent) -> String {
  case event {
    Created(post) -> {
      let #(seconds, nanoseconds) =
        timestamp.to_unix_seconds_and_nanoseconds(post.created_at)
      json.object([
        #("type", json.string("created")),
        #("id", json.string(post.id)),
        #("user_id", json.int(post.user_id)),
        #("author_name", json.string(post.author_name)),
        #("body", json.string(post.body)),
        #("created_at_seconds", json.int(seconds)),
        #("created_at_nanoseconds", json.int(nanoseconds)),
      ])
      |> json.to_string
    }
    Deleted(id) ->
      json.object([
        #("type", json.string("deleted")),
        #("id", json.string(id)),
      ])
      |> json.to_string
  }
}

pub fn decode_post_event(payload: String) -> Result(PostEvent, Nil) {
  let decoder = {
    use event_type <- decode.field("type", decode.string)
    case event_type {
      "created" -> {
        use id <- decode.field("id", decode.string)
        use user_id <- decode.field("user_id", decode.int)
        use author_name <- decode.field("author_name", decode.string)
        use body <- decode.field("body", decode.string)
        use seconds <- decode.field("created_at_seconds", decode.int)
        use nanoseconds <- decode.field("created_at_nanoseconds", decode.int)
        let created_at =
          timestamp.from_unix_seconds_and_nanoseconds(seconds, nanoseconds)
        decode.success(
          Created(Post(id:, user_id:, author_name:, body:, created_at:)),
        )
      }
      "deleted" -> {
        use id <- decode.field("id", decode.string)
        decode.success(Deleted(id))
      }
      _ -> decode.failure(Deleted(""), "PostEvent")
    }
  }

  json.parse(payload, decoder)
  |> result.replace_error(Nil)
}

pub type Flags {
  Flags(
    db: pog.Connection,
    pubsub: PubSub(PostEvent),
    user: Option(AuthUser),
    csrf_token: String,
  )
}

pub type Model {
  Model(
    db: pog.Connection,
    pubsub: PubSub(PostEvent),
    user: Option(AuthUser),
    csrf_token: String,
    posts: List(Post),
    has_more: Bool,
    loading_more: Bool,
    pending_count: Int,
    auto_refresh: Bool,
    confirming_delete: Option(String),
    form_key: Int,
    form_error: Option(String),
  )
}

pub type Msg {
  UserSubmittedForm(List(#(String, String)))
  UserClickedRefresh
  UserToggledAutoRefresh
  UserRequestedLoadMore
  UserRequestedDelete(String)
  UserCanceledDelete
  UserConfirmedDelete(String)
  PostsReloaded(List(Post), Bool)
  OlderPostsLoaded(cursor: String, posts: List(Post), has_more: Bool)
  OlderPostsLoadFailed
  PostCreated(Post)
  PostDeleted(String)
}

pub fn app() -> lustre.App(Flags, Model, Msg) {
  lustre.application(init:, update:, view:)
}

fn rows_to_page(rows: List(post_repo.PostRow)) -> #(List(Post), Bool) {
  let has_more = list.length(rows) > page_size
  let posts =
    rows
    |> list.take(page_size)
    |> list.map(fn(row) {
      Post(
        id: row.id,
        user_id: row.user_id,
        author_name: row.author_name,
        body: row.body,
        created_at: row.created_at,
      )
    })
  #(posts, has_more)
}

fn load_recent_page(
  db: pog.Connection,
) -> Result(#(List(Post), Bool), pog.QueryError) {
  case post_repo.list_recent(db, page_size + 1) {
    Ok(rows) -> Ok(rows_to_page(rows))
    Error(err) -> Error(err)
  }
}

fn load_older_page(
  db: pog.Connection,
  before_id: String,
) -> Result(#(List(Post), Bool), pog.QueryError) {
  case post_repo.list_before(db, before_id, page_size + 1) {
    Ok(rows) -> Ok(rows_to_page(rows))
    Error(err) -> Error(err)
  }
}

fn last_post_id(posts: List(Post)) -> Option(String) {
  case list.last(posts) {
    Ok(post) -> Some(post.id)
    Error(_) -> None
  }
}

fn is_newer_than_loaded(post: Post, loaded: List(Post)) -> Bool {
  case loaded {
    [first, ..] -> string.compare(post.id, first.id) == order.Gt
    [] -> True
  }
}

pub fn init(flags: Flags) -> #(Model, Effect(Msg)) {
  let #(posts, has_more) = case load_recent_page(flags.db) {
    Ok(page) -> page
    Error(_) -> #([], False)
  }

  let subscribe_effect =
    server_component.select(fn(_dispatch, subject) {
      pubsub.subscribe(flags.pubsub, subject)
      process.new_selector()
      |> process.select_map(subject, fn(ev) {
        case ev {
          Created(post) -> PostCreated(post)
          Deleted(id) -> PostDeleted(id)
        }
      })
    })

  #(
    Model(
      db: flags.db,
      pubsub: flags.pubsub,
      user: flags.user,
      csrf_token: flags.csrf_token,
      posts:,
      has_more:,
      loading_more: False,
      pending_count: 0,
      auto_refresh: False,
      confirming_delete: None,
      form_key: 0,
      form_error: None,
    ),
    subscribe_effect,
  )
}

pub fn update(model: Model, msg: Msg) -> #(Model, Effect(Msg)) {
  case msg {
    UserSubmittedForm(fields) -> {
      case model.user {
        None -> #(model, effect.none())
        Some(auth_user) -> {
          let raw_body = case list.key_find(fields, "body") {
            Ok(value) -> value
            Error(_) -> ""
          }

          case post_repo.validate_body(raw_body) {
            Error(post_repo.EmptyBody) -> #(
              Model(..model, form_error: None),
              effect.none(),
            )

            Error(post_repo.BodyTooLong(length:, max:)) -> #(
              Model(
                ..model,
                form_error: Some(
                  "Post must be "
                  <> int.to_string(max)
                  <> " characters or fewer ("
                  <> int.to_string(length)
                  <> " / "
                  <> int.to_string(max)
                  <> ").",
                ),
              ),
              effect.none(),
            )

            Ok(body) -> {
              let save_and_publish =
                effect.from(fn(dispatch) {
                  case post_repo.create(model.db, auth_user.id, body) {
                    Ok(row) -> {
                      let post =
                        Post(
                          id: row.id,
                          user_id: auth_user.id,
                          author_name: auth_user.name,
                          body: row.body,
                          created_at: row.created_at,
                        )
                      case load_recent_page(model.db) {
                        Ok(#(posts, has_more)) ->
                          dispatch(PostsReloaded(posts, has_more))
                        Error(_) -> Nil
                      }
                      pubsub.publish(model.pubsub, Created(post))
                    }
                    Error(_) -> Nil
                  }
                })
              #(
                Model(..model, form_key: model.form_key + 1, form_error: None),
                save_and_publish,
              )
            }
          }
        }
      }
    }

    UserClickedRefresh ->
      case load_recent_page(model.db) {
        Ok(#(posts, has_more)) -> #(
          Model(
            ..model,
            posts:,
            has_more:,
            loading_more: False,
            pending_count: 0,
          ),
          effect.none(),
        )
        Error(_) -> #(model, effect.none())
      }

    UserToggledAutoRefresh ->
      case model.auto_refresh {
        True -> #(Model(..model, auto_refresh: False), effect.none())
        False ->
          case model.pending_count > 0 {
            True ->
              case load_recent_page(model.db) {
                Ok(#(posts, has_more)) -> #(
                  Model(
                    ..model,
                    posts:,
                    has_more:,
                    loading_more: False,
                    pending_count: 0,
                    auto_refresh: True,
                  ),
                  effect.none(),
                )
                Error(_) -> #(Model(..model, auto_refresh: True), effect.none())
              }
            False -> #(Model(..model, auto_refresh: True), effect.none())
          }
      }

    UserRequestedLoadMore ->
      case model.loading_more || !model.has_more {
        True -> #(model, effect.none())
        False ->
          case last_post_id(model.posts) {
            None -> #(
              Model(..model, has_more: False, loading_more: False),
              effect.none(),
            )
            Some(cursor) -> {
              let load_effect =
                effect.from(fn(dispatch) {
                  case load_older_page(model.db, cursor) {
                    Ok(#(older, has_more)) ->
                      dispatch(OlderPostsLoaded(
                        cursor:,
                        posts: older,
                        has_more:,
                      ))
                    Error(_) -> dispatch(OlderPostsLoadFailed)
                  }
                })
              #(Model(..model, loading_more: True), load_effect)
            }
          }
      }

    UserRequestedDelete(post_id) ->
      case model.user {
        Some(auth_user) ->
          case
            list.any(model.posts, fn(p) {
              p.id == post_id && p.user_id == auth_user.id
            })
          {
            True -> #(
              Model(..model, confirming_delete: Some(post_id)),
              effect.none(),
            )
            False -> #(model, effect.none())
          }
        None -> #(model, effect.none())
      }

    UserCanceledDelete -> #(
      Model(..model, confirming_delete: None),
      effect.none(),
    )

    UserConfirmedDelete(post_id) ->
      case model.user {
        None -> #(Model(..model, confirming_delete: None), effect.none())
        Some(auth_user) -> {
          let delete_and_publish =
            effect.from(fn(_dispatch) {
              case post_repo.delete(model.db, post_id, auth_user.id) {
                Ok(True) -> pubsub.publish(model.pubsub, Deleted(post_id))
                Ok(False) | Error(_) -> Nil
              }
            })
          #(Model(..model, confirming_delete: None), delete_and_publish)
        }
      }

    PostsReloaded(posts, has_more) -> #(
      Model(..model, posts:, has_more:, loading_more: False, pending_count: 0),
      effect.none(),
    )

    OlderPostsLoaded(cursor, older, has_more) ->
      case last_post_id(model.posts) == Some(cursor) {
        True -> #(
          Model(
            ..model,
            posts: list.append(model.posts, older),
            has_more:,
            loading_more: False,
          ),
          effect.none(),
        )
        False -> #(Model(..model, loading_more: False), effect.none())
      }

    OlderPostsLoadFailed -> #(
      Model(..model, loading_more: False),
      effect.none(),
    )

    PostCreated(post) ->
      case is_newer_than_loaded(post, model.posts) {
        False -> #(model, effect.none())
        True ->
          case model.auto_refresh {
            True -> #(
              Model(..model, posts: [post, ..model.posts], pending_count: 0),
              effect.none(),
            )
            False -> #(
              Model(..model, pending_count: model.pending_count + 1),
              effect.none(),
            )
          }
      }

    PostDeleted(post_id) -> {
      let confirming_delete = case model.confirming_delete {
        Some(id) if id == post_id -> None
        other -> other
      }
      let remaining = list.filter(model.posts, fn(p) { p.id != post_id })
      case remaining, model.has_more {
        [], True -> {
          let reload_effect =
            effect.from(fn(dispatch) {
              case load_recent_page(model.db) {
                Ok(#(posts, has_more)) ->
                  dispatch(PostsReloaded(posts, has_more))
                Error(_) -> Nil
              }
            })
          #(Model(..model, posts: remaining, confirming_delete:), reload_effect)
        }
        _, _ -> #(
          Model(..model, posts: remaining, confirming_delete:),
          effect.none(),
        )
      }
    }
  }
}

pub fn view(model: Model) -> Element(Msg) {
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

  let post_count_label =
    int.to_string(list.length(model.posts))
    <> case model.has_more {
      True -> "+ posts"
      False -> " posts"
    }

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
              html.text(post_count_label),
            ]),
          ]),
        ],
      ),
      pending_banner(model.pending_count),
      feed(model.posts, model.user, model.confirming_delete),
      load_more_footer(model),
    ])

  html.div([attribute.class("flex min-h-screen flex-col md:flex-row")], [
    sidebar,
    timeline_pane,
  ])
}

fn load_more_footer(model: Model) -> Element(Msg) {
  case model.has_more, last_post_id(model.posts) {
    True, Some(cursor) ->
      element.element(
        "lote-sentinel",
        [
          attribute.class("block border-t border-neutral-200"),
          attribute.attribute("cursor", cursor),
          attribute.attribute("aria-busy", case model.loading_more {
            True -> "true"
            False -> "false"
          }),
          case model.loading_more {
            True -> attribute.attribute("disabled", "")
            False -> attribute.none()
          },
          event.on("load-more", decode.success(UserRequestedLoadMore)),
        ],
        [
          case model.loading_more {
            True ->
              html.p(
                [
                  attribute.class(
                    "px-4 py-3 text-center font-mono text-xs text-neutral-400",
                  ),
                ],
                [html.text("Loading...")],
              )
            False ->
              html.button(
                [
                  attribute.type_("button"),
                  event.on_click(UserRequestedLoadMore),
                  attribute.class(
                    "w-full cursor-pointer px-4 py-3 text-center text-xs text-neutral-500 hover:bg-neutral-50 hover:text-neutral-950",
                  ),
                ],
                [html.text("Load older posts")],
              )
          },
        ],
      )
    _, _ -> element.none()
  }
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
        html.a(
          [
            attribute.href("/sessions"),
            attribute.class(
              "text-neutral-500 underline-offset-2 hover:text-neutral-950 hover:underline",
            ),
          ],
          [html.text("Sessions")],
        ),
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
    Some(_) -> {
      let max_str = int.to_string(post_repo.max_body_length)
      let error_el = case model.form_error {
        Some(message) ->
          html.p(
            [
              attribute.role("alert"),
              attribute.class("text-xs text-red-600"),
            ],
            [html.text(message)],
          )
        None -> element.none()
      }

      keyed.fragment([
        #(
          "post-form-" <> int.to_string(model.form_key),
          html.form(
            [
              event.on_submit(UserSubmittedForm),
              attribute.class("flex flex-col gap-3 p-4"),
            ],
            [
              element.element(
                "lote-composer",
                [
                  attribute.attribute("max", max_str),
                  attribute.class("flex flex-col gap-3"),
                ],
                [
                  html.textarea(
                    [
                      attribute.name("body"),
                      attribute.rows(4),
                      attribute.placeholder("What is on your mind?"),
                      attribute.required(True),
                      attribute.class(
                        "block w-full resize-none border border-neutral-300 bg-white p-2.5 text-sm leading-normal text-neutral-950 placeholder:text-neutral-400 focus:border-neutral-950 focus:outline-none aria-[invalid=true]:border-red-500 aria-[invalid=true]:focus:border-red-600",
                      ),
                    ],
                    "",
                  ),
                  html.div(
                    [attribute.class("flex items-center justify-between gap-2")],
                    [
                      html.span(
                        [
                          attribute.attribute("data-char-counter", ""),
                          attribute.attribute("data-state", "ok"),
                          attribute.attribute("aria-live", "polite"),
                          attribute.class(
                            "font-mono text-xs tabular-nums text-neutral-400 data-[state=near]:text-neutral-700 data-[state=over]:font-medium data-[state=over]:text-red-600",
                          ),
                        ],
                        [html.text("0 / " <> max_str)],
                      ),
                      html.button(
                        [
                          attribute.type_("submit"),
                          attribute.class(
                            "cursor-pointer bg-neutral-950 px-4 py-1.5 text-xs font-medium text-white hover:bg-neutral-800 disabled:cursor-not-allowed disabled:bg-neutral-300 disabled:hover:bg-neutral-300",
                          ),
                        ],
                        [html.text("Post")],
                      ),
                    ],
                  ),
                ],
              ),
              error_el,
            ],
          ),
        ),
      ])
    }

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

fn feed(
  posts: List(Post),
  current_user: Option(AuthUser),
  confirming_delete: Option(String),
) -> Element(Msg) {
  case posts {
    [] ->
      html.p([attribute.class("px-4 py-8 text-xs text-neutral-400")], [
        html.text("No posts yet."),
      ])

    _ ->
      keyed.ul(
        [attribute.class("divide-y divide-neutral-200")],
        list.map(posts, fn(post) {
          #(post.id, post_row(post, current_user, confirming_delete))
        }),
      )
  }
}

fn post_row(
  post: Post,
  current_user: Option(AuthUser),
  confirming_delete: Option(String),
) -> Element(Msg) {
  html.li([attribute.class("px-4 py-3 hover:bg-neutral-50/70")], [
    html.div([attribute.class("flex items-baseline gap-2 text-xs")], [
      html.span([attribute.class("font-semibold text-neutral-950")], [
        html.text(post.author_name),
      ]),
      html.a(
        [
          attribute.href("/posts/" <> post.id),
          attribute.title(post.id),
          attribute.class(
            "font-mono text-neutral-400 underline-offset-2 hover:text-neutral-950 hover:underline",
          ),
        ],
        [html.text("#" <> short_id(post.id))],
      ),
      web_time.lote_time(
        post.created_at,
        "ml-auto shrink-0 font-mono text-xs text-neutral-400 tabular-nums",
      ),
      delete_controls(post, current_user, confirming_delete),
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

fn delete_controls(
  post: Post,
  current_user: Option(AuthUser),
  confirming_delete: Option(String),
) -> Element(Msg) {
  case current_user {
    Some(u) if u.id == post.user_id ->
      case confirming_delete {
        Some(id) if id == post.id ->
          html.span(
            [attribute.class("inline-flex shrink-0 items-baseline gap-1.5")],
            [
              html.button(
                [
                  attribute.type_("button"),
                  event.on_click(UserConfirmedDelete(post.id)),
                  attribute.class(
                    "cursor-pointer font-medium text-red-600 underline-offset-2 hover:underline",
                  ),
                ],
                [html.text("Confirm")],
              ),
              html.button(
                [
                  attribute.type_("button"),
                  event.on_click(UserCanceledDelete),
                  attribute.class(
                    "cursor-pointer text-neutral-500 underline-offset-2 hover:text-neutral-950 hover:underline",
                  ),
                ],
                [html.text("Cancel")],
              ),
            ],
          )

        _ ->
          html.button(
            [
              attribute.type_("button"),
              event.on_click(UserRequestedDelete(post.id)),
              attribute.class(
                "shrink-0 cursor-pointer text-neutral-400 underline-offset-2 hover:text-red-600 hover:underline",
              ),
            ],
            [html.text("Delete")],
          )
      }

    _ -> element.none()
  }
}

fn short_id(id: String) -> String {
  case string.length(id) >= 8 {
    True -> string.slice(id, at_index: string.length(id) - 8, length: 8)
    False -> id
  }
}
