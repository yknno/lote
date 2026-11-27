import gleam/dynamic/decode
import gleam/erlang/process
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/order
import gleam/result
import gleam/set.{type Set}
import gleam/string
import gleam/time/timestamp.{type Timestamp}
import lote/auth/user.{type AuthUser}
import lote/db/post_repo
import lote/rate_limit.{type Limiter}
import lote/realtime/pubsub.{type PubSub}
import lote/web/client_ip
import lote/web/csrf
import lote/web/rate_policy
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
import wisp

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

pub type PostNotification {
  PostCreatedNotification(id: String)
  PostDeletedNotification(id: String)
}

pub fn encode_post_event(event: PostEvent) -> String {
  case event {
    Created(post) ->
      json.object([
        #("type", json.string("created")),
        #("id", json.string(post.id)),
      ])
      |> json.to_string
    Deleted(id) ->
      json.object([
        #("type", json.string("deleted")),
        #("id", json.string(id)),
      ])
      |> json.to_string
  }
}

pub fn decode_post_notification(
  payload: String,
) -> Result(PostNotification, Nil) {
  let decoder = {
    use event_type <- decode.field("type", decode.string)
    case event_type {
      "created" -> {
        use id <- decode.field("id", decode.string)
        decode.success(PostCreatedNotification(id))
      }
      "deleted" -> {
        use id <- decode.field("id", decode.string)
        decode.success(PostDeletedNotification(id))
      }
      _ -> decode.failure(PostDeletedNotification(""), "PostNotification")
    }
  }

  json.parse(payload, decoder)
  |> result.replace_error(Nil)
}

pub fn decode_post_event(
  db: pog.Connection,
  payload: String,
) -> Result(PostEvent, Nil) {
  case decode_post_notification(payload) {
    Ok(PostDeletedNotification(id)) -> Ok(Deleted(id))
    Ok(PostCreatedNotification(id)) ->
      case post_repo.find_by_id(db, id) {
        Ok(Some(row)) ->
          Ok(
            Created(Post(
              id: row.id,
              user_id: row.user_id,
              author_name: row.author_name,
              body: row.body,
              created_at: row.created_at,
            )),
          )
        Ok(None) -> Error(Nil)
        Error(err) -> {
          wisp.log_warning(
            "Failed to load post "
            <> id
            <> " for PubSub event: "
            <> string.inspect(err),
          )
          Error(Nil)
        }
      }
    Error(Nil) -> Error(Nil)
  }
}

pub const post_create_policy = rate_policy.post_create_user_policy

pub const ws_read_policy = rate_policy.ws_read_policy

pub const delete_write_policy = rate_policy.http_write_user_policy

pub type Flags {
  Flags(
    db: pog.Connection,
    pubsub: PubSub(PostEvent),
    rate_limiter: Limiter,
    user: Option(AuthUser),
    csrf_token: String,
  )
}

const max_incremental_fetch = 100

pub type Model {
  Model(
    db: pog.Connection,
    pubsub: PubSub(PostEvent),
    rate_limiter: Limiter,
    read_rate_key: String,
    user: Option(AuthUser),
    csrf_token: String,
    posts: List(Post),
    has_more: Bool,
    loading_more: Bool,
    loading_newer: Bool,
    pending_ids: Set(String),
    auto_refresh: Bool,
    confirming_delete: Option(String),
    form_key: Int,
    submitting: Bool,
    form_error: Option(String),
    timeline_error: Option(String),
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
  UserDismissedError
  PostSaveSucceeded(
    post: Post,
    newer: Option(List(Post)),
    reloaded: Option(#(List(Post), Bool)),
    cleared_pending: Set(String),
  )
  PostSaveFailed(String)
  PostDeleteFailed(String)
  TimelineReadRateLimited(Int)
  PostsReloaded(List(Post), Bool, Set(String))
  NewerPostsLoaded(posts: List(Post), cleared_pending: Set(String))
  NewerPostsLoadFailed
  OlderPostsLoaded(cursor: String, posts: List(Post), has_more: Bool)
  OlderPostsLoadFailed
  PostCreated(Post)
  PostDeleted(String)
}

pub fn app() -> lustre.App(Flags, Model, Msg) {
  app_with_ip("127.0.0.1")
}

pub fn app_with_ip(client_ip: String) -> lustre.App(Flags, Model, Msg) {
  lustre.application(init: init_with_ip(_, client_ip), update:, view:)
}

fn row_to_post(row: post_repo.PostRow) -> Post {
  Post(
    id: row.id,
    user_id: row.user_id,
    author_name: row.author_name,
    body: row.body,
    created_at: row.created_at,
  )
}

fn rows_to_page(rows: List(post_repo.PostRow)) -> #(List(Post), Bool) {
  let has_more = list.length(rows) > page_size
  let posts =
    rows
    |> list.take(page_size)
    |> list.map(row_to_post)
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

fn load_newer_posts_effect(
  limiter: Limiter,
  read_rate_key: String,
  db: pog.Connection,
  head_id: Option(String),
  pending_snapshot: Set(String),
) -> Effect(Msg) {
  effect.from(fn(dispatch) {
    case rate_limit.check(limiter, read_rate_key, ws_read_policy) {
      rate_limit.Limited(retry_after_seconds:) ->
        dispatch(TimelineReadRateLimited(retry_after_seconds))

      rate_limit.Allowed(_) ->
        case head_id {
          Some(after_id) ->
            case post_repo.list_after(db, after_id, max_incremental_fetch + 1) {
              Ok(rows) ->
                case list.length(rows) > max_incremental_fetch {
                  True ->
                    case load_recent_page(db) {
                      Ok(#(posts, has_more)) ->
                        dispatch(PostsReloaded(
                          posts,
                          has_more,
                          pending_snapshot,
                        ))
                      Error(err) -> {
                        wisp.log_warning(
                          "Failed to reload recent posts: "
                          <> string.inspect(err),
                        )
                        dispatch(NewerPostsLoadFailed)
                      }
                    }
                  False ->
                    dispatch(NewerPostsLoaded(
                      posts: list.map(rows, row_to_post),
                      cleared_pending: pending_snapshot,
                    ))
                }
              Error(err) -> {
                wisp.log_warning(
                  "Failed to load newer posts: " <> string.inspect(err),
                )
                dispatch(NewerPostsLoadFailed)
              }
            }

          None ->
            case load_recent_page(db) {
              Ok(#(posts, has_more)) ->
                dispatch(PostsReloaded(posts, has_more, pending_snapshot))
              Error(err) -> {
                wisp.log_warning(
                  "Failed to load recent posts: " <> string.inspect(err),
                )
                dispatch(NewerPostsLoadFailed)
              }
            }
        }
    }
  })
}

fn first_post_id(posts: List(Post)) -> Option(String) {
  case posts {
    [first, ..] -> Some(first.id)
    [] -> None
  }
}

fn last_post_id(posts: List(Post)) -> Option(String) {
  case list.last(posts) {
    Ok(post) -> Some(post.id)
    Error(_) -> None
  }
}

fn is_id_newer_than_loaded(post_id: String, loaded: List(Post)) -> Bool {
  case loaded {
    [first, ..] -> string.compare(post_id, first.id) == order.Gt
    [] -> True
  }
}

fn merge_posts_desc(newer: List(Post), existing: List(Post)) -> List(Post) {
  case newer, existing {
    [], rest -> rest
    rest, [] -> rest
    [a, ..a_rest], [b, ..b_rest] ->
      case string.compare(a.id, b.id) {
        order.Gt -> [a, ..merge_posts_desc(a_rest, existing)]
        order.Lt -> [b, ..merge_posts_desc(newer, b_rest)]
        order.Eq -> [a, ..merge_posts_desc(a_rest, b_rest)]
      }
  }
}

fn remaining_pending(
  current_pending: Set(String),
  cleared_pending: Set(String),
  loaded_posts: List(Post),
) -> Set(String) {
  current_pending
  |> set.difference(cleared_pending)
  |> set.filter(fn(id) { is_id_newer_than_loaded(id, loaded_posts) })
}

pub fn init(flags: Flags) -> #(Model, Effect(Msg)) {
  init_with_ip(flags, "127.0.0.1")
}

pub fn init_with_ip(flags: Flags, client_ip: String) -> #(Model, Effect(Msg)) {
  let #(posts, has_more) = case load_recent_page(flags.db) {
    Ok(page) -> page
    Error(_) -> #([], False)
  }

  let read_rate_key = case flags.user {
    Some(auth_user) -> rate_policy.ws_read_user_key(auth_user.id)
    None ->
      client_ip
      |> client_ip.rate_limit_bucket
      |> rate_policy.ws_read_ip_key
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
      rate_limiter: flags.rate_limiter,
      read_rate_key:,
      user: flags.user,
      csrf_token: flags.csrf_token,
      posts:,
      has_more:,
      loading_more: False,
      loading_newer: False,
      pending_ids: set.new(),
      auto_refresh: False,
      confirming_delete: None,
      form_key: 0,
      submitting: False,
      form_error: None,
      timeline_error: None,
    ),
    subscribe_effect,
  )
}

pub fn update(model: Model, msg: Msg) -> #(Model, Effect(Msg)) {
  case msg {
    UserSubmittedForm(fields) -> {
      case model.user, model.submitting {
        _, True | None, _ -> #(model, effect.none())
        Some(auth_user), False -> {
          let raw_body = case list.key_find(fields, "body") {
            Ok(value) -> value
            Error(_) -> ""
          }

          case post_repo.validate_body(raw_body) {
            Error(post_repo.EmptyBody) -> #(
              Model(..model, form_error: None),
              effect.none(),
            )

            Error(post_repo.BodyTooLarge(max_bytes:, ..)) -> #(
              Model(
                ..model,
                form_error: Some(
                  "Post is too large (max "
                  <> int.to_string(max_bytes)
                  <> " bytes).",
                ),
              ),
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
              let head_id = first_post_id(model.posts)
              let pending_snapshot = model.pending_ids
              let rate_key = rate_policy.post_create_user_key(auth_user.id)
              let save_and_publish =
                effect.from(fn(dispatch) {
                  case
                    rate_limit.check(
                      model.rate_limiter,
                      rate_key,
                      post_create_policy,
                    )
                  {
                    rate_limit.Limited(retry_after_seconds:) ->
                      dispatch(PostSaveFailed(
                        "You're posting too fast. Please wait "
                        <> int.to_string(retry_after_seconds)
                        <> "s and try again.",
                      ))
                    rate_limit.Allowed(_) ->
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
                          let #(newer, reloaded) = case head_id {
                            Some(after_id) ->
                              case
                                post_repo.list_after(
                                  model.db,
                                  after_id,
                                  max_incremental_fetch + 1,
                                )
                              {
                                Ok(rows) ->
                                  case
                                    list.length(rows) > max_incremental_fetch
                                  {
                                    True ->
                                      case load_recent_page(model.db) {
                                        Ok(page) -> #(None, Some(page))
                                        Error(_) -> #(Some([post]), None)
                                      }
                                    False -> #(
                                      Some(merge_posts_desc(
                                        [post],
                                        list.map(rows, row_to_post),
                                      )),
                                      None,
                                    )
                                  }
                                Error(_) -> #(Some([post]), None)
                              }
                            None ->
                              case load_recent_page(model.db) {
                                Ok(page) -> #(None, Some(page))
                                Error(_) -> #(Some([post]), None)
                              }
                          }
                          dispatch(PostSaveSucceeded(
                            post:,
                            newer:,
                            reloaded:,
                            cleared_pending: pending_snapshot,
                          ))
                          pubsub.publish(model.pubsub, Created(post))
                        }
                        Error(err) -> {
                          wisp.log_warning(
                            "Failed to create post: " <> string.inspect(err),
                          )
                          dispatch(PostSaveFailed(
                            "Failed to publish post. Please try again.",
                          ))
                        }
                      }
                  }
                })
              #(
                Model(..model, submitting: True, form_error: None),
                save_and_publish,
              )
            }
          }
        }
      }
    }

    UserClickedRefresh ->
      case model.loading_newer {
        True -> #(model, effect.none())
        False -> #(
          Model(..model, loading_newer: True, timeline_error: None),
          load_newer_posts_effect(
            model.rate_limiter,
            model.read_rate_key,
            model.db,
            first_post_id(model.posts),
            model.pending_ids,
          ),
        )
      }

    UserToggledAutoRefresh ->
      case model.auto_refresh {
        True -> #(Model(..model, auto_refresh: False), effect.none())
        False ->
          case !set.is_empty(model.pending_ids) && !model.loading_newer {
            True -> #(
              Model(
                ..model,
                auto_refresh: True,
                loading_newer: True,
                timeline_error: None,
              ),
              load_newer_posts_effect(
                model.rate_limiter,
                model.read_rate_key,
                model.db,
                first_post_id(model.posts),
                model.pending_ids,
              ),
            )
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
                  case
                    rate_limit.check(
                      model.rate_limiter,
                      model.read_rate_key,
                      ws_read_policy,
                    )
                  {
                    rate_limit.Limited(retry_after_seconds:) ->
                      dispatch(TimelineReadRateLimited(retry_after_seconds))
                    rate_limit.Allowed(_) ->
                      case load_older_page(model.db, cursor) {
                        Ok(#(older, has_more)) ->
                          dispatch(OlderPostsLoaded(
                            cursor:,
                            posts: older,
                            has_more:,
                          ))
                        Error(err) -> {
                          wisp.log_warning(
                            "Failed to load older posts: "
                            <> string.inspect(err),
                          )
                          dispatch(OlderPostsLoadFailed)
                        }
                      }
                  }
                })
              #(
                Model(..model, loading_more: True, timeline_error: None),
                load_effect,
              )
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
              Model(
                ..model,
                confirming_delete: Some(post_id),
                timeline_error: None,
              ),
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
          let write_key = rate_policy.http_write_user_key(auth_user.id)
          let delete_and_publish =
            effect.from(fn(dispatch) {
              case
                rate_limit.check(
                  model.rate_limiter,
                  write_key,
                  delete_write_policy,
                )
              {
                rate_limit.Limited(retry_after_seconds:) ->
                  dispatch(PostDeleteFailed(
                    "Too many requests. Please wait "
                    <> int.to_string(retry_after_seconds)
                    <> "s and try again.",
                  ))
                rate_limit.Allowed(_) ->
                  case post_repo.delete(model.db, post_id, auth_user.id) {
                    Ok(True) -> pubsub.publish(model.pubsub, Deleted(post_id))
                    Ok(False) -> Nil
                    Error(err) -> {
                      wisp.log_warning(
                        "Failed to delete post "
                        <> post_id
                        <> ": "
                        <> string.inspect(err),
                      )
                      dispatch(PostDeleteFailed(
                        "Failed to delete post. Please try again.",
                      ))
                    }
                  }
              }
            })
          #(
            Model(..model, confirming_delete: None, timeline_error: None),
            delete_and_publish,
          )
        }
      }

    UserDismissedError -> #(Model(..model, timeline_error: None), effect.none())

    PostSaveSucceeded(post:, newer:, reloaded:, cleared_pending:) ->
      case reloaded {
        Some(#(posts, has_more)) -> {
          let merged = merge_posts_desc([post], posts)
          let pending_ids =
            remaining_pending(model.pending_ids, cleared_pending, merged)
          #(
            Model(
              ..model,
              posts: merged,
              has_more:,
              loading_more: False,
              loading_newer: False,
              pending_ids:,
              form_key: model.form_key + 1,
              submitting: False,
              form_error: None,
            ),
            effect.none(),
          )
        }
        None -> {
          let to_prepend = case newer {
            Some(items) -> items
            None -> [post]
          }
          let merged = merge_posts_desc(to_prepend, model.posts)
          let pending_ids =
            remaining_pending(model.pending_ids, cleared_pending, merged)
          #(
            Model(
              ..model,
              posts: merged,
              loading_newer: False,
              pending_ids:,
              form_key: model.form_key + 1,
              submitting: False,
              form_error: None,
            ),
            effect.none(),
          )
        }
      }

    PostSaveFailed(message) -> #(
      Model(..model, submitting: False, form_error: Some(message)),
      effect.none(),
    )

    PostDeleteFailed(message) -> #(
      Model(..model, timeline_error: Some(message)),
      effect.none(),
    )

    TimelineReadRateLimited(retry_after_seconds) -> #(
      Model(
        ..model,
        loading_newer: False,
        loading_more: False,
        timeline_error: Some(
          "Too many requests. Please wait "
          <> int.to_string(retry_after_seconds)
          <> "s and try again.",
        ),
      ),
      effect.none(),
    )

    PostsReloaded(posts, has_more, cleared_pending) -> {
      let pending_ids =
        remaining_pending(model.pending_ids, cleared_pending, posts)
      #(
        Model(
          ..model,
          posts:,
          has_more:,
          loading_more: False,
          loading_newer: False,
          pending_ids:,
          timeline_error: None,
        ),
        effect.none(),
      )
    }

    NewerPostsLoaded(posts: newer, cleared_pending:) -> {
      let merged = merge_posts_desc(newer, model.posts)
      let pending_ids =
        remaining_pending(model.pending_ids, cleared_pending, merged)
      #(
        Model(
          ..model,
          posts: merged,
          loading_newer: False,
          pending_ids:,
          timeline_error: None,
        ),
        effect.none(),
      )
    }

    NewerPostsLoadFailed -> #(
      Model(
        ..model,
        loading_newer: False,
        timeline_error: Some("Failed to load new posts. Please try again."),
      ),
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
      Model(
        ..model,
        loading_more: False,
        timeline_error: Some("Failed to load older posts. Please try again."),
      ),
      effect.none(),
    )

    PostCreated(post) ->
      case is_id_newer_than_loaded(post.id, model.posts) {
        False -> #(model, effect.none())
        True ->
          case model.auto_refresh {
            True -> #(
              Model(
                ..model,
                posts: merge_posts_desc([post], model.posts),
                pending_ids: set.delete(model.pending_ids, post.id),
              ),
              effect.none(),
            )
            False -> #(
              Model(
                ..model,
                pending_ids: set.insert(model.pending_ids, post.id),
              ),
              effect.none(),
            )
          }
      }

    PostDeleted(post_id) -> {
      let confirming_delete = case model.confirming_delete {
        Some(id) if id == post_id -> None
        other -> other
      }
      let pending_ids = set.delete(model.pending_ids, post_id)
      let remaining = list.filter(model.posts, fn(p) { p.id != post_id })
      case remaining, model.has_more {
        [], True -> {
          let pending_snapshot = pending_ids
          let reload_effect =
            effect.from(fn(dispatch) {
              case load_recent_page(model.db) {
                Ok(#(posts, has_more)) ->
                  dispatch(PostsReloaded(posts, has_more, pending_snapshot))
                Error(err) -> {
                  wisp.log_warning(
                    "Failed to reload posts after deletion: "
                    <> string.inspect(err),
                  )
                  Nil
                }
              }
            })
          #(
            Model(..model, posts: remaining, confirming_delete:, pending_ids:),
            reload_effect,
          )
        }
        _, _ -> #(
          Model(..model, posts: remaining, confirming_delete:, pending_ids:),
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
      timeline_error_banner(model.timeline_error),
      pending_banner(set.size(model.pending_ids), model.loading_newer),
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

fn timeline_error_banner(error: Option(String)) -> Element(Msg) {
  case error {
    Some(message) ->
      html.div(
        [
          attribute.role("alert"),
          attribute.class(
            "flex items-center justify-between gap-3 border-b border-red-200 bg-red-50 px-4 py-2 text-xs text-red-700",
          ),
        ],
        [
          html.span([], [html.text(message)]),
          html.button(
            [
              attribute.type_("button"),
              event.on_click(UserDismissedError),
              attribute.class(
                "shrink-0 cursor-pointer font-medium text-red-700 underline-offset-2 hover:underline",
              ),
            ],
            [html.text("Dismiss")],
          ),
        ],
      )
    None -> element.none()
  }
}

fn pending_banner(pending_count: Int, loading_newer: Bool) -> Element(Msg) {
  case pending_count {
    count if count > 0 -> {
      let label = case loading_newer, count {
        True, _ -> "Loading new posts..."
        False, 1 -> "Show 1 new post"
        False, n -> "Show " <> int.to_string(n) <> " new posts"
      }
      html.button(
        [
          attribute.type_("button"),
          attribute.disabled(loading_newer),
          event.on_click(UserClickedRefresh),
          attribute.class(
            "w-full cursor-pointer border-b border-neutral-200 bg-neutral-50 px-4 py-2 text-center text-xs font-medium text-neutral-900 hover:bg-neutral-100 disabled:cursor-wait disabled:text-neutral-400",
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
                  case model.submitting {
                    True -> attribute.attribute("submitting", "")
                    False -> attribute.none()
                  },
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
                          attribute.disabled(model.submitting),
                          attribute.class(
                            "cursor-pointer bg-neutral-950 px-4 py-1.5 text-xs font-medium text-white hover:bg-neutral-800 disabled:cursor-not-allowed disabled:bg-neutral-300 disabled:hover:bg-neutral-300",
                          ),
                        ],
                        [
                          html.text(case model.submitting {
                            True -> "Posting..."
                            False -> "Post"
                          }),
                        ],
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
