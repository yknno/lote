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
  let composer = case model.user {
    Some(_) ->
      html.form(
        [
          attribute.id("post-form-" <> int.to_string(model.form_key)),
          event.on_submit(UserSubmittedForm),
        ],
        [
          html.input([
            attribute.type_("text"),
            attribute.name("body"),
            attribute.placeholder("いまどうしてる？"),
            attribute.value(""),
            attribute.required(True),
          ]),
          html.button([attribute.type_("submit")], [html.text("Post")]),
        ],
      )
    None -> html.p([], [html.text("投稿するにはログインしてください。")])
  }

  html.div([], [
    composer,
    html.ul(
      [],
      list.map(model.posts, fn(post) {
        html.li([], [
          html.strong([], [html.text(post.author_name)]),
          html.text(": " <> post.body),
        ])
      }),
    ),
  ])
}
