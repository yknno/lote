import gleam/erlang/process.{type Subject}
import gleam/int
import gleam/otp/actor
import lote/realtime/pubsub.{type PubSub}
import lustre
import lustre/effect.{type Effect}
import lustre/element.{type Element}
import lustre/element/html
import lustre/event
import lustre/server_component

pub opaque type StoreMessage {
  Get(reply_to: Subject(Int))
  Increment
}

pub type Store {
  Store(actor: Subject(StoreMessage), pubsub: PubSub(Int))
}

pub fn start_store(pubsub: PubSub(Int)) -> Result(Store, actor.StartError) {
  case
    actor.new(0)
    |> actor.on_message(fn(count, msg) {
      case msg {
        Get(reply_to) -> {
          process.send(reply_to, count)
          actor.continue(count)
        }
        Increment -> {
          let next = count + 1
          pubsub.publish(pubsub, next)
          actor.continue(next)
        }
      }
    })
    |> actor.start
  {
    Ok(started) -> Ok(Store(actor: started.data, pubsub:))
    Error(err) -> Error(err)
  }
}

pub type Model {
  Model(count: Int, store: Store)
}

pub type Msg {
  UserClickedIncrement
  CountUpdated(Int)
}

pub fn app() -> lustre.App(Store, Model, Msg) {
  lustre.application(init:, update:, view:)
}

fn init(store: Store) -> #(Model, Effect(Msg)) {
  let current = process.call(store.actor, 5000, Get)

  let subscribe_effect =
    server_component.select(fn(_dispatch, subject) {
      pubsub.subscribe(store.pubsub, subject)
      process.new_selector()
      |> process.select_map(subject, CountUpdated)
    })

  #(Model(count: current, store:), subscribe_effect)
}

fn update(model: Model, msg: Msg) -> #(Model, Effect(Msg)) {
  case msg {
    UserClickedIncrement -> {
      let inc_effect =
        effect.from(fn(_dispatch) { process.send(model.store.actor, Increment) })
      #(model, inc_effect)
    }

    CountUpdated(next) -> #(Model(..model, count: next), effect.none())
  }
}

fn view(model: Model) -> Element(Msg) {
  html.div([], [
    html.p([], [html.text("Count: " <> int.to_string(model.count))]),
    html.button([event.on_click(UserClickedIncrement)], [html.text("+1")]),
  ])
}
