import gleam/erlang/process.{type Subject}
import gleam/list
import gleam/otp/actor

pub opaque type Message(event) {
  Subscribe(Subject(event))
  Unsubscribe(Subject(event))
  Publish(event)
}

pub type PubSub(event) =
  Subject(Message(event))

pub fn start() -> Result(PubSub(event), actor.StartError) {
  case
    actor.new([])
    |> actor.on_message(handle_message)
    |> actor.start
  {
    Ok(started) -> Ok(started.data)
    Error(err) -> Error(err)
  }
}

pub fn subscribe(pubsub: PubSub(event), subscriber: Subject(event)) -> Nil {
  process.send(pubsub, Subscribe(subscriber))
}

pub fn unsubscribe(pubsub: PubSub(event), subscriber: Subject(event)) -> Nil {
  process.send(pubsub, Unsubscribe(subscriber))
}

pub fn publish(pubsub: PubSub(event), event: event) -> Nil {
  process.send(pubsub, Publish(event))
}

fn handle_message(
  subscribers: List(Subject(event)),
  message: Message(event),
) -> actor.Next(List(Subject(event)), Message(event)) {
  case message {
    Subscribe(subscriber) -> actor.continue([subscriber, ..subscribers])

    Unsubscribe(subscriber) ->
      subscribers
      |> list.filter(fn(s) { s != subscriber })
      |> actor.continue

    Publish(event) -> {
      list.each(subscribers, process.send(_, event))
      actor.continue(subscribers)
    }
  }
}
