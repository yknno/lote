import gleam/dict.{type Dict}
import gleam/erlang/process.{type Monitor, type Subject}
import gleam/otp/actor

pub opaque type Message(event) {
  Subscribe(Subject(event))
  Unsubscribe(Subject(event))
  Publish(event)
  SubscriberDown(Monitor)
  Count(Subject(Int))
}

pub type PubSub(event) =
  Subject(Message(event))

pub fn start() -> Result(PubSub(event), actor.StartError) {
  case
    actor.new_with_initialiser(1000, fn(self) {
      let selector =
        process.new_selector()
        |> process.select(self)
        |> process.select_monitors(fn(down) { SubscriberDown(down.monitor) })

      actor.initialised(dict.new())
      |> actor.selecting(selector)
      |> actor.returning(self)
      |> Ok
    })
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

pub fn subscriber_count(pubsub: PubSub(event)) -> Int {
  actor.call(pubsub, waiting: 1000, sending: Count)
}

fn handle_message(
  subscribers: Dict(Subject(event), Monitor),
  message: Message(event),
) -> actor.Next(Dict(Subject(event), Monitor), Message(event)) {
  case message {
    Subscribe(subscriber) ->
      case dict.has_key(subscribers, subscriber) {
        True -> actor.continue(subscribers)
        False ->
          case process.subject_owner(subscriber) {
            Error(_) -> actor.continue(subscribers)
            Ok(pid) -> {
              let monitor = process.monitor(pid)
              subscribers
              |> dict.insert(subscriber, monitor)
              |> actor.continue
            }
          }
      }

    Unsubscribe(subscriber) ->
      case dict.get(subscribers, subscriber) {
        Ok(monitor) -> {
          process.demonitor_process(monitor)
          subscribers
          |> dict.delete(subscriber)
          |> actor.continue
        }
        Error(_) -> actor.continue(subscribers)
      }

    Publish(event) -> {
      dict.each(subscribers, fn(subscriber, _) {
        process.send(subscriber, event)
      })
      actor.continue(subscribers)
    }

    SubscriberDown(monitor) ->
      subscribers
      |> dict.filter(fn(_, m) { m != monitor })
      |> actor.continue

    Count(reply_to) -> {
      process.send(reply_to, dict.size(subscribers))
      actor.continue(subscribers)
    }
  }
}
