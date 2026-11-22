import gleam/dict.{type Dict}
import gleam/dynamic/decode
import gleam/erlang/process.{type Monitor, type Subject}
import gleam/otp/actor
import gleam/result
import pog

pub type Adapter(event) {
  Memory
  Postgres(
    db: pog.Connection,
    channel: String,
    encode: fn(event) -> String,
    decode: fn(String) -> Result(event, Nil),
  )
}

pub opaque type Message(event) {
  Subscribe(Subject(event))
  Unsubscribe(Subject(event))
  Publish(event)
  BroadcastLocal(event)
  ReceivePayload(String)
  SubscriberDown(Monitor)
  Count(Subject(Int))
}

pub type PubSub(event) =
  Subject(Message(event))

type State(event) {
  State(subscribers: Dict(Subject(event), Monitor), adapter: Adapter(event))
}

pub fn start() -> Result(PubSub(event), actor.StartError) {
  start_with_adapter(Memory)
}

pub fn start_with_adapter(
  adapter: Adapter(event),
) -> Result(PubSub(event), actor.StartError) {
  case
    actor.new_with_initialiser(1000, fn(self) {
      let selector =
        process.new_selector()
        |> process.select(self)
        |> process.select_monitors(fn(down) { SubscriberDown(down.monitor) })

      actor.initialised(State(subscribers: dict.new(), adapter:))
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

pub fn broadcast_local(pubsub: PubSub(event), event: event) -> Nil {
  process.send(pubsub, BroadcastLocal(event))
}

pub fn receive_payload(pubsub: PubSub(event), payload: String) -> Nil {
  process.send(pubsub, ReceivePayload(payload))
}

pub fn subscriber_count(pubsub: PubSub(event)) -> Int {
  actor.call(pubsub, waiting: 1000, sending: Count)
}

pub fn pg_notify(
  db: pog.Connection,
  channel: String,
  payload: String,
) -> Result(Nil, pog.QueryError) {
  pog.query("SELECT pg_notify($1, $2)::text")
  |> pog.parameter(pog.text(channel))
  |> pog.parameter(pog.text(payload))
  |> pog.returning(decode.dynamic)
  |> pog.execute(db)
  |> result.replace(Nil)
}

fn handle_message(
  state: State(event),
  message: Message(event),
) -> actor.Next(State(event), Message(event)) {
  case message {
    Subscribe(subscriber) ->
      case dict.has_key(state.subscribers, subscriber) {
        True -> actor.continue(state)
        False ->
          case process.subject_owner(subscriber) {
            Error(_) -> actor.continue(state)
            Ok(pid) -> {
              let monitor = process.monitor(pid)
              let subscribers =
                dict.insert(state.subscribers, subscriber, monitor)
              actor.continue(State(..state, subscribers:))
            }
          }
      }

    Unsubscribe(subscriber) ->
      case dict.get(state.subscribers, subscriber) {
        Ok(monitor) -> {
          process.demonitor_process(monitor)
          let subscribers = dict.delete(state.subscribers, subscriber)
          actor.continue(State(..state, subscribers:))
        }
        Error(_) -> actor.continue(state)
      }

    Publish(event) -> {
      deliver_to_subscribers(state.subscribers, event)
      case state.adapter {
        Memory -> Nil
        Postgres(db:, channel:, encode:, ..) -> {
          let _ = pg_notify(db, channel, encode(event))
          Nil
        }
      }
      actor.continue(state)
    }

    BroadcastLocal(event) -> {
      deliver_to_subscribers(state.subscribers, event)
      actor.continue(state)
    }

    ReceivePayload(payload) -> {
      case state.adapter {
        Memory -> Nil
        Postgres(decode:, ..) ->
          case decode(payload) {
            Ok(event) -> deliver_to_subscribers(state.subscribers, event)
            Error(_) -> Nil
          }
      }
      actor.continue(state)
    }

    SubscriberDown(monitor) -> {
      let subscribers =
        dict.filter(state.subscribers, fn(_, m) { m != monitor })
      actor.continue(State(..state, subscribers:))
    }

    Count(reply_to) -> {
      process.send(reply_to, dict.size(state.subscribers))
      actor.continue(state)
    }
  }
}

fn deliver_to_subscribers(
  subscribers: Dict(Subject(event), Monitor),
  event: event,
) -> Nil {
  dict.each(subscribers, fn(subscriber, _) { process.send(subscriber, event) })
}
