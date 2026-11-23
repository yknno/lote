import gleam/bit_array
import gleam/dict.{type Dict}
import gleam/dynamic/decode
import gleam/erlang/atom
import gleam/erlang/process.{type Monitor, type Name, type Pid, type Subject}
import gleam/int
import gleam/option.{type Option, None, Some}
import gleam/otp/actor
import gleam/otp/supervision.{type ChildSpecification}
import gleam/result
import gleam/string
import pog
import wisp

pub const max_notify_payload_bytes = 8000

pub type Adapter(event) {
  Memory
  Postgres(
    db: pog.Connection,
    database_url: String,
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
  ReconnectListener(Int)
  Ignore
  ProcessDown(Monitor)
  Count(Subject(Int))
}

pub type PubSub(event) =
  Subject(Message(event))

type State(event) {
  State(
    self: Subject(Message(event)),
    subscribers: Dict(Subject(event), Monitor),
    adapter: Adapter(event),
    listener_monitor: Option(Monitor),
    publisher: Option(Subject(event)),
    decoder: Option(Subject(String)),
  )
}

@external(erlang, "lote_pubsub_ffi", "start_and_listen")
fn start_pg_listener(config: pog.Config, channel: String) -> Result(Pid, String)

pub fn start() -> Result(PubSub(event), actor.StartError) {
  start_with_adapter(Memory)
}

pub fn start_with_adapter(
  adapter: Adapter(event),
) -> Result(PubSub(event), actor.StartError) {
  start_actor(None, adapter)
  |> result.map(fn(started) { started.data })
}

pub fn start_named(
  name: Name(Message(event)),
  adapter: Adapter(event),
) -> Result(actor.Started(PubSub(event)), actor.StartError) {
  start_actor(Some(name), adapter)
}

pub fn supervised(
  name: Name(Message(event)),
  adapter: Adapter(event),
) -> ChildSpecification(PubSub(event)) {
  supervision.worker(fn() { start_named(name, adapter) })
}

fn start_actor(
  name: Option(Name(Message(event))),
  adapter: Adapter(event),
) -> Result(actor.Started(PubSub(event)), actor.StartError) {
  let builder =
    actor.new_with_initialiser(5000, fn(self) {
      use #(listener_monitor, publisher, decoder) <- result.try(case adapter {
        Memory -> Ok(#(None, None, None))
        Postgres(db:, database_url:, channel:, encode:, decode:) -> {
          use db_config <- result.try(build_listener_config(database_url))
          let listener_monitor = case start_pg_listener(db_config, channel) {
            Ok(pid) -> Some(process.monitor(pid))
            Error(err) -> {
              wisp.log_warning(
                "Postgres PubSub initial LISTEN failed on channel \""
                <> channel
                <> "\": "
                <> err
                <> "; scheduling reconnect",
              )
              let _ =
                process.send_after(
                  self,
                  reconnect_delay_ms(1),
                  ReconnectListener(1),
                )
              None
            }
          }

          use pub_started <- result.try(
            start_publisher_worker(self, db, channel, encode)
            |> result.map_error(fn(err) {
              "failed to start Postgres PubSub publisher worker: "
              <> string.inspect(err)
            }),
          )
          use dec_started <- result.try(
            start_decoder_worker(self, channel, decode)
            |> result.map_error(fn(err) {
              "failed to start Postgres PubSub decoder worker: "
              <> string.inspect(err)
            }),
          )
          Ok(#(listener_monitor, Some(pub_started.data), Some(dec_started.data)))
        }
      })

      let base_selector =
        process.new_selector()
        |> process.select(self)
        |> process.select_monitors(fn(down) { ProcessDown(down.monitor) })

      let selector = case adapter {
        Memory -> base_selector
        Postgres(channel: expected_channel, ..) ->
          base_selector
          |> process.select_record(atom.create("notification"), 4, fn(record) {
            let notification_decoder = {
              use ch <- decode.field(3, decode.string)
              use payload <- decode.field(4, decode.string)
              decode.success(#(ch, payload))
            }
            case decode.run(record, notification_decoder) {
              Ok(#(ch, payload)) if ch == expected_channel ->
                ReceivePayload(payload)
              _ -> Ignore
            }
          })
      }

      actor.initialised(State(
        self:,
        subscribers: dict.new(),
        adapter:,
        listener_monitor:,
        publisher:,
        decoder:,
      ))
      |> actor.selecting(selector)
      |> actor.returning(self)
      |> Ok
    })
    |> actor.on_message(handle_message)

  let builder = case name {
    Some(n) -> actor.named(builder, n)
    None -> builder
  }

  actor.start(builder)
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

fn build_listener_config(database_url: String) -> Result(pog.Config, String) {
  let pool_name = process.new_name("lote_pubsub_listen")
  case pog.url_config(pool_name, database_url) {
    Error(_) -> Error("invalid database_url for Postgres PubSub")
    Ok(db_config) -> Ok(pog.connection_parameter(db_config, "timezone", "UTC"))
  }
}

fn start_publisher_worker(
  pubsub: Subject(Message(event)),
  db: pog.Connection,
  channel: String,
  encode: fn(event) -> String,
) -> Result(actor.Started(Subject(event)), actor.StartError) {
  actor.new(Nil)
  |> actor.on_message(fn(state, event) {
    let payload = encode(event)
    let byte_len = bit_array.byte_size(<<payload:utf8>>)
    case byte_len > max_notify_payload_bytes {
      True -> {
        wisp.log_warning(
          "Postgres PubSub payload exceeds "
          <> int.to_string(max_notify_payload_bytes)
          <> " bytes ("
          <> int.to_string(byte_len)
          <> " bytes) on channel \""
          <> channel
          <> "\"; falling back to local delivery",
        )
        process.send(pubsub, BroadcastLocal(event))
      }
      False ->
        case pg_notify(db, channel, payload) {
          Ok(_) -> Nil
          Error(err) -> {
            wisp.log_warning(
              "Postgres pg_notify failed on channel \""
              <> channel
              <> "\" ("
              <> int.to_string(byte_len)
              <> " bytes): "
              <> string.inspect(err)
              <> "; falling back to local delivery",
            )
            process.send(pubsub, BroadcastLocal(event))
          }
        }
    }
    actor.continue(state)
  })
  |> actor.start
}

fn start_decoder_worker(
  pubsub: Subject(Message(event)),
  channel: String,
  decode_payload: fn(String) -> Result(event, Nil),
) -> Result(actor.Started(Subject(String)), actor.StartError) {
  actor.new(Nil)
  |> actor.on_message(fn(state, payload) {
    case decode_payload(payload) {
      Ok(event) -> process.send(pubsub, BroadcastLocal(event))
      Error(_) ->
        wisp.log_warning(
          "Postgres PubSub failed to decode notification payload on channel \""
          <> channel
          <> "\"",
        )
    }
    actor.continue(state)
  })
  |> actor.start
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
      case state.adapter, state.publisher {
        Memory, _ -> deliver_to_subscribers(state.subscribers, event)
        Postgres(..), Some(publisher) -> process.send(publisher, event)
        Postgres(..), None -> deliver_to_subscribers(state.subscribers, event)
      }
      actor.continue(state)
    }

    BroadcastLocal(event) -> {
      deliver_to_subscribers(state.subscribers, event)
      actor.continue(state)
    }

    ReceivePayload(payload) -> {
      case state.decoder {
        Some(decoder) -> process.send(decoder, payload)
        None -> Nil
      }
      actor.continue(state)
    }

    ReconnectListener(attempt) ->
      case state.listener_monitor, state.adapter {
        None, Postgres(database_url:, channel:, ..) ->
          case build_listener_config(database_url) {
            Error(err) -> {
              wisp.log_warning(
                "Postgres PubSub reconnect aborted on channel \""
                <> channel
                <> "\": "
                <> err,
              )
              actor.continue(state)
            }
            Ok(db_config) ->
              case start_pg_listener(db_config, channel) {
                Ok(pid) -> {
                  wisp.log_info(
                    "Postgres PubSub listener reconnected on channel \""
                    <> channel
                    <> "\"",
                  )
                  let monitor = process.monitor(pid)
                  actor.continue(
                    State(..state, listener_monitor: Some(monitor)),
                  )
                }
                Error(err) -> {
                  let delay = reconnect_delay_ms(attempt + 1)
                  wisp.log_warning(
                    "Postgres PubSub reconnect failed on channel \""
                    <> channel
                    <> "\": "
                    <> err
                    <> "; retrying in "
                    <> int.to_string(delay)
                    <> "ms",
                  )
                  let _ =
                    process.send_after(
                      state.self,
                      delay,
                      ReconnectListener(attempt + 1),
                    )
                  actor.continue(state)
                }
              }
          }
        _, _ -> actor.continue(state)
      }

    Ignore -> actor.continue(state)

    ProcessDown(monitor) ->
      case state.listener_monitor {
        Some(listener_mon) if listener_mon == monitor -> {
          let channel = case state.adapter {
            Postgres(channel:, ..) -> channel
            Memory -> ""
          }
          let delay = reconnect_delay_ms(1)
          wisp.log_warning(
            "Postgres PubSub listener exited on channel \""
            <> channel
            <> "\"; scheduling reconnect in "
            <> int.to_string(delay)
            <> "ms",
          )
          let _ = process.send_after(state.self, delay, ReconnectListener(1))
          actor.continue(State(..state, listener_monitor: None))
        }
        _ -> {
          let subscribers =
            dict.filter(state.subscribers, fn(_, m) { m != monitor })
          actor.continue(State(..state, subscribers:))
        }
      }

    Count(reply_to) -> {
      process.send(reply_to, dict.size(state.subscribers))
      actor.continue(state)
    }
  }
}

fn reconnect_delay_ms(attempt: Int) -> Int {
  case attempt {
    n if n <= 1 -> 200
    2 -> 400
    3 -> 800
    4 -> 1600
    5 -> 3200
    6 -> 6400
    _ -> 10_000
  }
}

fn deliver_to_subscribers(
  subscribers: Dict(Subject(event), Monitor),
  event: event,
) -> Nil {
  dict.each(subscribers, fn(subscriber, _) { process.send(subscriber, event) })
}
