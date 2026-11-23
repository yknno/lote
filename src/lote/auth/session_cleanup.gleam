import gleam/erlang/process.{type Subject}
import gleam/int
import gleam/list
import gleam/otp/actor
import gleam/otp/supervision
import gleam/string
import lote/auth/session
import lote/realtime/pubsub.{type PubSub}
import pog
import wisp

pub const default_interval_ms = 3_600_000

pub const default_batch_limit = 500

const max_batches_per_tick = 20

pub opaque type Message {
  Tick
  Stop
}

type State {
  State(
    self: Subject(Message),
    db: pog.Connection,
    session_revocations: PubSub(String),
    interval_ms: Int,
    batch_limit: Int,
  )
}

pub fn start(
  db: pog.Connection,
  session_revocations: PubSub(String),
  interval_ms: Int,
  batch_limit: Int,
) -> Result(actor.Started(Subject(Message)), actor.StartError) {
  let effective_interval = int.max(interval_ms, 1)
  actor.new_with_initialiser(1000, fn(self) {
    let _ = process.send_after(self, effective_interval, Tick)
    actor.initialised(State(
      self:,
      db:,
      session_revocations:,
      interval_ms: effective_interval,
      batch_limit:,
    ))
    |> actor.returning(self)
    |> Ok
  })
  |> actor.on_message(handle_message)
  |> actor.start
}

pub fn supervised(
  db: pog.Connection,
  session_revocations: PubSub(String),
  interval_ms: Int,
  batch_limit: Int,
) -> supervision.ChildSpecification(Subject(Message)) {
  supervision.worker(fn() {
    start(db, session_revocations, interval_ms, batch_limit)
  })
}

pub fn stop(cleaner: Subject(Message)) -> Nil {
  process.send(cleaner, Stop)
}

pub fn run_once(
  db: pog.Connection,
  session_revocations: PubSub(String),
  batch_limit: Int,
) -> Result(Int, pog.QueryError) {
  delete_batches(db, session_revocations, batch_limit, max_batches_per_tick, 0)
}

fn delete_batches(
  db: pog.Connection,
  session_revocations: PubSub(String),
  batch_limit: Int,
  remaining_batches: Int,
  acc_deleted: Int,
) -> Result(Int, pog.QueryError) {
  case remaining_batches <= 0 || batch_limit <= 0 {
    True -> Ok(acc_deleted)
    False ->
      case session.delete_expired(db, batch_limit) {
        Error(err) -> Error(err)
        Ok(deleted_ids) -> {
          list.each(deleted_ids, fn(id) {
            pubsub.publish(session_revocations, id)
          })
          let count = list.length(deleted_ids)
          let total = acc_deleted + count
          case count < batch_limit {
            True -> Ok(total)
            False ->
              delete_batches(
                db,
                session_revocations,
                batch_limit,
                remaining_batches - 1,
                total,
              )
          }
        }
      }
  }
}

fn handle_message(
  state: State,
  message: Message,
) -> actor.Next(State, Message) {
  case message {
    Tick -> {
      case run_once(state.db, state.session_revocations, state.batch_limit) {
        Ok(0) -> Nil
        Ok(deleted) ->
          wisp.log_info(
            "Cleaned up " <> int.to_string(deleted) <> " expired sessions",
          )
        Error(err) ->
          wisp.log_warning(
            "Failed to clean up expired sessions: " <> string.inspect(err),
          )
      }
      let _ = process.send_after(state.self, state.interval_ms, Tick)
      actor.continue(state)
    }

    Stop -> actor.stop()
  }
}
