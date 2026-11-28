import gleam/dynamic/decode
import gleam/erlang/process.{type Subject}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/otp/actor
import gleam/otp/supervision
import gleam/result
import gleam/string
import lote/db/uuid
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
    grant_revocations: Option(PubSub(String)),
    interval_ms: Int,
    batch_limit: Int,
  )
}

pub fn start(
  db: pog.Connection,
  grant_revocations: Option(PubSub(String)),
  interval_ms: Int,
  batch_limit: Int,
) -> Result(actor.Started(Subject(Message)), actor.StartError) {
  let effective_interval = int.max(interval_ms, 1)
  actor.new_with_initialiser(1000, fn(self) {
    let _ = process.send_after(self, effective_interval, Tick)
    actor.initialised(State(
      self:,
      db:,
      grant_revocations:,
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
  grant_revocations: Option(PubSub(String)),
  interval_ms: Int,
  batch_limit: Int,
) -> supervision.ChildSpecification(Subject(Message)) {
  supervision.worker(fn() {
    start(db, grant_revocations, interval_ms, batch_limit)
  })
}

pub fn stop(cleaner: Subject(Message)) -> Nil {
  process.send(cleaner, Stop)
}

pub fn run_once(
  db: pog.Connection,
  grant_revocations: Option(PubSub(String)),
  batch_limit: Int,
) -> Result(Int, pog.QueryError) {
  delete_batches(db, grant_revocations, batch_limit, max_batches_per_tick, 0)
}

fn delete_batches(
  db: pog.Connection,
  grant_revocations: Option(PubSub(String)),
  batch_limit: Int,
  remaining_batches: Int,
  acc_deleted: Int,
) -> Result(Int, pog.QueryError) {
  case remaining_batches <= 0 || batch_limit <= 0 {
    True -> Ok(acc_deleted)
    False -> {
      use deleted_codes <- result.try(delete_expired_auth_codes(db, batch_limit))
      use deleted_access <- result.try(delete_expired_access_tokens(
        db,
        batch_limit,
      ))
      use deleted_refresh <- result.try(delete_expired_refresh_tokens(
        db,
        batch_limit,
      ))
      use deleted_grant_ids <- result.try(delete_expired_grants(db, batch_limit))

      case grant_revocations {
        Some(subject) ->
          list.each(deleted_grant_ids, fn(id) { pubsub.publish(subject, id) })
        None -> Nil
      }

      use deleted_cimd <- result.try(delete_expired_unused_cimd_clients(
        db,
        batch_limit,
      ))

      let deleted_grants = list.length(deleted_grant_ids)
      let batch_total =
        deleted_codes
        + deleted_access
        + deleted_refresh
        + deleted_grants
        + deleted_cimd
      let total = acc_deleted + batch_total

      let has_more =
        deleted_codes >= batch_limit
        || deleted_access >= batch_limit
        || deleted_refresh >= batch_limit
        || deleted_grants >= batch_limit
        || deleted_cimd >= batch_limit

      case has_more {
        False -> Ok(total)
        True ->
          delete_batches(
            db,
            grant_revocations,
            batch_limit,
            remaining_batches - 1,
            total,
          )
      }
    }
  }
}

fn delete_expired_auth_codes(
  db: pog.Connection,
  batch_limit: Int,
) -> Result(Int, pog.QueryError) {
  pog.query(
    "DELETE FROM oidc_auth_codes WHERE code_hash IN (SELECT code_hash FROM oidc_auth_codes WHERE expires_at <= NOW() LIMIT $1)",
  )
  |> pog.parameter(pog.int(batch_limit))
  |> pog.returning(decode.dynamic)
  |> pog.execute(db)
  |> result.map(fn(returned) { returned.count })
}

fn delete_expired_access_tokens(
  db: pog.Connection,
  batch_limit: Int,
) -> Result(Int, pog.QueryError) {
  pog.query(
    "DELETE FROM oidc_access_tokens WHERE token_hash IN (SELECT token_hash FROM oidc_access_tokens WHERE expires_at <= NOW() LIMIT $1)",
  )
  |> pog.parameter(pog.int(batch_limit))
  |> pog.returning(decode.dynamic)
  |> pog.execute(db)
  |> result.map(fn(returned) { returned.count })
}

fn delete_expired_refresh_tokens(
  db: pog.Connection,
  batch_limit: Int,
) -> Result(Int, pog.QueryError) {
  pog.query(
    "DELETE FROM oidc_refresh_tokens WHERE token_hash IN (SELECT token_hash FROM oidc_refresh_tokens WHERE expires_at <= NOW() LIMIT $1)",
  )
  |> pog.parameter(pog.int(batch_limit))
  |> pog.returning(decode.dynamic)
  |> pog.execute(db)
  |> result.map(fn(returned) { returned.count })
}

fn delete_expired_grants(
  db: pog.Connection,
  batch_limit: Int,
) -> Result(List(String), pog.QueryError) {
  let decoder = {
    use id <- decode.field(0, uuid.decoder())
    decode.success(id)
  }

  pog.query(
    "DELETE FROM oidc_grants WHERE id IN (SELECT id FROM oidc_grants WHERE expires_at <= NOW() LIMIT $1) RETURNING public_id",
  )
  |> pog.parameter(pog.int(batch_limit))
  |> pog.returning(decoder)
  |> pog.execute(db)
  |> result.map(fn(returned) { returned.rows })
}

fn delete_expired_unused_cimd_clients(
  db: pog.Connection,
  batch_limit: Int,
) -> Result(Int, pog.QueryError) {
  pog.query(
    "DELETE FROM oidc_clients
    WHERE id IN (
      SELECT c.id
      FROM oidc_clients c
      WHERE c.kind = 'cimd'
        AND c.cimd_expires_at IS NOT NULL
        AND c.cimd_expires_at <= NOW()
        AND NOT EXISTS (
          SELECT 1 FROM oidc_consents con WHERE con.client_ref_id = c.id
        )
      LIMIT $1
    )",
  )
  |> pog.parameter(pog.int(batch_limit))
  |> pog.returning(decode.dynamic)
  |> pog.execute(db)
  |> result.map(fn(returned) { returned.count })
}

fn handle_message(
  state: State,
  message: Message,
) -> actor.Next(State, Message) {
  case message {
    Tick -> {
      case run_once(state.db, state.grant_revocations, state.batch_limit) {
        Ok(0) -> Nil
        Ok(deleted) ->
          wisp.log_info(
            "Cleaned up " <> int.to_string(deleted) <> " expired OIDC rows",
          )
        Error(err) ->
          wisp.log_warning(
            "Failed to clean up expired OIDC rows: " <> string.inspect(err),
          )
      }
      let _ = process.send_after(state.self, state.interval_ms, Tick)
      actor.continue(state)
    }

    Stop -> actor.stop()
  }
}
