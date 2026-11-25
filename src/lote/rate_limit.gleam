import gleam/bit_array
import gleam/crypto
import gleam/dict.{type Dict}
import gleam/dynamic/decode
import gleam/erlang/process.{type Name, type Subject}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/otp/actor
import gleam/otp/supervision.{type ChildSpecification}
import gleam/result
import gleam/string
import gleam/time/timestamp
import pog
import wisp

pub const default_max_memory_entries = 50_000

pub const default_sweep_interval_ms = 60_000

pub const default_cleanup_interval_ms = 300_000

pub const default_cleanup_batch_limit = 1000

const max_cleanup_batches_per_tick = 20

/// GCRA rate-limit policy.
/// Allows up to `burst` back-to-back requests and replenishes at `limit`
/// requests per `window_ms` milliseconds.
pub type Policy {
  Policy(limit: Int, window_ms: Int, burst: Int)
}

pub type Decision {
  Allowed(remaining: Int)
  Limited(retry_after_seconds: Int)
}

pub opaque type Message {
  Check(
    hashed_key: String,
    policy: Policy,
    now_ms: Int,
    reply_to: Subject(Decision),
  )
  Peek(
    hashed_key: String,
    policy: Policy,
    now_ms: Int,
    reply_to: Subject(Decision),
  )
  Reset(hashed_key: String)
  Sweep
  Stop
}

pub opaque type CleanupMessage {
  CleanupTick
  CleanupStop
}

pub opaque type Limiter {
  DisabledLimiter
  MemoryLimiter(subject: Subject(Message), key_secret: String)
  PostgresLimiter(db: pog.Connection, key_secret: String)
}

type MemoryState {
  MemoryState(
    self: Subject(Message),
    entries: Dict(String, Int),
    max_entries: Int,
    sweep_interval_ms: Int,
  )
}

type CleanupState {
  CleanupState(
    self: Subject(CleanupMessage),
    db: pog.Connection,
    interval_ms: Int,
    batch_limit: Int,
  )
}

pub fn disabled() -> Limiter {
  DisabledLimiter
}

pub fn postgres(db: pog.Connection, key_secret: String) -> Limiter {
  PostgresLimiter(db:, key_secret:)
}

pub fn memory_named(name: Name(Message), key_secret: String) -> Limiter {
  MemoryLimiter(subject: process.named_subject(name), key_secret:)
}

pub fn start_memory(key_secret: String) -> Result(Limiter, actor.StartError) {
  start_memory_with_cap(
    key_secret,
    default_max_memory_entries,
    default_sweep_interval_ms,
  )
}

pub fn start_memory_with_cap(
  key_secret: String,
  max_entries: Int,
  sweep_interval_ms: Int,
) -> Result(Limiter, actor.StartError) {
  start_memory_actor(None, max_entries, sweep_interval_ms)
  |> result.map(fn(started) {
    MemoryLimiter(subject: started.data, key_secret:)
  })
}

pub fn supervised_memory(
  name: Name(Message),
) -> ChildSpecification(Subject(Message)) {
  supervision.worker(fn() {
    start_memory_actor(
      Some(name),
      default_max_memory_entries,
      default_sweep_interval_ms,
    )
  })
}

fn start_memory_actor(
  name: Option(Name(Message)),
  max_entries: Int,
  sweep_interval_ms: Int,
) -> Result(actor.Started(Subject(Message)), actor.StartError) {
  let effective_max = int.max(max_entries, 1)
  let effective_sweep = int.max(sweep_interval_ms, 1)

  let builder =
    actor.new_with_initialiser(1000, fn(self) {
      let _ = process.send_after(self, effective_sweep, Sweep)
      actor.initialised(MemoryState(
        self:,
        entries: dict.new(),
        max_entries: effective_max,
        sweep_interval_ms: effective_sweep,
      ))
      |> actor.returning(self)
      |> Ok
    })
    |> actor.on_message(handle_memory_message)

  let builder = case name {
    Some(n) -> actor.named(builder, n)
    None -> builder
  }

  actor.start(builder)
}

pub fn stop_memory(limiter: Limiter) -> Nil {
  case limiter {
    MemoryLimiter(subject:, ..) -> process.send(subject, Stop)
    DisabledLimiter | PostgresLimiter(..) -> Nil
  }
}

pub fn start_postgres_cleanup(
  db: pog.Connection,
  interval_ms: Int,
  batch_limit: Int,
) -> Result(actor.Started(Subject(CleanupMessage)), actor.StartError) {
  let effective_interval = int.max(interval_ms, 1)
  actor.new_with_initialiser(1000, fn(self) {
    let _ = process.send_after(self, effective_interval, CleanupTick)
    actor.initialised(CleanupState(
      self:,
      db:,
      interval_ms: effective_interval,
      batch_limit:,
    ))
    |> actor.returning(self)
    |> Ok
  })
  |> actor.on_message(handle_cleanup_message)
  |> actor.start
}

pub fn supervised_postgres_cleanup(
  db: pog.Connection,
  interval_ms: Int,
  batch_limit: Int,
) -> ChildSpecification(Subject(CleanupMessage)) {
  supervision.worker(fn() {
    start_postgres_cleanup(db, interval_ms, batch_limit)
  })
}

pub fn stop_postgres_cleanup(cleaner: Subject(CleanupMessage)) -> Nil {
  process.send(cleaner, CleanupStop)
}

/// Derive a fixed-length opaque storage key via HMAC-SHA256 so raw IPs,
/// login IDs, and user IDs are never stored in memory, PostgreSQL, or logs.
pub fn hash_key(key_secret: String, raw_key: String) -> String {
  crypto.hmac(<<"rate_limit:":utf8, raw_key:utf8>>, crypto.Sha256, <<
    key_secret:utf8,
  >>)
  |> bit_array.base16_encode
  |> string.lowercase
}

pub fn now_ms() -> Int {
  let #(seconds, nanoseconds) =
    timestamp.system_time()
    |> timestamp.to_unix_seconds_and_nanoseconds
  seconds * 1000 + nanoseconds / 1_000_000
}

pub fn check(limiter: Limiter, key: String, policy: Policy) -> Decision {
  check_at(limiter, key, policy, now_ms())
}

pub fn peek(limiter: Limiter, key: String, policy: Policy) -> Decision {
  peek_at(limiter, key, policy, now_ms())
}

pub fn peek_at(
  limiter: Limiter,
  key: String,
  policy: Policy,
  current_ms: Int,
) -> Decision {
  case limiter {
    DisabledLimiter -> Allowed(remaining: int.max(policy.burst - 1, 0))
    MemoryLimiter(subject:, key_secret:) -> {
      let hashed_key = hash_key(key_secret, key)
      actor.call(subject, waiting: 1000, sending: fn(reply_to) {
        Peek(hashed_key:, policy:, now_ms: current_ms, reply_to:)
      })
    }
    PostgresLimiter(db:, key_secret:) -> {
      let hashed_key = hash_key(key_secret, key)
      peek_postgres(db, hashed_key, policy, current_ms)
    }
  }
}

pub fn check_at(
  limiter: Limiter,
  key: String,
  policy: Policy,
  current_ms: Int,
) -> Decision {
  case limiter {
    DisabledLimiter -> Allowed(remaining: int.max(policy.burst - 1, 0))
    MemoryLimiter(subject:, key_secret:) -> {
      let hashed_key = hash_key(key_secret, key)
      actor.call(subject, waiting: 1000, sending: fn(reply_to) {
        Check(hashed_key:, policy:, now_ms: current_ms, reply_to:)
      })
    }
    PostgresLimiter(db:, key_secret:) -> {
      let hashed_key = hash_key(key_secret, key)
      check_postgres(db, hashed_key, policy, current_ms)
    }
  }
}

pub fn reset(limiter: Limiter, key: String) -> Nil {
  case limiter {
    DisabledLimiter -> Nil
    MemoryLimiter(subject:, key_secret:) ->
      process.send(subject, Reset(hash_key(key_secret, key)))
    PostgresLimiter(db:, key_secret:) -> {
      let hashed_key = hash_key(key_secret, key)
      case
        pog.query("DELETE FROM rate_limits WHERE key = $1")
        |> pog.parameter(pog.text(hashed_key))
        |> pog.returning(decode.dynamic)
        |> pog.execute(db)
      {
        Ok(_) -> Nil
        Error(err) ->
          wisp.log_warning(
            "Failed to reset rate limit entry: " <> string.inspect(err),
          )
      }
    }
  }
}

pub fn delete_expired_postgres(
  db: pog.Connection,
  current_ms: Int,
  batch_limit: Int,
) -> Result(Int, pog.QueryError) {
  case batch_limit <= 0 {
    True -> Ok(0)
    False ->
      pog.query(
        "DELETE FROM rate_limits WHERE key IN (SELECT key FROM rate_limits WHERE tat_ms <= $1 LIMIT $2)",
      )
      |> pog.parameter(pog.int(current_ms))
      |> pog.parameter(pog.int(batch_limit))
      |> pog.returning(decode.dynamic)
      |> pog.execute(db)
      |> result.map(fn(returned) { returned.count })
  }
}

/// Pure GCRA transition for in-process callers (such as per-connection WS frame
/// rate limiting) as well as the Memory backend.
pub fn check_gcra(
  tat_ms: Int,
  current_ms: Int,
  policy: Policy,
) -> #(Decision, Int) {
  let #(emission_ms, tolerance_ms) = policy_params(policy)
  let allow_at = tat_ms - tolerance_ms
  case allow_at <= current_ms {
    True -> {
      let base = int.max(tat_ms, current_ms)
      let new_tat = base + emission_ms
      let remaining =
        compute_remaining(new_tat, current_ms, emission_ms, tolerance_ms)
      #(Allowed(remaining:), new_tat)
    }
    False -> {
      let wait_ms = allow_at - current_ms
      let retry_after_seconds = ceil_seconds(wait_ms)
      #(Limited(retry_after_seconds:), tat_ms)
    }
  }
}

fn policy_params(policy: Policy) -> #(Int, Int) {
  let limit = int.max(policy.limit, 1)
  let window_ms = int.max(policy.window_ms, 1)
  let burst = int.max(policy.burst, 1)
  let emission_ms = int.max(window_ms / limit, 1)
  let tolerance_ms = emission_ms * { burst - 1 }
  #(emission_ms, tolerance_ms)
}

fn compute_remaining(
  new_tat: Int,
  current_ms: Int,
  emission_ms: Int,
  tolerance_ms: Int,
) -> Int {
  let headroom = current_ms + tolerance_ms - new_tat
  case headroom < 0 {
    True -> 0
    False -> headroom / emission_ms + 1
  }
}

fn ceil_seconds(wait_ms: Int) -> Int {
  case wait_ms <= 0 {
    True -> 1
    False -> { wait_ms + 999 } / 1000
  }
}

fn check_postgres(
  db: pog.Connection,
  hashed_key: String,
  policy: Policy,
  current_ms: Int,
) -> Decision {
  let #(emission_ms, tolerance_ms) = policy_params(policy)
  let decoder = {
    use allowed <- decode.field(0, decode.bool)
    use tat_ms <- decode.field(1, decode.int)
    decode.success(#(allowed, tat_ms))
  }

  let sql =
    "WITH attempt AS (
       INSERT INTO rate_limits (key, tat_ms)
       VALUES ($1, $2::bigint + $3::bigint)
       ON CONFLICT (key) DO UPDATE
       SET tat_ms = GREATEST(rate_limits.tat_ms, $2::bigint) + $3::bigint
       WHERE rate_limits.tat_ms - $4::bigint <= $2::bigint
       RETURNING tat_ms
     )
     SELECT TRUE AS allowed, tat_ms FROM attempt
     UNION ALL
     SELECT FALSE AS allowed, tat_ms FROM rate_limits
     WHERE key = $1 AND NOT EXISTS (SELECT 1 FROM attempt)
     LIMIT 1"

  case
    pog.query(sql)
    |> pog.parameter(pog.text(hashed_key))
    |> pog.parameter(pog.int(current_ms))
    |> pog.parameter(pog.int(emission_ms))
    |> pog.parameter(pog.int(tolerance_ms))
    |> pog.returning(decoder)
    |> pog.execute(db)
  {
    Ok(pog.Returned(rows: [#(True, new_tat), ..], ..)) -> {
      let remaining =
        compute_remaining(new_tat, current_ms, emission_ms, tolerance_ms)
      Allowed(remaining:)
    }
    Ok(pog.Returned(rows: [#(False, existing_tat), ..], ..)) -> {
      let wait_ms = existing_tat - tolerance_ms - current_ms
      Limited(retry_after_seconds: ceil_seconds(wait_ms))
    }
    Ok(pog.Returned(rows: [], ..)) ->
      // Row was deleted concurrently between attempt and fallback select; fail open.
      Allowed(remaining: int.max(policy.burst - 1, 0))
    Error(err) -> {
      wisp.log_warning(
        "Postgres rate limit query failed (failing open): "
        <> string.inspect(err),
      )
      Allowed(remaining: int.max(policy.burst - 1, 0))
    }
  }
}

fn peek_postgres(
  db: pog.Connection,
  hashed_key: String,
  policy: Policy,
  current_ms: Int,
) -> Decision {
  let decoder = {
    use tat_ms <- decode.field(0, decode.int)
    decode.success(tat_ms)
  }

  case
    pog.query("SELECT tat_ms FROM rate_limits WHERE key = $1 LIMIT 1")
    |> pog.parameter(pog.text(hashed_key))
    |> pog.returning(decoder)
    |> pog.execute(db)
  {
    Ok(pog.Returned(rows: [existing_tat, ..], ..)) -> {
      let #(decision, _) = check_gcra(existing_tat, current_ms, policy)
      decision
    }
    Ok(pog.Returned(rows: [], ..)) ->
      Allowed(remaining: int.max(policy.burst - 1, 0))
    Error(err) -> {
      wisp.log_warning(
        "Postgres rate limit peek failed (failing open): "
        <> string.inspect(err),
      )
      Allowed(remaining: int.max(policy.burst - 1, 0))
    }
  }
}

fn handle_memory_message(
  state: MemoryState,
  message: Message,
) -> actor.Next(MemoryState, Message) {
  case message {
    Check(hashed_key:, policy:, now_ms: current_ms, reply_to:) -> {
      let existing_tat = case dict.get(state.entries, hashed_key) {
        Ok(tat) -> tat
        Error(_) -> current_ms
      }
      let #(decision, new_tat) = check_gcra(existing_tat, current_ms, policy)
      let entries = case decision {
        Allowed(_) -> {
          let bounded = case
            !dict.has_key(state.entries, hashed_key)
            && dict.size(state.entries) >= state.max_entries
          {
            True -> evict_entries(state.entries, current_ms, state.max_entries)
            False -> state.entries
          }
          dict.insert(bounded, hashed_key, new_tat)
        }
        Limited(_) -> state.entries
      }
      process.send(reply_to, decision)
      actor.continue(MemoryState(..state, entries:))
    }

    Peek(hashed_key:, policy:, now_ms: current_ms, reply_to:) -> {
      let decision = case dict.get(state.entries, hashed_key) {
        Ok(existing_tat) -> {
          let #(d, _) = check_gcra(existing_tat, current_ms, policy)
          d
        }
        Error(_) -> Allowed(remaining: int.max(policy.burst - 1, 0))
      }
      process.send(reply_to, decision)
      actor.continue(state)
    }

    Reset(hashed_key) ->
      actor.continue(
        MemoryState(..state, entries: dict.delete(state.entries, hashed_key)),
      )

    Sweep -> {
      let current_ms = now_ms()
      let entries = dict.filter(state.entries, fn(_, tat) { tat > current_ms })
      let _ = process.send_after(state.self, state.sweep_interval_ms, Sweep)
      actor.continue(MemoryState(..state, entries:))
    }

    Stop -> actor.stop()
  }
}

fn evict_entries(
  entries: Dict(String, Int),
  current_ms: Int,
  max_entries: Int,
) -> Dict(String, Int) {
  let active = dict.filter(entries, fn(_, tat) { tat > current_ms })
  case dict.size(active) < max_entries {
    True -> active
    False -> {
      // Drop oldest 10% (at least 1) by earliest tat_ms to bound memory under floods.
      let drop_count = int.max(max_entries / 10, 1)
      active
      |> dict.to_list
      |> list.sort(fn(a, b) { int.compare(a.1, b.1) })
      |> list.drop(drop_count)
      |> dict.from_list
    }
  }
}

fn handle_cleanup_message(
  state: CleanupState,
  message: CleanupMessage,
) -> actor.Next(CleanupState, CleanupMessage) {
  case message {
    CleanupTick -> {
      case
        cleanup_batches(
          state.db,
          now_ms(),
          state.batch_limit,
          max_cleanup_batches_per_tick,
        )
      {
        Ok(_) -> Nil
        Error(err) ->
          wisp.log_warning(
            "Failed to clean up expired rate limit entries: "
            <> string.inspect(err),
          )
      }
      let _ = process.send_after(state.self, state.interval_ms, CleanupTick)
      actor.continue(state)
    }
    CleanupStop -> actor.stop()
  }
}

fn cleanup_batches(
  db: pog.Connection,
  current_ms: Int,
  batch_limit: Int,
  remaining_batches: Int,
) -> Result(Nil, pog.QueryError) {
  case remaining_batches <= 0 || batch_limit <= 0 {
    True -> Ok(Nil)
    False ->
      case delete_expired_postgres(db, current_ms, batch_limit) {
        Error(err) -> Error(err)
        Ok(deleted) if deleted < batch_limit -> Ok(Nil)
        Ok(_) ->
          cleanup_batches(db, current_ms, batch_limit, remaining_batches - 1)
      }
  }
}
