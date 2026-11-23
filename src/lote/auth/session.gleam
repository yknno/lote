import cake/adapter/postgres
import cake/delete as d
import cake/fragment as f
import cake/insert as i
import cake/join as j
import cake/select as s
import cake/where as w
import gleam/bit_array
import gleam/crypto
import gleam/dynamic/decode
import gleam/http
import gleam/http/cookie
import gleam/http/request.{type Request}
import gleam/http/response
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import gleam/time/calendar
import gleam/time/timestamp.{type Timestamp}
import lote/auth/user.{type AuthUser, AuthUser}
import lote/db/uuid
import pog
import wisp

const cookie_name = "lote_session_id"

const max_age_seconds = 604_800

const max_user_agent_length = 512

pub type ActiveSession {
  ActiveSession(id: String, user: AuthUser, expires_at: Timestamp)
}

pub type SessionInfo {
  SessionInfo(
    public_id: String,
    user_agent: String,
    created_at: Timestamp,
    expires_at: Timestamp,
    is_current: Bool,
  )
}

pub fn create(
  resp: wisp.Response,
  req: wisp.Request,
  db: pog.Connection,
  secret_key_base: String,
  auth_user: AuthUser,
) -> Result(wisp.Response, pog.QueryError) {
  let session_id = wisp.random_string(32)
  let user_agent =
    req
    |> request.get_header("user-agent")
    |> result.unwrap("")
    |> string.trim
    |> string.slice(at_index: 0, length: max_user_agent_length)

  let query =
    [
      i.row([
        i.string(session_id),
        i.int(auth_user.id),
        i.string(user_agent),
        i.fragment(f.literal("NOW() + INTERVAL '7 days'")),
      ]),
    ]
    |> i.from_values(table_name: "sessions", columns: [
      "id",
      "user_id",
      "user_agent",
      "expires_at",
    ])
    |> i.to_query

  use _ <- result.map(postgres.run_write_query(query, decode.dynamic, db))
  set_cookie(resp, req, session_id, secret_key_base, max_age_seconds)
}

pub fn destroy(
  resp: wisp.Response,
  req: wisp.Request,
  db: pog.Connection,
  secret_key_base: String,
) -> wisp.Response {
  case read_session_id(req, secret_key_base) {
    Ok(session_id) -> {
      let query =
        d.new()
        |> d.table("sessions")
        |> d.where(w.eq(w.col("id"), w.string(session_id)))
        |> d.to_query
      let _ = postgres.run_write_query(query, decode.dynamic, db)
      Nil
    }
    Error(_) -> Nil
  }
  clear_cookie(resp, req, secret_key_base)
}

pub fn clear_cookie(
  resp: wisp.Response,
  req: wisp.Request,
  secret_key_base: String,
) -> wisp.Response {
  set_cookie(resp, req, "", secret_key_base, 0)
}

pub fn list_active_for_user(
  db: pog.Connection,
  user_id: Int,
  current_session_id: String,
) -> Result(List(SessionInfo), pog.QueryError) {
  let query =
    s.new()
    |> s.from_table("sessions")
    |> s.selects([
      s.col("id"),
      s.col("public_id"),
      s.col("user_agent"),
      s.col("created_at"),
      s.col("expires_at"),
    ])
    |> s.where(
      w.and([
        w.eq(w.col("user_id"), w.int(user_id)),
        w.gt(w.col("expires_at"), w.fragment_value(f.literal("NOW()"))),
      ]),
    )
    |> s.order_by_desc("created_at")
    |> s.order_by_desc("id")
    |> s.to_query

  let decoder = {
    use id <- decode.field(0, decode.string)
    use public_id <- decode.field(1, uuid.decoder())
    use user_agent <- decode.field(2, decode.string)
    use created_at <- decode.field(3, timestamptz_decoder())
    use expires_at <- decode.field(4, timestamptz_decoder())
    decode.success(SessionInfo(
      public_id:,
      user_agent:,
      created_at:,
      expires_at:,
      is_current: id == current_session_id,
    ))
  }

  postgres.run_read_query(query, decoder, db)
}

pub fn revoke_by_public_id(
  db: pog.Connection,
  public_id: String,
  user_id: Int,
) -> Result(Option(String), pog.QueryError) {
  case uuid.normalize(public_id) {
    Error(_) -> Ok(None)
    Ok(normalized) -> {
      let query =
        d.new()
        |> d.table("sessions")
        |> d.where(
          w.and([
            w.eq(
              w.col("public_id"),
              w.fragment_value(
                f.prepared(f.placeholder <> "::uuid", [f.string(normalized)]),
              ),
            ),
            w.eq(w.col("user_id"), w.int(user_id)),
          ]),
        )
        |> d.returning(["id"])
        |> d.to_query

      let decoder = {
        use id <- decode.field(0, decode.string)
        decode.success(id)
      }

      case postgres.run_write_query(query, decoder, db) {
        Ok([id, ..]) -> Ok(Some(id))
        Ok([]) -> Ok(None)
        Error(err) -> Error(err)
      }
    }
  }
}

pub fn revoke_others(
  db: pog.Connection,
  user_id: Int,
  current_session_id: String,
) -> Result(List(String), pog.QueryError) {
  let query =
    d.new()
    |> d.table("sessions")
    |> d.where(
      w.and([
        w.eq(w.col("user_id"), w.int(user_id)),
        w.neq(w.col("id"), w.string(current_session_id)),
      ]),
    )
    |> d.returning(["id"])
    |> d.to_query

  let decoder = {
    use id <- decode.field(0, decode.string)
    decode.success(id)
  }

  postgres.run_write_query(query, decoder, db)
}

pub fn session_id(
  req: Request(body),
  secret_key_base: String,
) -> Option(String) {
  case read_session_id(req, secret_key_base) {
    Ok(id) -> Some(id)
    Error(_) -> None
  }
}

pub fn current_session(
  req: Request(body),
  db: pog.Connection,
  secret_key_base: String,
) -> Option(ActiveSession) {
  case read_session_id(req, secret_key_base) {
    Ok(id) ->
      case find_active_session(db, id) {
        Some(#(user, expires_at)) ->
          Some(ActiveSession(id:, user:, expires_at:))
        None -> None
      }
    Error(_) -> None
  }
}

pub fn current_user(
  req: Request(body),
  db: pog.Connection,
  secret_key_base: String,
) -> Option(AuthUser) {
  case current_session(req, db, secret_key_base) {
    Some(active) -> Some(active.user)
    None -> None
  }
}

fn find_active_session(
  db: pog.Connection,
  session_id: String,
) -> Option(#(AuthUser, Timestamp)) {
  let query =
    s.new()
    |> s.from_table("sessions")
    |> s.join(j.inner(
      with: j.table("users"),
      on: w.eq(w.col("users.id"), w.col("sessions.user_id")),
      alias: "users",
    ))
    |> s.selects([
      s.col("users.id"),
      s.col("users.name"),
      s.col("sessions.expires_at"),
    ])
    |> s.where(
      w.and([
        w.eq(w.col("sessions.id"), w.string(session_id)),
        w.gt(w.col("sessions.expires_at"), w.fragment_value(f.literal("NOW()"))),
      ]),
    )
    |> s.limit(1)
    |> s.to_query

  let decoder = {
    use id <- decode.field(0, decode.int)
    use name <- decode.field(1, decode.string)
    use expires_at <- decode.field(2, timestamptz_decoder())
    decode.success(#(AuthUser(id:, name:), expires_at))
  }

  case postgres.run_read_query(query, decoder, db) {
    Ok([active, ..]) -> Some(active)
    _ -> None
  }
}

fn read_session_id(
  req: Request(body),
  secret_key_base: String,
) -> Result(String, Nil) {
  use raw <- result.try(
    req
    |> request.get_cookies
    |> list.key_find(cookie_name),
  )
  use bits <- result.try(
    crypto.verify_signed_message(raw, <<secret_key_base:utf8>>),
  )
  use id <- result.try(bit_array.to_string(bits))
  case id {
    "" -> Error(Nil)
    _ -> Ok(id)
  }
}

fn set_cookie(
  resp: wisp.Response,
  req: wisp.Request,
  value: String,
  secret_key_base: String,
  max_age: Int,
) -> wisp.Response {
  let scheme = case req.host {
    "localhost" | "127.0.0.1" | "[::1]" if req.scheme == http.Http ->
      case request.get_header(req, "x-forwarded-proto") {
        Ok(_) -> http.Https
        Error(_) -> http.Http
      }
    _ -> http.Https
  }
  let attributes =
    cookie.Attributes(..cookie.defaults(scheme), max_age: Some(max_age))
  let signed =
    crypto.sign_message(<<value:utf8>>, <<secret_key_base:utf8>>, crypto.Sha512)
  response.set_cookie(resp, cookie_name, signed, attributes)
}

fn timestamptz_decoder() -> decode.Decoder(Timestamp) {
  use date <- decode.field(0, pog.calendar_date_decoder())
  use time <- decode.field(1, pog.calendar_time_of_day_decoder())
  decode.success(timestamp.from_calendar(date, time, calendar.utc_offset))
}
