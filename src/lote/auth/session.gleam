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
import lote/auth/user.{type AuthUser, AuthUser}
import pog
import wisp

const cookie_name = "lote_session_id"

const max_age_seconds = 604_800

pub fn create(
  resp: wisp.Response,
  req: wisp.Request,
  db: pog.Connection,
  secret_key_base: String,
  auth_user: AuthUser,
) -> Result(wisp.Response, pog.QueryError) {
  let session_id = wisp.random_string(32)

  let query =
    [
      i.row([
        i.string(session_id),
        i.int(auth_user.id),
        i.fragment(f.literal("NOW() + INTERVAL '7 days'")),
      ]),
    ]
    |> i.from_values(table_name: "sessions", columns: [
      "id",
      "user_id",
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
  set_cookie(resp, req, "", secret_key_base, 0)
}

pub type ActiveSession {
  ActiveSession(id: String, user: AuthUser)
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
      case find_user(db, id) {
        Some(user) -> Some(ActiveSession(id:, user:))
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

fn find_user(db: pog.Connection, session_id: String) -> Option(AuthUser) {
  let query =
    s.new()
    |> s.from_table("sessions")
    |> s.join(j.inner(
      with: j.table("users"),
      on: w.eq(w.col("users.id"), w.col("sessions.user_id")),
      alias: "users",
    ))
    |> s.selects([s.col("users.id"), s.col("users.name")])
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
    decode.success(AuthUser(id:, name:))
  }

  case postgres.run_read_query(query, decoder, db) {
    Ok([auth_user, ..]) -> Some(auth_user)
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
