import cake/adapter/postgres
import cake/delete as d
import cake/fragment as f
import cake/insert as i
import cake/join as j
import cake/select as s
import cake/where as w
import gleam/bit_array
import gleam/dynamic/decode
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import gleam/time/calendar
import gleam/time/timestamp.{type Timestamp}
import lote/db/uuid
import pog

pub const max_body_length = 300

pub const max_body_bytes = 16_384

pub const max_raw_body_bytes = 32_768

pub type BodyError {
  EmptyBody
  BodyTooLong(length: Int, max: Int)
  BodyTooLarge(bytes: Int, max_bytes: Int)
}

pub type CreateError {
  InvalidBody(BodyError)
  QueryError(pog.QueryError)
}

pub type CreatedPost {
  CreatedPost(id: String, user_id: Int, body: String, created_at: Timestamp)
}

pub type PostRow {
  PostRow(
    id: String,
    user_id: Int,
    author_name: String,
    body: String,
    created_at: Timestamp,
  )
}

pub fn trim_body(raw: String) -> String {
  raw
  |> string.to_utf_codepoints
  |> list.drop_while(is_whitespace_codepoint)
  |> list.reverse
  |> list.drop_while(is_whitespace_codepoint)
  |> list.reverse
  |> string.from_utf_codepoints
}

fn is_whitespace_codepoint(cp: UtfCodepoint) -> Bool {
  case string.utf_codepoint_to_int(cp) {
    0x0009
    | 0x000A
    | 0x000B
    | 0x000C
    | 0x000D
    | 0x0020
    | 0x00A0
    | 0x1680
    | 0x2028
    | 0x2029
    | 0x202F
    | 0x205F
    | 0x3000
    | 0xFEFF -> True
    n if n >= 0x2000 && n <= 0x200A -> True
    _ -> False
  }
}

pub fn validate_body(raw: String) -> Result(String, BodyError) {
  let raw_bytes = bit_array.byte_size(<<raw:utf8>>)
  case raw_bytes > max_raw_body_bytes {
    True -> Error(BodyTooLarge(bytes: raw_bytes, max_bytes: max_body_bytes))
    False -> {
      let body = trim_body(raw)
      let body_bytes = bit_array.byte_size(<<body:utf8>>)
      case body_bytes {
        0 -> Error(EmptyBody)
        n if n > max_body_bytes ->
          Error(BodyTooLarge(bytes: n, max_bytes: max_body_bytes))
        _ -> {
          let length = string.length(body)
          case length > max_body_length {
            True -> Error(BodyTooLong(length:, max: max_body_length))
            False -> Ok(body)
          }
        }
      }
    }
  }
}

pub fn create(
  db: pog.Connection,
  user_id: Int,
  body: String,
) -> Result(CreatedPost, CreateError) {
  use body <- result.try(validate_body(body) |> result.map_error(InvalidBody))

  let query =
    [i.row([i.int(user_id), i.string(body)])]
    |> i.from_values(table_name: "posts", columns: ["user_id", "body"])
    |> i.returning(["id", "user_id", "body", "created_at"])
    |> i.to_query

  let decoder = {
    use id <- decode.field(0, uuid.decoder())
    use uid <- decode.field(1, decode.int)
    use body <- decode.field(2, decode.string)
    use created_at <- decode.field(3, timestamptz_decoder())
    decode.success(CreatedPost(id:, user_id: uid, body:, created_at:))
  }

  case postgres.run_write_query(query, decoder, db) {
    Ok([row, ..]) -> Ok(row)
    Ok([]) -> Error(QueryError(pog.ConnectionUnavailable))
    Error(err) -> Error(QueryError(err))
  }
}

pub fn list_recent(
  db: pog.Connection,
  limit: Int,
) -> Result(List(PostRow), pog.QueryError) {
  base_post_select()
  |> s.order_by_desc("posts.id")
  |> s.limit(limit)
  |> s.to_query
  |> postgres.run_read_query(post_row_decoder(), db)
}

pub fn list_before(
  db: pog.Connection,
  before_id: String,
  limit: Int,
) -> Result(List(PostRow), pog.QueryError) {
  case uuid.normalize(before_id) {
    Error(_) -> Ok([])
    Ok(normalized) ->
      base_post_select()
      |> s.where(w.lt(
        w.col("posts.id"),
        w.fragment_value(
          f.prepared(f.placeholder <> "::uuid", [f.string(normalized)]),
        ),
      ))
      |> s.order_by_desc("posts.id")
      |> s.limit(limit)
      |> s.to_query
      |> postgres.run_read_query(post_row_decoder(), db)
  }
}

pub fn list_after(
  db: pog.Connection,
  after_id: String,
  limit: Int,
) -> Result(List(PostRow), pog.QueryError) {
  case uuid.normalize(after_id) {
    Error(_) -> Ok([])
    Ok(normalized) ->
      base_post_select()
      |> s.where(w.gt(
        w.col("posts.id"),
        w.fragment_value(
          f.prepared(f.placeholder <> "::uuid", [f.string(normalized)]),
        ),
      ))
      |> s.order_by_desc("posts.id")
      |> s.limit(limit)
      |> s.to_query
      |> postgres.run_read_query(post_row_decoder(), db)
  }
}

pub fn find_by_id(
  db: pog.Connection,
  id: String,
) -> Result(Option(PostRow), pog.QueryError) {
  case uuid.normalize(id) {
    Error(_) -> Ok(None)
    Ok(normalized) -> {
      let query =
        base_post_select()
        |> s.where(w.eq(
          w.col("posts.id"),
          w.fragment_value(
            f.prepared(f.placeholder <> "::uuid", [f.string(normalized)]),
          ),
        ))
        |> s.limit(1)
        |> s.to_query

      case postgres.run_read_query(query, post_row_decoder(), db) {
        Ok([row, ..]) -> Ok(Some(row))
        Ok([]) -> Ok(None)
        Error(err) -> Error(err)
      }
    }
  }
}

pub fn delete(
  db: pog.Connection,
  id: String,
  user_id: Int,
) -> Result(Bool, pog.QueryError) {
  case uuid.normalize(id) {
    Error(_) -> Ok(False)
    Ok(normalized) -> {
      let query =
        d.new()
        |> d.table("posts")
        |> d.where(
          w.and([
            w.eq(
              w.col("id"),
              w.fragment_value(
                f.prepared(f.placeholder <> "::uuid", [f.string(normalized)]),
              ),
            ),
            w.eq(w.col("user_id"), w.int(user_id)),
          ]),
        )
        |> d.returning(["id"])
        |> d.to_query

      case postgres.run_write_query(query, decode.dynamic, db) {
        Ok([_, ..]) -> Ok(True)
        Ok([]) -> Ok(False)
        Error(err) -> Error(err)
      }
    }
  }
}

fn base_post_select() -> s.Select {
  s.new()
  |> s.from_table("posts")
  |> s.join(j.inner(
    with: j.table("users"),
    on: w.eq(w.col("users.id"), w.col("posts.user_id")),
    alias: "users",
  ))
  |> s.selects([
    s.col("posts.id"),
    s.col("posts.user_id"),
    s.col("users.name"),
    s.col("posts.body"),
    s.col("posts.created_at"),
  ])
}

fn post_row_decoder() -> decode.Decoder(PostRow) {
  use id <- decode.field(0, uuid.decoder())
  use user_id <- decode.field(1, decode.int)
  use author_name <- decode.field(2, decode.string)
  use body <- decode.field(3, decode.string)
  use created_at <- decode.field(4, timestamptz_decoder())
  decode.success(PostRow(id:, user_id:, author_name:, body:, created_at:))
}

fn timestamptz_decoder() -> decode.Decoder(Timestamp) {
  use date <- decode.field(0, pog.calendar_date_decoder())
  use time <- decode.field(1, pog.calendar_time_of_day_decoder())
  decode.success(timestamp.from_calendar(date, time, calendar.utc_offset))
}
