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
import gleam/string
import gleam/time/calendar
import gleam/time/timestamp.{type Timestamp}
import pog

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

pub fn create(
  db: pog.Connection,
  user_id: Int,
  body: String,
) -> Result(CreatedPost, pog.QueryError) {
  let query =
    [i.row([i.int(user_id), i.string(body)])]
    |> i.from_values(table_name: "posts", columns: ["user_id", "body"])
    |> i.returning(["id", "user_id", "body", "created_at"])
    |> i.to_query

  let decoder = {
    use id <- decode.field(0, uuid_decoder())
    use uid <- decode.field(1, decode.int)
    use body <- decode.field(2, decode.string)
    use created_at <- decode.field(3, timestamptz_decoder())
    decode.success(CreatedPost(id:, user_id: uid, body:, created_at:))
  }

  case postgres.run_write_query(query, decoder, db) {
    Ok([row, ..]) -> Ok(row)
    Ok([]) -> Error(pog.ConnectionUnavailable)
    Error(err) -> Error(err)
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
  case normalize_uuid(before_id) {
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

pub fn find_by_id(
  db: pog.Connection,
  id: String,
) -> Result(Option(PostRow), pog.QueryError) {
  case normalize_uuid(id) {
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
  case normalize_uuid(id) {
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
  use id <- decode.field(0, uuid_decoder())
  use user_id <- decode.field(1, decode.int)
  use author_name <- decode.field(2, decode.string)
  use body <- decode.field(3, decode.string)
  use created_at <- decode.field(4, timestamptz_decoder())
  decode.success(PostRow(id:, user_id:, author_name:, body:, created_at:))
}

fn uuid_decoder() -> decode.Decoder(String) {
  use bytes <- decode.then(decode.bit_array)
  case format_uuid(bytes) {
    Ok(uuid) -> decode.success(uuid)
    Error(_) -> decode.failure("", "UUID")
  }
}

fn format_uuid(bytes: BitArray) -> Result(String, Nil) {
  case bytes {
    <<
      a:bytes-size(4),
      b:bytes-size(2),
      c:bytes-size(2),
      d:bytes-size(2),
      e:bytes-size(6),
    >> ->
      Ok(
        hex(a)
        <> "-"
        <> hex(b)
        <> "-"
        <> hex(c)
        <> "-"
        <> hex(d)
        <> "-"
        <> hex(e),
      )
    _ -> Error(Nil)
  }
}

fn hex(bytes: BitArray) -> String {
  bytes |> bit_array.base16_encode |> string.lowercase
}

fn normalize_uuid(input: String) -> Result(String, Nil) {
  let lower = string.lowercase(input)
  case string.split(lower, "-") {
    [a, b, c, d, e] ->
      case
        is_hex_len(a, 8)
        && is_hex_len(b, 4)
        && is_hex_len(c, 4)
        && is_hex_len(d, 4)
        && is_hex_len(e, 12)
      {
        True -> Ok(lower)
        False -> Error(Nil)
      }
    _ -> Error(Nil)
  }
}

fn is_hex_len(s: String, expected_len: Int) -> Bool {
  string.length(s) == expected_len
  && s
  |> string.to_utf_codepoints
  |> list.all(fn(cp) {
    let n = string.utf_codepoint_to_int(cp)
    { n >= 48 && n <= 57 } || { n >= 97 && n <= 102 }
  })
}

fn timestamptz_decoder() -> decode.Decoder(Timestamp) {
  use date <- decode.field(0, pog.calendar_date_decoder())
  use time <- decode.field(1, pog.calendar_time_of_day_decoder())
  decode.success(timestamp.from_calendar(date, time, calendar.utc_offset))
}
