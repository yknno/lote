import cake/adapter/postgres
import cake/insert as i
import cake/join as j
import cake/select as s
import cake/where as w
import gleam/dynamic/decode
import gleam/time/calendar
import gleam/time/timestamp.{type Timestamp}
import pog

pub type CreatedPost {
  CreatedPost(id: Int, user_id: Int, body: String, created_at: Timestamp)
}

pub type PostRow {
  PostRow(
    id: Int,
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
    use id <- decode.field(0, decode.int)
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
  |> s.order_by_desc("posts.id")
  |> s.limit(limit)
  |> s.to_query
  |> postgres.run_read_query(post_row_decoder(), db)
}

fn post_row_decoder() -> decode.Decoder(PostRow) {
  use id <- decode.field(0, decode.int)
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
