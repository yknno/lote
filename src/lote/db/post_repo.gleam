import cake/adapter/postgres
import cake/insert as i
import cake/select as s
import gleam/dynamic/decode
import gleam/time/calendar
import gleam/time/timestamp.{type Timestamp}
import pog

pub type PostRow {
  PostRow(id: Int, body: String, created_at: Timestamp)
}

pub fn create(
  db: pog.Connection,
  body: String,
) -> Result(PostRow, pog.QueryError) {
  let query =
    [i.row([i.string(body)])]
    |> i.from_values(table_name: "posts", columns: ["body"])
    |> i.returning(["id", "body", "created_at"])
    |> i.to_query

  case postgres.run_write_query(query, post_decoder(), db) {
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
  |> s.selects([s.col("id"), s.col("body"), s.col("created_at")])
  |> s.order_by_desc("created_at")
  |> s.order_by_desc("id")
  |> s.limit(limit)
  |> s.to_query
  |> postgres.run_read_query(post_decoder(), db)
}

fn post_decoder() -> decode.Decoder(PostRow) {
  use id <- decode.field(0, decode.int)
  use body <- decode.field(1, decode.string)
  use created_at <- decode.field(2, timestamptz_decoder())
  decode.success(PostRow(id:, body:, created_at:))
}

fn timestamptz_decoder() -> decode.Decoder(Timestamp) {
  use date <- decode.field(0, pog.calendar_date_decoder())
  use time <- decode.field(1, pog.calendar_time_of_day_decoder())
  decode.success(timestamp.from_calendar(date, time, calendar.utc_offset))
}
