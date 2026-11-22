import gleam/int
import gleam/time/calendar
import gleam/time/timestamp.{type Timestamp}
import lustre/attribute
import lustre/element.{type Element}
import lustre/element/html

pub fn lote_time(ts: Timestamp, class: String) -> Element(msg) {
  let iso = timestamp.to_rfc3339(ts, calendar.utc_offset)

  element.element(
    "lote-time",
    [
      attribute.attribute("datetime", iso),
      attribute.class(class),
    ],
    [
      html.time([attribute.datetime(iso)], [
        html.text(format_utc_fallback(ts)),
      ]),
    ],
  )
}

fn format_utc_fallback(ts: Timestamp) -> String {
  let #(date, time) = timestamp.to_calendar(ts, calendar.utc_offset)
  int.to_string(date.year)
  <> "-"
  <> pad2(calendar.month_to_int(date.month))
  <> "-"
  <> pad2(date.day)
  <> " "
  <> pad2(time.hours)
  <> ":"
  <> pad2(time.minutes)
  <> " UTC"
}

fn pad2(n: Int) -> String {
  case n < 10 {
    True -> "0" <> int.to_string(n)
    False -> int.to_string(n)
  }
}
