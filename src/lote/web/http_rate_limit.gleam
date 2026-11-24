import gleam/http/response
import gleam/int
import lote/rate_limit
import wisp

pub const write_policy =
  rate_limit.Policy(limit: 30, window_ms: 60_000, burst: 10)

pub fn require_user_write(
  limiter: rate_limit.Limiter,
  user_id: Int,
  next: fn() -> wisp.Response,
) -> wisp.Response {
  case
    rate_limit.check(
      limiter,
      "http:write:user:" <> int.to_string(user_id),
      write_policy,
    )
  {
    rate_limit.Allowed(_) -> next()
    rate_limit.Limited(retry_after_seconds:) ->
      too_many_requests(retry_after_seconds)
  }
}

pub fn too_many_requests(retry_after_seconds: Int) -> wisp.Response {
  wisp.response(429)
  |> response.set_header("retry-after", int.to_string(retry_after_seconds))
  |> wisp.string_body("Too Many Requests")
}
