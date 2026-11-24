import gleam/http/response
import gleam/int
import lote/rate_limit
import lote/web/rate_policy
import wisp

pub const write_policy = rate_policy.http_write_user_policy

pub fn require_user_write(
  limiter: rate_limit.Limiter,
  user_id: Int,
  next: fn() -> wisp.Response,
) -> wisp.Response {
  case
    rate_limit.check(
      limiter,
      rate_policy.http_write_user_key(user_id),
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
