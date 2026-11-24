import gleam/http/response
import gleam/int
import lote/rate_limit
import lote/web/client_ip
import wisp

pub const write_policy =
  rate_limit.Policy(limit: 30, window_ms: 60_000, burst: 10)

pub fn require_user_write(
  limiter: rate_limit.Limiter,
  user_id: Int,
  next: fn() -> wisp.Response,
) -> wisp.Response {
  require_key(limiter, "http:write:user:" <> int.to_string(user_id), next)
}

pub fn require_ip_write(
  limiter: rate_limit.Limiter,
  ip: String,
  next: fn() -> wisp.Response,
) -> wisp.Response {
  require_key(
    limiter,
    "http:write:ip:" <> client_ip.rate_limit_bucket(ip),
    next,
  )
}

fn require_key(
  limiter: rate_limit.Limiter,
  key: String,
  next: fn() -> wisp.Response,
) -> wisp.Response {
  case rate_limit.check(limiter, key, write_policy) {
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
