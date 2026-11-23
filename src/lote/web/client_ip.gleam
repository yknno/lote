import gleam/http/request.{type Request}
import gleam/list
import gleam/option.{type Option, Some}
import gleam/result
import gleam/string
import mist

/// Extract the canonical client IP from a Mist request using `trusted_proxy_hops`.
/// When `trusted_proxy_hops == 0`, X-Forwarded-For is completely ignored to prevent
/// header spoofing. When `trusted_proxy_hops > 0` (e.g. 1 behind Cloud Run LB),
/// the entry `trusted_proxy_hops` from the right in X-Forwarded-For is selected.
pub fn from_mist_request(
  req: Request(mist.Connection),
  trusted_proxy_hops: Int,
) -> String {
  let peer_ip =
    mist.get_connection_info(req.body)
    |> result.map(fn(info) { mist.ip_address_to_string(info.ip_address) })
    |> option.from_result

  let forwarded_for =
    request.get_header(req, "x-forwarded-for")
    |> option.from_result

  extract(peer_ip, forwarded_for, trusted_proxy_hops)
}

pub fn extract(
  peer_ip: Option(String),
  forwarded_for: Option(String),
  trusted_proxy_hops: Int,
) -> String {
  let raw = case trusted_proxy_hops > 0, forwarded_for {
    True, Some(header) -> {
      let hops =
        header
        |> string.split(",")
        |> list.map(string.trim)
        |> list.filter(fn(part) { part != "" })

      let count = list.length(hops)
      case count >= trusted_proxy_hops {
        True ->
          hops
          |> list.drop(count - trusted_proxy_hops)
          |> list.first
          |> result.unwrap(option.unwrap(peer_ip, "unknown"))
        False -> option.unwrap(peer_ip, "unknown")
      }
    }
    _, _ -> option.unwrap(peer_ip, "unknown")
  }

  normalize(raw)
}

fn normalize(ip: String) -> String {
  let trimmed =
    ip
    |> string.trim
    |> string.lowercase

  case trimmed {
    "" -> "unknown"
    _ ->
      case string.starts_with(trimmed, "::ffff:") {
        True -> string.drop_start(trimmed, 7)
        False -> trimmed
      }
  }
}
