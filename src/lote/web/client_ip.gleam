import gleam/http/request.{type Request}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
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

/// Extract and canonicalize the client IP address.
/// IPv4-mapped IPv6 addresses (`::ffff:0:0/96`, in both dotted-decimal and hex
/// notation) are unwrapped to IPv4, and IPv6 addresses are formatted in
/// lowercase RFC 5952 compressed form. Malformed X-Forwarded-For entries fall
/// back to `peer_ip` (or `"unknown"`).
pub fn extract(
  peer_ip: Option(String),
  forwarded_for: Option(String),
  trusted_proxy_hops: Int,
) -> String {
  let xff_candidate = case trusted_proxy_hops > 0, forwarded_for {
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
          |> option.from_result
        False -> None
      }
    }
    _, _ -> None
  }

  let from_xff =
    xff_candidate
    |> option.then(fn(raw) { canonicalize(raw) |> option.from_result })

  case from_xff {
    Some(ip) -> ip
    None ->
      peer_ip
      |> option.then(fn(raw) { canonicalize(raw) |> option.from_result })
      |> option.unwrap("unknown")
  }
}

/// Convert a client IP into its rate-limit bucket key:
/// - IPv4 (including unwrapped `::ffff:0:0/96` IPv4-mapped IPv6): `/32`
/// - IPv6: `/64` (masks the 64-bit interface identifier so Privacy Extensions
///   or attacker address rotation within a `/64` allocation cannot bypass
///   IP-based rate limits)
/// - Unparseable / `"unknown"`: `"unknown"`
pub fn rate_limit_bucket(ip: String) -> String {
  ip
  |> strip_framing
  |> ffi_rate_limit_bucket
  |> result.unwrap("unknown")
}

fn canonicalize(raw: String) -> Result(String, Nil) {
  raw
  |> strip_framing
  |> ffi_parse_canonical
}

fn strip_framing(raw: String) -> String {
  let trimmed = string.trim(raw)

  let unbracketed = case string.starts_with(trimmed, "[") {
    True ->
      case string.split_once(string.drop_start(trimmed, 1), "]") {
        Ok(#(inner, _rest)) -> inner
        Error(Nil) -> trimmed
      }
    False ->
      // Strip optional `:port` from IPv4 addresses (IPv6 always contains >=2 colons)
      case string.split(trimmed, ":") {
        [host, port] ->
          case int.parse(port) {
            Ok(p) if p >= 0 && p <= 65_535 -> host
            _ -> trimmed
          }
        _ -> trimmed
      }
  }

  // Strip optional IPv6 zone identifier (e.g. `fe80::1%eth0`)
  case string.split_once(unbracketed, "%") {
    Ok(#(addr, _zone)) -> addr
    Error(Nil) -> unbracketed
  }
}

@external(erlang, "lote_client_ip_ffi", "parse_canonical")
fn ffi_parse_canonical(ip: String) -> Result(String, Nil)

@external(erlang, "lote_client_ip_ffi", "rate_limit_bucket")
fn ffi_rate_limit_bucket(ip: String) -> Result(String, Nil)
