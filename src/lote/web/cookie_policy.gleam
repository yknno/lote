import gleam/bit_array
import gleam/crypto
import gleam/http
import gleam/http/cookie
import gleam/http/request.{type Request}
import gleam/http/response
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleam/string
import gleam/uri
import wisp

pub const host_prefix = "__Host-"

/// Normalize `req.scheme` from `X-Forwarded-Proto` when `trusted_proxy_hops > 0`.
/// When `trusted_proxy_hops <= 0`, `X-Forwarded-Proto` is completely ignored to
/// prevent untrusted clients from spoofing transport scheme headers.
pub fn apply_trusted_forwarded_proto(
  req: Request(body),
  trusted_proxy_hops: Int,
) -> Request(body) {
  let forwarded_protos =
    list.filter_map(req.headers, fn(header) {
      case string.lowercase(header.0) == "x-forwarded-proto" {
        True -> Ok(header.1)
        False -> Error(Nil)
      }
    })

  case trusted_proxy_hops > 0, forwarded_protos {
    True, [_, ..] -> {
      let hops =
        forwarded_protos
        |> string.join(",")
        |> string.split(",")
        |> list.map(string.trim)
        |> list.filter(fn(part) { part != "" })

      let count = list.length(hops)
      case count >= trusted_proxy_hops {
        True ->
          case
            hops
            |> list.drop(count - trusted_proxy_hops)
            |> list.first
            |> result.map(string.lowercase)
          {
            Ok("https") -> request.set_scheme(req, http.Https)
            Ok("http") -> request.set_scheme(req, http.Http)
            _ -> req
          }
        False -> req
      }
    }
    _, _ -> req
  }
}

pub fn is_loopback_host(host_name: String) -> Bool {
  case string.lowercase(string.trim(host_name)) {
    "localhost" | "127.0.0.1" | "[::1]" | "::1" -> True
    _ -> False
  }
}

pub fn request_host_name(req: Request(body)) -> String {
  let raw_host = case request.get_header(req, "host") {
    Ok(header) if header != "" -> header
    _ -> req.host
  }
  case uri.parse("http://" <> string.trim(raw_host)) {
    Ok(uri.Uri(host: Some(host_name), ..)) -> host_name
    _ -> raw_host
  }
}

/// Plain HTTP cookies and origins are permitted strictly on loopback hosts
/// (`localhost`, `127.0.0.1`, `[::1]`) when the transport scheme is `Http`.
/// All non-loopback hosts and all `Https` requests enforce `Https` (`__Host-`).
pub fn effective_scheme(req: Request(body)) -> http.Scheme {
  case req.scheme == http.Http && is_loopback_host(request_host_name(req)) {
    True -> http.Http
    False -> http.Https
  }
}

pub fn cookie_name(base_name: String, scheme: http.Scheme) -> String {
  case scheme {
    http.Https -> host_prefix <> base_name
    http.Http -> base_name
  }
}

pub fn cookie_name_for_request(
  req: Request(body),
  base_name: String,
) -> String {
  cookie_name(base_name, effective_scheme(req))
}

pub fn read_signed(
  req: Request(body),
  base_name: String,
  secret_key_base: String,
) -> Result(String, Nil) {
  let expected_name = cookie_name_for_request(req, base_name)
  use raw <- result.try(
    req
    |> request.get_cookies
    |> list.key_find(expected_name),
  )
  use bits <- result.try(
    crypto.verify_signed_message(raw, <<secret_key_base:utf8>>),
  )
  use value <- result.try(bit_array.to_string(bits))
  case value {
    "" -> Error(Nil)
    _ -> Ok(value)
  }
}

pub fn set_signed(
  resp: wisp.Response,
  req: wisp.Request,
  base_name: String,
  value: String,
  secret_key_base: String,
  max_age_seconds: Int,
) -> wisp.Response {
  let scheme = effective_scheme(req)
  let name = cookie_name(base_name, scheme)
  let attributes =
    cookie.Attributes(
      ..cookie.defaults(scheme),
      domain: None,
      path: Some("/"),
      http_only: True,
      max_age: Some(max_age_seconds),
    )
  let signed =
    crypto.sign_message(<<value:utf8>>, <<secret_key_base:utf8>>, crypto.Sha512)
  response.set_cookie(resp, name, signed, attributes)
}
