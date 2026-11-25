import gleam/http
import gleam/http/request.{type Request}
import gleam/option.{type Option, None, Some}
import gleam/string
import gleam/uri
import lote/web/cookie_policy

pub fn verify_same_origin(req: Request(body)) -> Bool {
  case request.get_header(req, "origin"), request.get_header(req, "host") {
    Ok(origin), Ok(host) -> origins_match(req.scheme, origin, host)
    _, _ -> False
  }
}

fn origins_match(
  req_scheme: http.Scheme,
  origin: String,
  host: String,
) -> Bool {
  case uri.parse(origin) {
    Ok(uri.Uri(
      scheme: Some(scheme),
      userinfo: None,
      host: Some(origin_host),
      port: origin_port,
      path: "",
      query: None,
      fragment: None,
    )) -> {
      let scheme = string.lowercase(scheme)
      case scheme {
        "http" | "https" ->
          case uri.parse(scheme <> "://" <> host) {
            Ok(uri.Uri(
              userinfo: None,
              host: Some(host_name),
              port: host_port,
              path: "",
              query: None,
              fragment: None,
              ..,
            )) -> {
              let expected_scheme = case
                req_scheme == http.Http
                && cookie_policy.is_loopback_host(host_name)
              {
                True -> "http"
                False -> "https"
              }
              scheme == expected_scheme
              && string.lowercase(origin_host) == string.lowercase(host_name)
              && normalize_port(scheme, origin_port)
              == normalize_port(scheme, host_port)
            }
            _ -> False
          }
        _ -> False
      }
    }
    _ -> False
  }
}

fn normalize_port(scheme: String, port: Option(Int)) -> Option(Int) {
  case scheme, port {
    "http", Some(80) -> None
    "https", Some(443) -> None
    _, other -> other
  }
}
