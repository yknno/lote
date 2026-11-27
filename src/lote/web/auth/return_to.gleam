import gleam/bit_array
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/string
import gleam/uri

pub const max_bytes = 2048

pub fn sanitize(raw: Option(String)) -> Option(String) {
  case raw {
    None -> None
    Some(s) ->
      case is_safe_relative_url(s) {
        True -> Some(s)
        False -> None
      }
  }
}

pub fn login_redirect_path(return_to: String) -> String {
  case sanitize(Some(return_to)) {
    Some(valid) ->
      "/auth/login?return_to="
      <> string.replace(uri.percent_encode(valid), each: "+", with: "%2B")
    None -> "/auth/login"
  }
}

fn is_safe_relative_url(s: String) -> Bool {
  case
    s != ""
    && bit_array.byte_size(<<s:utf8>>) <= max_bytes
    && string.starts_with(s, "/")
    && !string.starts_with(s, "//")
    && !string.starts_with(s, "/\\")
    && !string.contains(s, "\\")
    && !has_control_or_ascii_whitespace(s)
  {
    False -> False
    True ->
      case uri.parse(s) {
        Error(_) -> False
        Ok(parsed) ->
          parsed.scheme == None
          && parsed.host == None
          && parsed.userinfo == None
          && parsed.port == None
          && parsed.fragment == None
          && string.starts_with(parsed.path, "/")
          && !string.starts_with(parsed.path, "//")
          && !is_auth_self_loop(parsed.path)
      }
  }
}

fn has_control_or_ascii_whitespace(s: String) -> Bool {
  s
  |> string.to_utf_codepoints
  |> list.any(fn(cp) {
    case string.utf_codepoint_to_int(cp) {
      byte if byte <= 0x20 || byte == 0x7F -> True
      _ -> False
    }
  })
}

fn is_auth_self_loop(path: String) -> Bool {
  case path {
    "/auth/login" | "/auth/password/login" | "/auth/logout" -> True
    _ ->
      case uri.path_segments(path) {
        ["auth", "login"]
        | ["auth", "password", "login"]
        | ["auth", "logout"] -> True
        _ -> False
      }
  }
}
