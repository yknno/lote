import gleam/bit_array
import gleam/crypto
import gleam/http
import gleam/http/cookie
import gleam/http/request.{type Request}
import gleam/http/response
import gleam/list
import gleam/option.{Some}
import gleam/result
import wisp

pub const cookie_name = "lote_csrf_token"

pub const form_field_name = "_csrf"

const max_age_seconds = 604_800

pub fn ensure_token(
  req: wisp.Request,
  secret_key_base: String,
) -> #(String, Bool) {
  case read_token(req, secret_key_base) {
    Ok(token) -> #(token, False)
    Error(_) -> #(wisp.random_string(32), True)
  }
}

pub fn attach_cookie(
  resp: wisp.Response,
  req: wisp.Request,
  token: String,
  secret_key_base: String,
  should_set: Bool,
) -> wisp.Response {
  case should_set {
    True -> set_cookie(resp, req, token, secret_key_base)
    False -> resp
  }
}

pub fn rotate_cookie(
  resp: wisp.Response,
  req: wisp.Request,
  secret_key_base: String,
) -> wisp.Response {
  set_cookie(resp, req, wisp.random_string(32), secret_key_base)
}

pub fn read_token(
  req: Request(body),
  secret_key_base: String,
) -> Result(String, Nil) {
  use raw <- result.try(
    req
    |> request.get_cookies
    |> list.key_find(cookie_name),
  )
  use bits <- result.try(
    crypto.verify_signed_message(raw, <<secret_key_base:utf8>>),
  )
  use token <- result.try(bit_array.to_string(bits))
  case token {
    "" -> Error(Nil)
    _ -> Ok(token)
  }
}

pub fn verify_form_token(
  req: Request(body),
  form_values: List(#(String, String)),
  secret_key_base: String,
) -> Result(String, Nil) {
  use expected <- result.try(read_token(req, secret_key_base))
  use submitted <- result.try(list.key_find(form_values, form_field_name))
  case constant_time_equal(expected, submitted) {
    True -> Ok(expected)
    False -> Error(Nil)
  }
}

pub fn require_form_token(
  req: wisp.Request,
  form_values: List(#(String, String)),
  secret_key_base: String,
  next: fn(String) -> wisp.Response,
) -> wisp.Response {
  case verify_form_token(req, form_values, secret_key_base) {
    Ok(token) -> next(token)
    Error(_) -> wisp.response(403) |> wisp.string_body("Invalid CSRF token")
  }
}

fn set_cookie(
  resp: wisp.Response,
  req: wisp.Request,
  token: String,
  secret_key_base: String,
) -> wisp.Response {
  let scheme = case req.host {
    "localhost" | "127.0.0.1" | "[::1]" if req.scheme == http.Http ->
      case request.get_header(req, "x-forwarded-proto") {
        Ok(_) -> http.Https
        Error(_) -> http.Http
      }
    _ -> http.Https
  }
  let attributes =
    cookie.Attributes(..cookie.defaults(scheme), max_age: Some(max_age_seconds))
  let signed =
    crypto.sign_message(<<token:utf8>>, <<secret_key_base:utf8>>, crypto.Sha512)
  response.set_cookie(resp, cookie_name, signed, attributes)
}

fn constant_time_equal(a: String, b: String) -> Bool {
  a != "" && crypto.secure_compare(<<a:utf8>>, <<b:utf8>>)
}
