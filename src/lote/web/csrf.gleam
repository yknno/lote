import gleam/bit_array
import gleam/crypto
import gleam/http/request.{type Request}
import gleam/list
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
  should_set: Bool,
) -> wisp.Response {
  case should_set {
    True -> set_cookie(resp, req, token)
    False -> resp
  }
}

pub fn rotate_cookie(resp: wisp.Response, req: wisp.Request) -> wisp.Response {
  set_cookie(resp, req, wisp.random_string(32))
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
) -> wisp.Response {
  wisp.set_cookie(resp, req, cookie_name, token, wisp.Signed, max_age_seconds)
}

fn constant_time_equal(a: String, b: String) -> Bool {
  a != "" && crypto.secure_compare(<<a:utf8>>, <<b:utf8>>)
}
