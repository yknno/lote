import gleam/crypto
import gleam/http
import gleam/http/request
import lote/web/csrf
import wisp
import wisp/simulate

pub fn form_csrf_token_ensure_reuse_and_verification_test() {
  // Use a non-default secret_key_base to verify csrf.attach_cookie and
  // csrf.rotate_cookie sign cookies with the provided secret rather than
  // simulate.default_secret_key_base.
  let secret =
    "custom_csrf_secret_key_base_0123456789abcdefghijklmnopqrstuvwxyz"

  let initial_req = simulate.browser_request(http.Get, "/")
  let #(token, should_set) = csrf.ensure_token(initial_req, secret)
  assert should_set
  let initial_resp =
    wisp.ok() |> csrf.attach_cookie(initial_req, token, secret, should_set)

  // Reuses existing valid token without rotating cookie
  let second_req =
    simulate.browser_request(http.Get, "/")
    |> simulate.session(initial_req, initial_resp)
  assert csrf.ensure_token(second_req, secret) == #(token, False)
  assert csrf.read_token(second_req, secret) == Ok(token)
  assert csrf.read_token(second_req, simulate.default_secret_key_base)
    == Error(Nil)

  // Valid form token succeeds; missing or wrong token fails
  assert csrf.verify_form_token(
      second_req,
      [#(csrf.form_field_name, token)],
      secret,
    )
    == Ok(token)
  assert csrf.verify_form_token(second_req, [], secret) == Error(Nil)
  assert csrf.verify_form_token(
      second_req,
      [#(csrf.form_field_name, "wrong-token")],
      secret,
    )
    == Error(Nil)

  // Rotating issues a new distinct token
  let rotated_resp = wisp.ok() |> csrf.rotate_cookie(second_req, secret)
  let after_rotate_req =
    simulate.browser_request(http.Get, "/")
    |> simulate.session(second_req, rotated_resp)
  let assert Ok(rotated_token) = csrf.read_token(after_rotate_req, secret)
  assert rotated_token != token
  assert csrf.verify_form_token(
      after_rotate_req,
      [#(csrf.form_field_name, token)],
      secret,
    )
    == Error(Nil)
}

pub fn tampered_or_empty_csrf_cookie_is_rejected_test() {
  let secret = "csrf_tamper_test_secret_key_base_0123456789abcdef"
  let empty_signed =
    crypto.sign_message(<<"":utf8>>, <<secret:utf8>>, crypto.Sha512)

  let empty_req =
    simulate.browser_request(http.Post, "/auth/logout")
    |> request.set_cookie(csrf.cookie_name, empty_signed)
  assert csrf.read_token(empty_req, secret) == Error(Nil)
  assert csrf.verify_form_token(
      empty_req,
      [#(csrf.form_field_name, "")],
      secret,
    )
    == Error(Nil)

  // ensure_token must issue a fresh token when the existing cookie is invalid
  let #(new_token, should_set) = csrf.ensure_token(empty_req, secret)
  assert should_set
  assert new_token != ""
}
