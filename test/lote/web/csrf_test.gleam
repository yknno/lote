import gleam/http
import lote/web/csrf
import wisp
import wisp/simulate

pub fn form_csrf_token_ensure_reuse_and_verification_test() {
  let secret = simulate.default_secret_key_base

  let initial_req = simulate.browser_request(http.Get, "/")
  let #(token, should_set) = csrf.ensure_token(initial_req, secret)
  assert should_set
  let initial_resp =
    wisp.ok() |> csrf.attach_cookie(initial_req, token, should_set)

  // Reuses existing valid token without rotating cookie
  let second_req =
    simulate.browser_request(http.Get, "/")
    |> simulate.session(initial_req, initial_resp)
  assert csrf.ensure_token(second_req, secret) == #(token, False)
  assert csrf.read_token(second_req, secret) == Ok(token)

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
  let rotated_resp = wisp.ok() |> csrf.rotate_cookie(second_req)
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
