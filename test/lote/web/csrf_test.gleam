import gleam/http
import gleam/http/request
import lote/web/csrf
import wisp
import wisp/simulate

pub fn verify_same_origin_accepts_matching_hosts_and_default_ports_test() {
  let req1 =
    request.new()
    |> request.set_header("host", "localhost:8080")
    |> request.set_header("origin", "http://localhost:8080")
  assert csrf.verify_same_origin(req1)

  let req2 =
    request.new()
    |> request.set_header("host", "Example.COM:443")
    |> request.set_header("origin", "https://example.com")
  assert csrf.verify_same_origin(req2)

  let req3 =
    request.new()
    |> request.set_header("host", "[::1]:8080")
    |> request.set_header("origin", "http://[::1]:8080")
  assert csrf.verify_same_origin(req3)
}

pub fn verify_same_origin_rejects_mismatched_or_missing_origin_test() {
  let cross_origin =
    request.new()
    |> request.set_header("host", "localhost:8080")
    |> request.set_header("origin", "http://evil.example")
  assert !csrf.verify_same_origin(cross_origin)

  let wrong_port =
    request.new()
    |> request.set_header("host", "localhost:8080")
    |> request.set_header("origin", "http://localhost:9999")
  assert !csrf.verify_same_origin(wrong_port)

  let missing_origin =
    request.new()
    |> request.set_header("host", "localhost:8080")
  assert !csrf.verify_same_origin(missing_origin)

  let null_origin =
    request.new()
    |> request.set_header("host", "localhost:8080")
    |> request.set_header("origin", "null")
  assert !csrf.verify_same_origin(null_origin)
}

pub fn form_and_websocket_csrf_token_verification_test() {
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

  // Valid WebSocket request (same origin + signed cookie + query param)
  let valid_ws_req =
    simulate.browser_request(http.Get, "/ws?csrf-token=" <> token)
    |> simulate.session(initial_req, initial_resp)
  assert csrf.verify_websocket_request(valid_ws_req, secret) == Ok(token)

  // WebSocket with mismatched token fails
  let bad_token_ws =
    simulate.browser_request(http.Get, "/ws?csrf-token=wrong")
    |> simulate.session(initial_req, initial_resp)
  assert csrf.verify_websocket_request(bad_token_ws, secret) == Error(Nil)

  // WebSocket with cross-origin header fails even with valid token
  let cross_origin_ws =
    valid_ws_req
    |> request.set_header("origin", "https://evil.example")
  assert csrf.verify_websocket_request(cross_origin_ws, secret) == Error(Nil)
}
