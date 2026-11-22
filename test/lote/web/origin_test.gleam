import gleam/http/request
import lote/web/origin

pub fn verify_same_origin_accepts_matching_hosts_and_default_ports_test() {
  let req1 =
    request.new()
    |> request.set_header("host", "localhost:8080")
    |> request.set_header("origin", "http://localhost:8080")
  assert origin.verify_same_origin(req1)

  let req2 =
    request.new()
    |> request.set_header("host", "Example.COM:443")
    |> request.set_header("origin", "https://example.com")
  assert origin.verify_same_origin(req2)

  let req3 =
    request.new()
    |> request.set_header("host", "[::1]:8080")
    |> request.set_header("origin", "http://[::1]:8080")
  assert origin.verify_same_origin(req3)
}

pub fn verify_same_origin_rejects_mismatched_missing_or_malformed_origin_test() {
  let cross_origin =
    request.new()
    |> request.set_header("host", "localhost:8080")
    |> request.set_header("origin", "http://evil.example")
  assert !origin.verify_same_origin(cross_origin)

  let wrong_port =
    request.new()
    |> request.set_header("host", "localhost:8080")
    |> request.set_header("origin", "http://localhost:9999")
  assert !origin.verify_same_origin(wrong_port)

  let missing_origin =
    request.new()
    |> request.set_header("host", "localhost:8080")
  assert !origin.verify_same_origin(missing_origin)

  let null_origin =
    request.new()
    |> request.set_header("host", "localhost:8080")
    |> request.set_header("origin", "null")
  assert !origin.verify_same_origin(null_origin)

  let origin_with_path =
    request.new()
    |> request.set_header("host", "localhost:8080")
    |> request.set_header("origin", "http://localhost:8080/extra")
  assert !origin.verify_same_origin(origin_with_path)
}
