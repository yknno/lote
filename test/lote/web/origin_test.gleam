import gleam/http
import gleam/http/request
import lote/web/cookie_policy
import lote/web/origin

pub fn verify_same_origin_accepts_matching_hosts_schemes_and_default_ports_test() {
  let req1 =
    request.new()
    |> request.set_scheme(http.Http)
    |> request.set_header("host", "localhost:8080")
    |> request.set_header("origin", "http://localhost:8080")
  assert origin.verify_same_origin(req1)

  let req2 =
    request.new()
    |> request.set_scheme(http.Https)
    |> request.set_header("host", "Example.COM:443")
    |> request.set_header("origin", "https://example.com")
  assert origin.verify_same_origin(req2)

  // Behind a TLS-terminating reverse proxy even before X-Forwarded-Proto normalization,
  // non-loopback hosts accept https Origins
  let req2_proxy =
    request.new()
    |> request.set_scheme(http.Http)
    |> request.set_header("host", "example.com")
    |> request.set_header("origin", "https://example.com")
  assert origin.verify_same_origin(req2_proxy)

  let req3 =
    request.new()
    |> request.set_scheme(http.Http)
    |> request.set_header("host", "[::1]:8080")
    |> request.set_header("origin", "http://[::1]:8080")
  assert origin.verify_same_origin(req3)
}

pub fn verify_same_origin_rejects_cross_scheme_origin_downgrade_test() {
  // Non-loopback host MUST reject http:// Origin even if transport socket is plain TCP
  let prod_http_origin =
    request.new()
    |> request.set_scheme(http.Http)
    |> request.set_header("host", "example.com")
    |> request.set_header("origin", "http://example.com")
  assert !origin.verify_same_origin(prod_http_origin)

  let prod_https_socket_http_origin =
    request.new()
    |> request.set_scheme(http.Https)
    |> request.set_header("host", "example.com")
    |> request.set_header("origin", "http://example.com")
  assert !origin.verify_same_origin(prod_https_socket_http_origin)

  // HTTPS loopback (direct TLS or via trusted X-Forwarded-Proto) rejects http:// Origin
  let https_loopback_downgrade =
    request.new()
    |> request.set_scheme(http.Http)
    |> request.set_header("host", "localhost:8443")
    |> request.set_header("x-forwarded-proto", "https")
    |> request.set_header("origin", "http://localhost:8443")
    |> cookie_policy.apply_trusted_forwarded_proto(1)
  assert !origin.verify_same_origin(https_loopback_downgrade)

  let https_loopback_valid =
    request.new()
    |> request.set_scheme(http.Http)
    |> request.set_header("host", "localhost:8443")
    |> request.set_header("x-forwarded-proto", "https")
    |> request.set_header("origin", "https://localhost:8443")
    |> cookie_policy.apply_trusted_forwarded_proto(1)
  assert origin.verify_same_origin(https_loopback_valid)

  // Untrusted X-Forwarded-Proto (trusted_proxy_hops == 0) is ignored on plain-HTTP loopback
  let spoofed_xfp_loopback =
    request.new()
    |> request.set_scheme(http.Http)
    |> request.set_header("host", "localhost:8080")
    |> request.set_header("x-forwarded-proto", "https")
    |> request.set_header("origin", "http://localhost:8080")
    |> cookie_policy.apply_trusted_forwarded_proto(0)
  assert origin.verify_same_origin(spoofed_xfp_loopback)

  // Multiple X-Forwarded-Proto headers: attacker sends "http", proxy appends "https".
  let multi_xfp_req =
    request.Request(..request.new(), scheme: http.Http, headers: [
      #("host", "localhost:8443"),
      #("x-forwarded-proto", "http"),
      #("X-Forwarded-Proto", "https"),
      #("origin", "https://localhost:8443"),
    ])
    |> cookie_policy.apply_trusted_forwarded_proto(1)
  assert multi_xfp_req.scheme == http.Https
  assert origin.verify_same_origin(multi_xfp_req)
}

pub fn verify_same_origin_rejects_mismatched_missing_or_malformed_origin_test() {
  let cross_origin =
    request.new()
    |> request.set_scheme(http.Http)
    |> request.set_header("host", "localhost:8080")
    |> request.set_header("origin", "http://evil.example")
  assert !origin.verify_same_origin(cross_origin)

  let wrong_port =
    request.new()
    |> request.set_scheme(http.Http)
    |> request.set_header("host", "localhost:8080")
    |> request.set_header("origin", "http://localhost:9999")
  assert !origin.verify_same_origin(wrong_port)

  let missing_origin =
    request.new()
    |> request.set_scheme(http.Http)
    |> request.set_header("host", "localhost:8080")
  assert !origin.verify_same_origin(missing_origin)

  let null_origin =
    request.new()
    |> request.set_scheme(http.Http)
    |> request.set_header("host", "localhost:8080")
    |> request.set_header("origin", "null")
  assert !origin.verify_same_origin(null_origin)

  let origin_with_path =
    request.new()
    |> request.set_scheme(http.Http)
    |> request.set_header("host", "localhost:8080")
    |> request.set_header("origin", "http://localhost:8080/extra")
  assert !origin.verify_same_origin(origin_with_path)
}
