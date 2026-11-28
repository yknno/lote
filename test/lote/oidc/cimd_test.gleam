import gleam/erlang/atom.{type Atom}
import gleam/erlang/process
import gleam/option.{type Option, None, Some}
import gleam/set
import gleam/string
import lote/auth/user
import lote/oidc/cimd
import lote/oidc/cleanup
import lote/oidc/client
import lote/oidc/grant
import lote/oidc/scope
import lote/test_helper
import pog

type TestRootCerts

pub fn ip_classification_blocks_all_special_purpose_ipv4_and_ipv6_ranges_test() {
  // Public routable IPv4 and IPv6 addresses
  assert ffi_is_global_public_ip_string("8.8.8.8")
  assert ffi_is_global_public_ip_string("1.1.1.1")
  assert ffi_is_global_public_ip_string("93.184.216.34")
  assert ffi_is_global_public_ip_string("100.63.255.255")
  assert ffi_is_global_public_ip_string("100.128.0.1")
  assert ffi_is_global_public_ip_string("172.15.255.255")
  assert ffi_is_global_public_ip_string("172.32.0.1")
  assert ffi_is_global_public_ip_string("2606:4700:4700::1111")
  assert ffi_is_global_public_ip_string("2001:4860:4860::8888")

  // Blocked special-purpose IPv4 ranges
  assert !ffi_is_global_public_ip_string("0.0.0.0")
  assert !ffi_is_global_public_ip_string("10.0.0.1")
  assert !ffi_is_global_public_ip_string("100.64.0.1")
  assert !ffi_is_global_public_ip_string("100.127.255.254")
  assert !ffi_is_global_public_ip_string("127.0.0.1")
  assert !ffi_is_global_public_ip_string("169.254.169.254")
  assert !ffi_is_global_public_ip_string("172.16.0.1")
  assert !ffi_is_global_public_ip_string("172.31.255.255")
  assert !ffi_is_global_public_ip_string("192.0.0.1")
  assert !ffi_is_global_public_ip_string("192.0.2.1")
  assert !ffi_is_global_public_ip_string("192.88.99.1")
  assert !ffi_is_global_public_ip_string("192.168.1.1")
  assert !ffi_is_global_public_ip_string("198.18.0.1")
  assert !ffi_is_global_public_ip_string("198.19.255.255")
  assert !ffi_is_global_public_ip_string("198.51.100.1")
  assert !ffi_is_global_public_ip_string("203.0.113.1")
  assert !ffi_is_global_public_ip_string("224.0.0.1")
  assert !ffi_is_global_public_ip_string("240.0.0.1")
  assert !ffi_is_global_public_ip_string("255.255.255.255")

  // Blocked special-purpose IPv6 ranges (including 3fff::/20, full 2001::/23, IPv4-mapped, NAT64, 6to4, Teredo, ULA)
  assert !ffi_is_global_public_ip_string("::")
  assert !ffi_is_global_public_ip_string("::1")
  assert !ffi_is_global_public_ip_string("::ffff:127.0.0.1")
  assert !ffi_is_global_public_ip_string("::ffff:8.8.8.8")
  assert !ffi_is_global_public_ip_string("64:ff9b::1")
  assert !ffi_is_global_public_ip_string("100::1")
  assert !ffi_is_global_public_ip_string("2001::1")
  assert !ffi_is_global_public_ip_string("2001:1::1")
  assert !ffi_is_global_public_ip_string("2001:2::1")
  assert !ffi_is_global_public_ip_string("2001:10::1")
  assert !ffi_is_global_public_ip_string("2001:20::1")
  assert !ffi_is_global_public_ip_string("2001:30::1")
  assert !ffi_is_global_public_ip_string("2001:1ff::1")
  assert !ffi_is_global_public_ip_string("2001:db8::1")
  assert !ffi_is_global_public_ip_string("2002:7f00:1::")
  assert !ffi_is_global_public_ip_string("3fff::1")
  assert !ffi_is_global_public_ip_string("3fff:fff::1")
  assert !ffi_is_global_public_ip_string("fc00::1")
  assert !ffi_is_global_public_ip_string("fd12:3456::1")
  assert !ffi_is_global_public_ip_string("fe80::1")
  assert !ffi_is_global_public_ip_string("ff02::1")
}

pub fn validate_client_id_url_and_host_extraction_test() {
  assert cimd.is_cimd_client_id("https://app.example.com/oauth/client.json")
  assert !cimd.is_cimd_client_id("cli_0123456789abcdef0123456789abcdef")
  assert !cimd.is_cimd_client_id("http://app.example.com/oauth/client.json")

  let assert Ok(u1) =
    cimd.validate_client_id_url("https://app.example.com/oauth/client.json")
  assert u1.path == "/oauth/client.json"
  assert cimd.client_id_host("https://app.example.com/oauth/client.json")
    == Some("app.example.com")
  assert cimd.client_id_authority("https://app.example.com/oauth/client.json")
    == Some("app.example.com")
  assert cimd.client_id_authority(
      "https://app.example.com:443/oauth/client.json",
    )
    == Some("app.example.com")

  let assert Ok(u2) =
    cimd.validate_client_id_url("https://Sub.Example.com:8443/v1/meta")
  assert u2.port == Some(8443)
  assert cimd.client_id_host("https://Sub.Example.com:8443/v1/meta")
    == Some("sub.example.com")
  assert cimd.client_id_authority("https://Sub.Example.com:8443/v1/meta")
    == Some("sub.example.com:8443")

  // Invalid schemes, empty/root/double-slash paths, bad percent-escapes, dot segments, fragments, queries, userinfo, bad ports
  let assert Error(_) = cimd.validate_client_id_url("")
  let assert Error(_) =
    cimd.validate_client_id_url("http://app.example.com/oauth/client.json")
  let assert Error(_) =
    cimd.validate_client_id_url("HTTPS://app.example.com/oauth/client.json")
  let assert Error(_) = cimd.validate_client_id_url("https://app.example.com")
  let assert Error(_) = cimd.validate_client_id_url("https://app.example.com/")
  let assert Error(_) =
    cimd.validate_client_id_url("https://app.example.com///")
  let assert Error(_) =
    cimd.validate_client_id_url("https://app.example.com//evil.example/meta")
  let assert Error(_) =
    cimd.validate_client_id_url("https://app.example.com/oauth/%GG")
  let assert Error(_) =
    cimd.validate_client_id_url("https://app.example.com/oauth/%")
  let assert Error(_) =
    cimd.validate_client_id_url("https://app.example.com/./client.json")
  let assert Error(_) =
    cimd.validate_client_id_url("https://app.example.com/a/../client.json")
  let assert Error(_) =
    cimd.validate_client_id_url("https://app.example.com/a/%2e%2e/client.json")
  let assert Error(_) =
    cimd.validate_client_id_url("https://app.example.com/a/%2E/client.json")
  let assert Error(_) =
    cimd.validate_client_id_url("https://app.example.com/a%2fb")
  let assert Error(_) =
    cimd.validate_client_id_url("https://app.example.com/a%5cb")
  let assert Error(_) =
    cimd.validate_client_id_url("https://app.example.com/client.json#frag")
  let assert Error(_) =
    cimd.validate_client_id_url("https://app.example.com/client.json#")
  let assert Error(_) =
    cimd.validate_client_id_url("https://app.example.com/client.json?query=1")
  let assert Error(_) =
    cimd.validate_client_id_url(
      "https://user:pass@app.example.com/oauth/client.json",
    )
  let assert Error(_) =
    cimd.validate_client_id_url("https://app.example.com:/oauth/client.json")
  let assert Error(_) =
    cimd.validate_client_id_url(
      "https://app.example.com:0443/oauth/client.json",
    )
  let assert Error(_) =
    cimd.validate_client_id_url(
      "https://app.example.com:65536/oauth/client.json",
    )

  // Local / intranet / IP literal hosts and >512-byte URLs
  let assert Error(_) = cimd.validate_client_id_url("https://localhost/c")
  let assert Error(_) = cimd.validate_client_id_url("https://sub.localhost/c")
  let assert Error(_) = cimd.validate_client_id_url("https://foo.local/c")
  let assert Error(_) = cimd.validate_client_id_url("https://foo.internal/c")
  let assert Error(_) = cimd.validate_client_id_url("https://box.home.arpa/c")
  let assert Error(_) = cimd.validate_client_id_url("https://intranet/c")
  let assert Error(_) = cimd.validate_client_id_url("https://127.0.0.1/c")
  let assert Error(_) = cimd.validate_client_id_url("https://127.1/c")
  let assert Error(_) = cimd.validate_client_id_url("https://0x7f000001/c")
  let assert Error(_) = cimd.validate_client_id_url("https://0177.0.0.1/c")
  let assert Error(_) = cimd.validate_client_id_url("https://[::1]/c")
  let assert Error(_) =
    cimd.validate_client_id_url("https://[2606:4700:4700::1111]/c")
  let assert Error(_) =
    cimd.validate_client_id_url(
      "https://app.example.com/" <> string.repeat("a", 500),
    )

  assert cimd.client_id_host("https://127.0.0.1/c") == None
}

pub fn parse_and_validate_document_strict_compliance_test() {
  let cid = "https://app.example.com/oauth/client.json"

  // Minimal valid document: defaults name to host, Web app type, all scopes, 300s TTL
  let minimal_json =
    "{\"client_id\":\"https://app.example.com/oauth/client.json\",\"redirect_uris\":[\"https://app.example.com/cb\"]}"
  let assert Ok(meta1) =
    cimd.parse_and_validate_document(
      cid,
      json_response(200, "application/json; charset=utf-8", None, minimal_json),
    )
  assert meta1.client_id == cid
  assert meta1.client_name == "app.example.com"
  assert meta1.application_type == client.Web
  assert meta1.redirect_uris == ["https://app.example.com/cb"]
  assert meta1.allowed_scopes == set.from_list(scope.all())
  assert meta1.cache_ttl_seconds == cimd.default_cache_ttl_seconds

  // Full native client metadata + scope filtering + Cache-Control clamping
  let native_json =
    "{\"client_id\":\"https://app.example.com/oauth/client.json\",\"client_name\":\"Example CLI\",\"application_type\":\"native\",\"token_endpoint_auth_method\":\"none\",\"grant_types\":[\"authorization_code\",\"refresh_token\"],\"response_types\":[\"code\"],\"scope\":\"openid email posts:read\",\"redirect_uris\":[\"http://127.0.0.1/cb\"]}"
  let assert Ok(meta2) =
    cimd.parse_and_validate_document(
      cid,
      json_response(
        200,
        "application/json",
        Some("public, max-age=1200"),
        native_json,
      ),
    )
  assert meta2.client_name == "Example CLI"
  assert meta2.application_type == client.Native
  assert meta2.allowed_scopes == set.from_list([scope.OpenId, scope.PostsRead])
  assert meta2.cache_ttl_seconds == 1200

  // Cache-Control min/max clamping
  let assert Ok(meta_min) =
    cimd.parse_and_validate_document(
      cid,
      json_response(200, "application/json", Some("max-age=5"), minimal_json),
    )
  assert meta_min.cache_ttl_seconds == cimd.min_cache_ttl_seconds

  let assert Ok(meta_nostore) =
    cimd.parse_and_validate_document(
      cid,
      json_response(
        200,
        "application/json",
        Some("no-store, max-age=3600"),
        minimal_json,
      ),
    )
  assert meta_nostore.cache_ttl_seconds == cimd.min_cache_ttl_seconds

  let assert Ok(meta_max) =
    cimd.parse_and_validate_document(
      cid,
      json_response(
        200,
        "application/json",
        Some("max-age=999999"),
        minimal_json,
      ),
    )
  assert meta_max.cache_ttl_seconds == cimd.max_cache_ttl_seconds

  // Status != 200 (including 302 redirect) and wrong Content-Type
  let assert Error(cimd.UnexpectedStatus(302)) =
    cimd.parse_and_validate_document(
      cid,
      json_response(302, "application/json", None, minimal_json),
    )
  let assert Error(cimd.InvalidContentType("text/html")) =
    cimd.parse_and_validate_document(
      cid,
      json_response(200, "text/html", None, minimal_json),
    )

  // Exact byte-for-byte client_id matching (:443 or path difference rejected)
  let assert Error(cimd.InvalidDocument(_)) =
    cimd.parse_and_validate_document(
      cid,
      json_response(
        200,
        "application/json",
        None,
        "{\"client_id\":\"https://app.example.com:443/oauth/client.json\",\"redirect_uris\":[\"https://app.example.com/cb\"]}",
      ),
    )
  let assert Error(cimd.InvalidDocument(_)) =
    cimd.parse_and_validate_document(
      cid,
      json_response(
        200,
        "application/json",
        None,
        "{\"client_id\":\"https://app.example.com/other.json\",\"redirect_uris\":[\"https://app.example.com/cb\"]}",
      ),
    )

  // Duplicate JSON keys rejected
  let assert Error(cimd.InvalidDocument(_)) =
    cimd.parse_and_validate_document(
      cid,
      json_response(
        200,
        "application/json",
        None,
        "{\"client_id\":\"https://evil.example.com/c\",\"client_id\":\"https://app.example.com/oauth/client.json\",\"redirect_uris\":[\"https://app.example.com/cb\"]}",
      ),
    )

  // Forbidden client_secret / client_secret_expires_at / non-"none" auth methods
  let assert Error(cimd.InvalidDocument(_)) =
    cimd.parse_and_validate_document(
      cid,
      json_response(
        200,
        "application/json",
        None,
        "{\"client_id\":\"https://app.example.com/oauth/client.json\",\"client_secret\":\"s3cr3t\",\"redirect_uris\":[\"https://app.example.com/cb\"]}",
      ),
    )
  let assert Error(cimd.InvalidDocument(_)) =
    cimd.parse_and_validate_document(
      cid,
      json_response(
        200,
        "application/json",
        None,
        "{\"client_id\":\"https://app.example.com/oauth/client.json\",\"client_secret_expires_at\":0,\"redirect_uris\":[\"https://app.example.com/cb\"]}",
      ),
    )
  let assert Error(cimd.InvalidDocument(_)) =
    cimd.parse_and_validate_document(
      cid,
      json_response(
        200,
        "application/json",
        None,
        "{\"client_id\":\"https://app.example.com/oauth/client.json\",\"token_endpoint_auth_method\":\"client_secret_basic\",\"redirect_uris\":[\"https://app.example.com/cb\"]}",
      ),
    )
  let assert Error(cimd.InvalidDocument(_)) =
    cimd.parse_and_validate_document(
      cid,
      json_response(
        200,
        "application/json",
        None,
        "{\"client_id\":\"https://app.example.com/oauth/client.json\",\"token_endpoint_auth_method\":\"private_key_jwt\",\"redirect_uris\":[\"https://app.example.com/cb\"]}",
      ),
    )

  // Invalid redirect_uris, grant_types, response_types, or unsupported scopes
  let assert Error(cimd.InvalidDocument(_)) =
    cimd.parse_and_validate_document(
      cid,
      json_response(
        200,
        "application/json",
        None,
        "{\"client_id\":\"https://app.example.com/oauth/client.json\",\"redirect_uris\":[\"http://app.example.com/cb\"]}",
      ),
    )
  let assert Error(cimd.InvalidDocument(_)) =
    cimd.parse_and_validate_document(
      cid,
      json_response(
        200,
        "application/json",
        None,
        "{\"client_id\":\"https://app.example.com/oauth/client.json\",\"grant_types\":[\"client_credentials\"],\"redirect_uris\":[\"https://app.example.com/cb\"]}",
      ),
    )
  let assert Error(cimd.InvalidDocument(_)) =
    cimd.parse_and_validate_document(
      cid,
      json_response(
        200,
        "application/json",
        None,
        "{\"client_id\":\"https://app.example.com/oauth/client.json\",\"response_types\":[\"token\"],\"redirect_uris\":[\"https://app.example.com/cb\"]}",
      ),
    )
  let assert Error(cimd.InvalidDocument(_)) =
    cimd.parse_and_validate_document(
      cid,
      json_response(
        200,
        "application/json",
        None,
        "{\"client_id\":\"https://app.example.com/oauth/client.json\",\"scope\":\"email custom:unknown\",\"redirect_uris\":[\"https://app.example.com/cb\"]}",
      ),
    )
}

pub fn tls_socket_framing_and_ssrf_blocking_test() {
  let fetcher = cimd.default_fetcher()

  // Direct SSRF attempts blocked before any socket connect
  let assert Error(cimd.BlockedAddress(_)) =
    fetcher("https://127.0.0.1/client.json")
  let assert Error(cimd.BlockedAddress(_)) =
    fetcher("https://169.254.169.254/latest/meta-data/")
  let assert Error(cimd.BlockedAddress(_)) =
    fetcher("https://[::1]/client.json")
  let assert Error(cimd.BlockedAddress(_)) =
    fetcher("https://localhost/client.json")

  // Real TLS 1.3 socket with HTTP/1.1 chunked response + SNI + PKIX hostname check
  let chunked_raw = <<
    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nCache-Control: max-age=180\r\n\r\n38\r\n{\"client_id\":\"https://app.example.com/oauth/client.json\"\r\n2f\r\n,\"redirect_uris\":[\"https://app.example.com/cb\"]\r\n1\r\n}\r\n0\r\n\r\n":utf8,
  >>
  let #(port1, roots1) = ffi_test_serve_tls_once("app.example.com", chunked_raw)
  let assert Ok(#(200, "application/json", Some("max-age=180"), body1)) =
    ffi_fetch_tls_pinned_for_test(
      "127.0.0.1",
      port1,
      "app.example.com",
      "/oauth/client.json",
      roots1,
      cimd.max_document_bytes,
    )
  let assert Ok(parsed) =
    cimd.parse_and_validate_document(
      "https://app.example.com/oauth/client.json",
      cimd.FetchResponse(
        status: 200,
        content_type: "application/json",
        cache_control: Some("max-age=180"),
        body: body1,
      ),
    )
  assert parsed.cache_ttl_seconds == 180

  // Oversized response body aborted immediately
  let oversized_raw = <<
    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 20000\r\n\r\n{}":utf8,
  >>
  let #(port2, roots2) =
    ffi_test_serve_tls_once("app.example.com", oversized_raw)
  let assert Error(#(tag2, _)) =
    ffi_fetch_tls_pinned_for_test(
      "127.0.0.1",
      port2,
      "app.example.com",
      "/oauth/client.json",
      roots2,
      cimd.max_document_bytes,
    )
  assert atom.to_string(tag2) == "response_too_large"

  // Certificate SAN hostname mismatch rejected by TLS verify_peer
  let small_raw = <<
    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}":utf8,
  >>
  let #(port3, roots3) = ffi_test_serve_tls_once("app.example.com", small_raw)
  let assert Error(#(tag3, _)) =
    ffi_fetch_tls_pinned_for_test(
      "127.0.0.1",
      port3,
      "other.example.com",
      "/oauth/client.json",
      roots3,
      cimd.max_document_bytes,
    )
  assert atom.to_string(tag3) == "tls_or_connect_error"
}

pub fn resolve_client_caching_expiry_rate_gate_and_cleanup_test() {
  use tx <- test_helper.with_db

  let events = process.new_subject()
  let cid1 = "https://reader.example.com/oauth/metadata.json"
  let cid2 = "https://ephemeral.example.com/oauth/metadata.json"

  let doc1_v1 =
    "{\"client_id\":\"https://reader.example.com/oauth/metadata.json\",\"client_name\":\"Reader v1\",\"redirect_uris\":[\"https://reader.example.com/cb\"]}"
  let doc1_v2 =
    "{\"client_id\":\"https://reader.example.com/oauth/metadata.json\",\"client_name\":\"Reader v2\",\"application_type\":\"native\",\"scope\":\"openid posts:read\",\"redirect_uris\":[\"http://127.0.0.1/cb\"]}"
  let doc2 =
    "{\"client_id\":\"https://ephemeral.example.com/oauth/metadata.json\",\"client_name\":\"Ephemeral App\",\"redirect_uris\":[\"https://ephemeral.example.com/cb\"]}"

  let gate_ok = fn() {
    process.send(events, "gate")
    Ok(Nil)
  }

  let fetcher_v1 = fn(url: String) {
    process.send(events, "fetch:" <> url)
    case url == cid1 {
      True ->
        Ok(json_response(200, "application/json", Some("max-age=300"), doc1_v1))
      False ->
        Ok(json_response(200, "application/json", Some("max-age=300"), doc2))
    }
  }

  // 1. Initial resolve misses cache, runs gate + fetcher, stores kind='cimd'
  let assert Ok(Ok(resolved_v1)) =
    cimd.resolve_client(tx, fetcher_v1, cid1, gate_ok)
  assert resolved_v1.kind == client.Cimd
  assert resolved_v1.visibility == client.Public
  assert resolved_v1.owner_user_id == None
  assert resolved_v1.name == "Reader v1"
  assert process.receive(events, 0) == Ok("gate")
  assert process.receive(events, 0) == Ok("fetch:" <> cid1)

  // find_by_client_id finds cached CIMD client for token/revoke endpoints
  let assert Ok(Some(found)) = client.find_by_client_id(tx, cid1)
  assert found.id == resolved_v1.id

  // 2. Second resolve hits fresh DB cache without calling gate or fetcher
  let fail_gate = fn() { Error("should_not_run_gate") }
  let fail_fetcher = fn(_url) { Error(cimd.Timeout) }
  let assert Ok(Ok(cached_v1)) =
    cimd.resolve_client(tx, fail_fetcher, cid1, fail_gate)
  assert cached_v1.id == resolved_v1.id
  assert cached_v1.name == "Reader v1"
  assert process.receive(events, 0) == Error(Nil)

  // 3. Rate-limit gate blocks uncached network fetches before fetcher runs
  let blocked_gate = fn() { Error("rate_limited") }
  let assert Error("rate_limited") =
    cimd.resolve_client(tx, fetcher_v1, cid2, blocked_gate)
  assert process.receive(events, 0) == Error(Nil)
  let assert Ok(None) = client.find_by_client_id(tx, cid2)

  // 4. Failed / invalid fetches are never cached
  let bad_fetcher = fn(_url) {
    Ok(json_response(500, "application/json", None, "{}"))
  }
  let assert Ok(Error(cimd.UnexpectedStatus(500))) =
    cimd.resolve_client(tx, bad_fetcher, cid2, gate_ok)
  assert process.receive(events, 0) == Ok("gate")
  let assert Ok(None) = client.find_by_client_id(tx, cid2)

  // 5. Expired cimd_expires_at triggers re-fetch and updates metadata in-place (preserving id)
  expire_cimd_row(tx, cid1)
  let assert Ok(None) = client.find_fresh_cimd_by_client_id(tx, cid1)

  let fetcher_v2 = fn(url: String) {
    process.send(events, "fetch_v2:" <> url)
    Ok(json_response(200, "application/json", Some("max-age=600"), doc1_v2))
  }
  let assert Ok(Ok(resolved_v2)) =
    cimd.resolve_client(tx, fetcher_v2, cid1, gate_ok)
  assert resolved_v2.id == resolved_v1.id
  assert resolved_v2.name == "Reader v2"
  assert resolved_v2.application_type == client.Native
  assert resolved_v2.redirect_uris == ["http://127.0.0.1/cb"]
  assert resolved_v2.allowed_scopes
    == set.from_list([scope.OpenId, scope.PostsRead])
  assert process.receive(events, 0) == Ok("gate")
  assert process.receive(events, 0) == Ok("fetch_v2:" <> cid1)

  // 6. Cleanup deletes expired unused CIMD rows while keeping expired CIMD rows with consents
  let assert Ok(Ok(resolved_cid2)) =
    cimd.resolve_client(tx, fetcher_v1, cid2, gate_ok)
  let _ = process.receive(events, 0)
  let _ = process.receive(events, 0)

  let assert Ok(alice) = user.create(tx, "AliceCimdConsent")
  let assert Ok(_) =
    grant.upsert_consent(
      tx,
      alice.id,
      resolved_v2.id,
      set.from_list([scope.OpenId]),
    )

  expire_cimd_row(tx, cid1)
  expire_cimd_row(tx, cid2)

  let assert Ok(deleted_count) = cleanup.run_once(tx, None, 100)
  assert deleted_count >= 1

  // cid2 had no consents -> purged; cid1 has Alice's consent -> retained!
  let assert Ok(None) = client.find_by_client_id(tx, cid2)
  assert resolved_cid2.client_id == cid2
  let assert Ok(Some(retained)) = client.find_by_client_id(tx, cid1)
  assert retained.id == resolved_v2.id
}

fn json_response(
  status: Int,
  content_type: String,
  cache_control: Option(String),
  body_text: String,
) -> cimd.FetchResponse {
  cimd.FetchResponse(status:, content_type:, cache_control:, body: <<
    body_text:utf8,
  >>)
}

fn expire_cimd_row(db: pog.Connection, client_id: String) -> Nil {
  let assert Ok(_) =
    pog.query(
      "UPDATE oidc_clients SET cimd_expires_at = NOW() - INTERVAL '10 seconds' WHERE client_id = $1",
    )
    |> pog.parameter(pog.text(client_id))
    |> pog.execute(db)
  Nil
}

pub fn cimd_security_audit_regressions_test() {
  let cid = "https://app.example.com/oauth/client.json"
  let fetcher = cimd.default_fetcher()

  // 1. Trailing-dot FQDN SSRF attempts blocked before any DNS/socket call
  let assert Error(cimd.BlockedAddress(_)) =
    fetcher("https://localhost./client.json")
  let assert Error(cimd.BlockedAddress(_)) =
    fetcher("https://127.0.0.1./client.json")
  let assert Error(cimd.BlockedAddress(_)) =
    fetcher("https://metadata.google.internal./client.json")

  // 2. Non-UTF-8 bytes in HTTP response headers over TLS return InvalidHttpResponse without crashing
  let bad_hdr_raw = <<
    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: max-age=60, x=":utf8,
    0xFF,
    "\r\nContent-Length: 2\r\n\r\n{}":utf8,
  >>
  let #(port, roots) = ffi_test_serve_tls_once("app.example.com", bad_hdr_raw)
  let assert Error(#(tag, _)) =
    ffi_fetch_tls_pinned_for_test(
      "127.0.0.1",
      port,
      "app.example.com",
      "/oauth/client.json",
      roots,
      cimd.max_document_bytes,
    )
  assert atom.to_string(tag) == "invalid_http_response"

  // 3. Unicode Bi-Di override (U+202E RLO) and invisible-only (U+200B / U+3164) client_name rejected
  let rlo_doc =
    "{\"client_id\":\""
    <> cid
    <> "\",\"client_name\":\"Trusted\u{202E}live\",\"redirect_uris\":[\"https://app.example.com/cb\"]}"
  let assert Error(cimd.InvalidDocument(_)) =
    cimd.parse_and_validate_document(
      cid,
      json_response(200, "application/json", None, rlo_doc),
    )

  let zwsp_doc =
    "{\"client_id\":\""
    <> cid
    <> "\",\"client_name\":\"\u{200B}\u{3164}\",\"redirect_uris\":[\"https://app.example.com/cb\"]}"
  let assert Error(cimd.InvalidDocument(_)) =
    cimd.parse_and_validate_document(
      cid,
      json_response(200, "application/json", None, zwsp_doc),
    )

  // 4. JWKS containing private ("d") or symmetric ("kty":"oct") keys & non-"none" revocation auth rejected
  let priv_jwk_doc =
    "{\"client_id\":\""
    <> cid
    <> "\",\"jwks\":{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"d\":\"secret\"}]},\"redirect_uris\":[\"https://app.example.com/cb\"]}"
  let assert Error(cimd.InvalidDocument(_)) =
    cimd.parse_and_validate_document(
      cid,
      json_response(200, "application/json", None, priv_jwk_doc),
    )

  let oct_jwk_doc =
    "{\"client_id\":\""
    <> cid
    <> "\",\"jwks\":{\"keys\":[{\"kty\":\"oct\",\"k\":\"secret\"}]},\"redirect_uris\":[\"https://app.example.com/cb\"]}"
  let assert Error(cimd.InvalidDocument(_)) =
    cimd.parse_and_validate_document(
      cid,
      json_response(200, "application/json", None, oct_jwk_doc),
    )

  let bad_rev_auth_doc =
    "{\"client_id\":\""
    <> cid
    <> "\",\"revocation_endpoint_auth_method\":\"client_secret_basic\",\"redirect_uris\":[\"https://app.example.com/cb\"]}"
  let assert Error(cimd.InvalidDocument(_)) =
    cimd.parse_and_validate_document(
      cid,
      json_response(200, "application/json", None, bad_rev_auth_doc),
    )

  // 5. grant_types: ["authorization_code"] (without "refresh_token") strips offline_access; Cache-Control: no-cache -> 60s
  let no_refresh_doc =
    "{\"client_id\":\""
    <> cid
    <> "\",\"grant_types\":[\"authorization_code\"],\"redirect_uris\":[\"https://app.example.com/cb\"]}"
  let assert Ok(parsed_no_rt) =
    cimd.parse_and_validate_document(
      cid,
      json_response(200, "application/json", Some("no-cache"), no_refresh_doc),
    )
  assert !set.contains(parsed_no_rt.allowed_scopes, scope.OfflineAccess)
  assert parsed_no_rt.cache_ttl_seconds == cimd.min_cache_ttl_seconds
}

@external(erlang, "lote_cimd_http_ffi", "is_global_public_ip_string")
fn ffi_is_global_public_ip_string(ip_literal: String) -> Bool

@external(erlang, "lote_cimd_test_ffi", "test_serve_tls_once")
fn ffi_test_serve_tls_once(
  cert_dns_host: String,
  raw_http_response: BitArray,
) -> #(Int, TestRootCerts)

@external(erlang, "lote_cimd_test_ffi", "fetch_tls_pinned_for_test")
fn ffi_fetch_tls_pinned_for_test(
  ip_literal: String,
  port: Int,
  sni_host: String,
  path: String,
  cacerts: TestRootCerts,
  max_body_bytes: Int,
) -> Result(#(Int, String, Option(String), BitArray), #(Atom, String))
