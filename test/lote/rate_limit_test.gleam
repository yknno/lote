import gleam/dynamic/decode
import gleam/erlang/process
import gleam/option.{None, Some}
import gleam/otp/static_supervisor as supervisor
import gleam/string
import lote/config
import lote/rate_limit
import lote/test_helper
import lote/web/client_ip
import pog

const test_secret = "rate_limit_test_secret_key_base_0123456789abcdef"

pub fn gcra_burst_refill_and_retry_after_test() {
  // 10 req / 60s (emission = 6000ms), burst = 3
  let policy = rate_limit.Policy(limit: 10, window_ms: 60_000, burst: 3)
  let t0 = 1_000_000

  let #(d1, tat1) = rate_limit.check_gcra(t0, t0, policy)
  assert d1 == rate_limit.Allowed(remaining: 2)

  let #(d2, tat2) = rate_limit.check_gcra(tat1, t0, policy)
  assert d2 == rate_limit.Allowed(remaining: 1)

  let #(d3, tat3) = rate_limit.check_gcra(tat2, t0, policy)
  assert d3 == rate_limit.Allowed(remaining: 0)

  // 4th request at same instant is limited for 6 seconds and does not advance tat
  let #(d4, tat4) = rate_limit.check_gcra(tat3, t0, policy)
  assert d4 == rate_limit.Limited(retry_after_seconds: 6)
  assert tat4 == tat3

  // Halfway through emission interval (3500ms later), still limited (ceil(2500ms) = 3s)
  let #(d5, tat5) = rate_limit.check_gcra(tat4, t0 + 3500, policy)
  assert d5 == rate_limit.Limited(retry_after_seconds: 3)
  assert tat5 == tat3

  // After 6000ms, 1 token has replenished
  let #(d6, tat6) = rate_limit.check_gcra(tat5, t0 + 6000, policy)
  assert d6 == rate_limit.Allowed(remaining: 0)

  // After long idle period, full burst is restored
  let #(d7, _tat7) = rate_limit.check_gcra(tat6, t0 + 120_000, policy)
  assert d7 == rate_limit.Allowed(remaining: 2)
}

pub fn hash_key_produces_opaque_secret_keyed_digest_test() {
  let raw = "login:ip_id:203.0.113.10:alice"
  let h1 = rate_limit.hash_key(test_secret, raw)
  let h2 = rate_limit.hash_key("different_secret_key_base", raw)

  // 64 lowercase hex characters (HMAC-SHA256)
  assert string.length(h1) == 64
  assert h1 == string.lowercase(h1)
  assert h1 != h2
  assert !string.contains(h1, "203.0.113.10")
  assert !string.contains(h1, "alice")
  assert !string.contains(h1, "login")
}

pub fn memory_limiter_enforces_limit_resets_and_bounds_entries_test() {
  let assert Ok(limiter) =
    rate_limit.start_memory_with_cap(test_secret, 5, 60_000)
  let policy = rate_limit.Policy(limit: 5, window_ms: 50_000, burst: 2)
  let t0 = 2_000_000

  assert rate_limit.check_at(limiter, "k1", policy, t0)
    == rate_limit.Allowed(remaining: 1)
  assert rate_limit.check_at(limiter, "k1", policy, t0)
    == rate_limit.Allowed(remaining: 0)
  assert rate_limit.check_at(limiter, "k1", policy, t0)
    == rate_limit.Limited(retry_after_seconds: 10)

  // Separate key has its own independent quota
  assert rate_limit.check_at(limiter, "k2", policy, t0)
    == rate_limit.Allowed(remaining: 1)

  // Reset restores full burst for k1
  rate_limit.reset(limiter, "k1")
  assert rate_limit.check_at(limiter, "k1", policy, t0)
    == rate_limit.Allowed(remaining: 1)

  // Inserting beyond cap (5 entries) evicts safely without crashing
  let _ = rate_limit.check_at(limiter, "k3", policy, t0 + 1)
  let _ = rate_limit.check_at(limiter, "k4", policy, t0 + 2)
  let _ = rate_limit.check_at(limiter, "k5", policy, t0 + 3)
  let _ = rate_limit.check_at(limiter, "k6", policy, t0 + 4)
  assert rate_limit.check_at(limiter, "k7", policy, t0 + 5)
    == rate_limit.Allowed(remaining: 1)

  rate_limit.stop_memory(limiter)
}

pub fn supervised_memory_limiter_recovers_after_crash_test() {
  let name = process.new_name("lote_rate_limit_sup_test")
  let limiter = rate_limit.memory_named(name, test_secret)
  let policy = rate_limit.Policy(limit: 5, window_ms: 50_000, burst: 2)

  let assert Ok(sup) =
    supervisor.new(supervisor.OneForOne)
    |> supervisor.add(rate_limit.supervised_memory(name))
    |> supervisor.start

  let assert Ok(pid1) = process.named(name)
  assert rate_limit.check_at(limiter, "user:1", policy, 5000)
    == rate_limit.Allowed(remaining: 1)

  process.kill(pid1)
  assert test_helper.wait_until(100, 10, fn() {
    case process.named(name) {
      Ok(pid2) -> pid2 != pid1 && process.is_alive(pid2)
      Error(_) -> False
    }
  })

  // Same named limiter continues working with the restarted actor
  assert rate_limit.check_at(limiter, "user:1", policy, 5000)
    == rate_limit.Allowed(remaining: 1)

  process.send_exit(sup.pid)
}

pub fn postgres_limiter_enforces_atomic_gcra_hashes_keys_and_cleans_expired_test() {
  use tx <- test_helper.with_db

  let limiter = rate_limit.postgres(tx, test_secret)
  let policy = rate_limit.Policy(limit: 10, window_ms: 60_000, burst: 3)
  let t0 = 5_000_000
  let raw_key = "login:ip_id:203.0.113.10:alice"

  assert rate_limit.check_at(limiter, raw_key, policy, t0)
    == rate_limit.Allowed(remaining: 2)
  assert rate_limit.check_at(limiter, raw_key, policy, t0)
    == rate_limit.Allowed(remaining: 1)
  assert rate_limit.check_at(limiter, raw_key, policy, t0)
    == rate_limit.Allowed(remaining: 0)

  // Verify PostgreSQL stores only the HMAC-SHA256 digest and never raw IP or login_id
  let key_decoder = {
    use k <- decode.field(0, decode.string)
    decode.success(k)
  }
  let assert Ok(pog.Returned(rows: [stored_key], ..)) =
    pog.query("SELECT key FROM rate_limits")
    |> pog.returning(key_decoder)
    |> pog.execute(tx)
  assert stored_key == rate_limit.hash_key(test_secret, raw_key)
  assert string.length(stored_key) == 64
  assert !string.contains(stored_key, "203.0.113.10")
  assert !string.contains(stored_key, "alice")

  // 4th attempt is limited with exact 6s retry-after and does not mutate tat
  assert rate_limit.check_at(limiter, raw_key, policy, t0)
    == rate_limit.Limited(retry_after_seconds: 6)
  assert rate_limit.check_at(limiter, raw_key, policy, t0 + 3500)
    == rate_limit.Limited(retry_after_seconds: 3)

  // After 1 emission interval (6000ms), allowed again
  assert rate_limit.check_at(limiter, raw_key, policy, t0 + 6000)
    == rate_limit.Allowed(remaining: 0)

  // Reset clears the hashed key
  rate_limit.reset(limiter, raw_key)
  assert rate_limit.check_at(limiter, raw_key, policy, t0)
    == rate_limit.Allowed(remaining: 2)

  // Expired cleanup deletes only entries whose tat_ms <= current_ms
  assert rate_limit.check_at(limiter, "pg:active", policy, t0 + 100_000)
    == rate_limit.Allowed(remaining: 2)
  assert rate_limit.delete_expired_postgres(tx, t0 + 50_000, 100) == Ok(1)
  // pg:active still exists and has remaining == 1 on next check at t0 + 100_000
  assert rate_limit.check_at(limiter, "pg:active", policy, t0 + 100_000)
    == rate_limit.Allowed(remaining: 1)
}

pub fn client_ip_extract_respects_trusted_proxy_hops_and_resists_spoofing_test() {
  // With 0 trusted proxies, X-Forwarded-For is completely ignored
  assert client_ip.extract(Some("10.0.0.1"), Some("1.2.3.4"), 0) == "10.0.0.1"

  // With 1 trusted proxy (e.g. Cloud Run LB), rightmost XFF entry is selected,
  // ignoring any spoofed leftmost client IP.
  assert client_ip.extract(Some("10.0.0.1"), Some("9.9.9.9, 203.0.113.5"), 1)
    == "203.0.113.5"

  // With 2 trusted proxies (e.g. CDN -> LB), 2nd from right is selected
  assert client_ip.extract(
      Some("10.0.0.1"),
      Some("9.9.9.9, 203.0.113.5, 198.51.100.1"),
      2,
    )
    == "203.0.113.5"

  // Fewer XFF entries than trusted_proxy_hops falls back to peer IP
  assert client_ip.extract(Some("10.0.0.1"), Some("203.0.113.5"), 2)
    == "10.0.0.1"
  assert client_ip.extract(Some("10.0.0.1"), None, 1) == "10.0.0.1"

  // Normalization: IPv4-mapped IPv6 and uppercase IPv6
  assert client_ip.extract(Some("::ffff:127.0.0.1"), None, 0) == "127.0.0.1"
  assert client_ip.extract(Some("2001:DB8::1"), None, 0) == "2001:db8::1"
  assert client_ip.extract(None, None, 0) == "unknown"
}

pub fn config_parsers_for_rate_limit_adapter_and_proxy_hops_test() {
  assert config.parse_rate_limit_adapter("", config.MemoryRateLimit)
    == Ok(config.MemoryRateLimit)
  assert config.parse_rate_limit_adapter("", config.PostgresRateLimit)
    == Ok(config.PostgresRateLimit)
  assert config.parse_rate_limit_adapter("memory", config.PostgresRateLimit)
    == Ok(config.MemoryRateLimit)
  assert config.parse_rate_limit_adapter(" PostgreSQL ", config.MemoryRateLimit)
    == Ok(config.PostgresRateLimit)
  assert config.parse_rate_limit_adapter("redis", config.MemoryRateLimit)
    == Error("redis")

  assert config.parse_trusted_proxy_hops("") == Ok(0)
  assert config.parse_trusted_proxy_hops("0") == Ok(0)
  assert config.parse_trusted_proxy_hops(" 2 ") == Ok(2)
  assert config.parse_trusted_proxy_hops("-1") == Error("-1")
  assert config.parse_trusted_proxy_hops("abc") == Error("abc")
}
