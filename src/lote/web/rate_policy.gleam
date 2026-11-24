import gleam/int
import lote/rate_limit.{Policy}

// ---------------------------------------------------------------------------
// Layer 1: Baseline Transport & IP Guards
// ---------------------------------------------------------------------------

/// Baseline front-door HTTP rate limit per client IP (/32 IPv4 or /64 IPv6).
/// Applied across Web, OIDC, and API routes (exempting `/health`, `/static/*`
/// hits, and `POST /auth/logout`).
pub const http_ip_policy = Policy(limit: 300, window_ms: 60_000, burst: 120)

pub fn http_ip_key(ip_bucket: String) -> String {
  "http:ip:" <> ip_bucket
}

/// WebSocket `/ws` handshake rate limit per client IP bucket.
pub const ws_connect_policy = Policy(limit: 120, window_ms: 60_000, burst: 60)

pub fn ws_connect_ip_key(ip_bucket: String) -> String {
  "ws:connect:ip:" <> ip_bucket
}

/// Per-connection WebSocket inbound frame rate limit (in-process GCRA).
pub const ws_frame_policy = Policy(limit: 30, window_ms: 10_000, burst: 30)

// ---------------------------------------------------------------------------
// Layer 2: Principal Throughput Limits (Interactive & API Read / Write)
// ---------------------------------------------------------------------------

/// Shared mutating-action ceiling per user across Web form POSTs, WebSocket
/// post deletion, and Bearer API write endpoints.
pub const http_write_user_policy =
  Policy(limit: 30, window_ms: 60_000, burst: 10)

pub fn http_write_user_key(user_id: Int) -> String {
  "http:write:user:" <> int.to_string(user_id)
}

/// Interactive WebSocket timeline DB read limit (`Refresh`, `Load older`).
/// Keyed by user ID when authenticated, or by IP bucket when anonymous so
/// multiple concurrent anonymous WS connections share one read quota.
pub const ws_read_policy = Policy(limit: 60, window_ms: 60_000, burst: 20)

pub fn ws_read_user_key(user_id: Int) -> String {
  "ws:read:user:" <> int.to_string(user_id)
}

pub fn ws_read_ip_key(ip_bucket: String) -> String {
  "ws:read:ip:" <> ip_bucket
}

/// Per-OAuth-client Bearer API read ceiling (`GET` / `HEAD /api/*`).
pub const api_read_client_policy =
  Policy(limit: 120, window_ms: 60_000, burst: 60)

pub fn api_read_client_key(client_id: String) -> String {
  "api:read:client:" <> client_id
}

/// Account-wide Bearer API read ceiling aggregated across all clients/bots
/// acting on behalf of the same user.
pub const api_read_user_policy =
  Policy(limit: 300, window_ms: 60_000, burst: 100)

pub fn api_read_user_key(user_id: Int) -> String {
  "api:read:user:" <> int.to_string(user_id)
}

/// Per-OAuth-client Bearer API write ceiling (`DELETE`, `PUT`, `PATCH`, etc.).
/// Strictly lower than `http_write_user_policy` so a single noisy bot cannot
/// exhaust the human owner's Web management write quota.
pub const api_write_client_policy =
  Policy(limit: 20, window_ms: 60_000, burst: 5)

pub fn api_write_client_key(client_id: String) -> String {
  "http:write:client:" <> client_id
}

// ---------------------------------------------------------------------------
// Layer 3: Strict Action & Credential Brute-Force Limits
// ---------------------------------------------------------------------------

/// IP-wide password login attempt ceiling.
pub const login_ip_policy = Policy(limit: 100, window_ms: 900_000, burst: 50)

pub fn login_ip_key(ip_bucket: String) -> String {
  "login:ip:" <> ip_bucket
}

/// Per-(IP, login_id) password brute-force ceiling (reset on valid login).
pub const login_account_policy = Policy(limit: 5, window_ms: 900_000, burst: 5)

pub fn login_account_key(
  ip_bucket: String,
  normalized_login_id: String,
) -> String {
  "login:ip_id:" <> ip_bucket <> ":" <> normalized_login_id
}

/// IP-wide OAuth token & introspection endpoint ceiling.
pub const oidc_ip_policy = Policy(limit: 100, window_ms: 900_000, burst: 50)

pub fn oidc_ip_key(ip_bucket: String) -> String {
  "oidc:ip:" <> ip_bucket
}

/// Per-(IP, client_id) confidential client secret brute-force ceiling
/// (applied only to existing confidential clients and reset on valid secret).
pub const oidc_client_auth_policy =
  Policy(limit: 10, window_ms: 900_000, burst: 10)

pub fn oidc_client_auth_key(ip_bucket: String, client_id: String) -> String {
  "oidc:client_auth:ip_id:" <> ip_bucket <> ":" <> client_id
}

/// Per-OAuth-client post creation ceiling (`POST /api/v1/posts`).
pub const post_create_client_policy =
  Policy(limit: 6, window_ms: 60_000, burst: 3)

pub fn post_create_client_key(client_id: String) -> String {
  "post:create:client:" <> client_id
}

/// Shared account-wide post creation ceiling across Web composer and all bots.
pub const post_create_user_policy =
  Policy(limit: 10, window_ms: 60_000, burst: 5)

pub fn post_create_user_key(user_id: Int) -> String {
  "post:create:user:" <> int.to_string(user_id)
}
