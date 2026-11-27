import envoy
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import gleam/uri
import wisp

pub type PubSubAdapter {
  MemoryPubSub
  PostgresPubSub
}

pub type RateLimitAdapter {
  MemoryRateLimit
  PostgresRateLimit
}

pub type Config {
  Config(
    port: Int,
    secret_key_base: String,
    database_url: String,
    issuer_url: String,
    oidc_signing_key_pem: Option(String),
    oidc_verify_keys_pem: Option(String),
    auth_adapters: List(String),
    pubsub_adapter: PubSubAdapter,
    rate_limit_adapter: RateLimitAdapter,
    trusted_proxy_hops: Int,
  )
}

pub fn load() -> Config {
  let port =
    envoy.get("PORT")
    |> result.try(int.parse)
    |> result.unwrap(8080)

  let secret_key_base =
    envoy.get("SECRET_KEY_BASE")
    |> result.lazy_unwrap(fn() { wisp.random_string(64) })

  let database_url =
    envoy.get("DATABASE_URL")
    |> result.unwrap("postgres://postgres:postgres@localhost:5432/lote")

  let default_issuer = default_issuer_url(port)
  let issuer_url = case
    envoy.get("ISSUER_URL")
    |> result.unwrap("")
    |> parse_issuer_url(port)
  {
    Ok(issuer) -> issuer
    Error(invalid) -> {
      wisp.log_warning(
        "Invalid ISSUER_URL \""
        <> invalid
        <> "\", falling back to \""
        <> default_issuer
        <> "\"",
      )
      default_issuer
    }
  }

  let oidc_signing_key_pem =
    envoy.get("OIDC_SIGNING_KEY_PEM")
    |> result.unwrap("")
    |> parse_optional_pem

  let oidc_verify_keys_pem =
    envoy.get("OIDC_VERIFY_KEYS_PEM")
    |> result.unwrap("")
    |> parse_optional_pem

  let auth_adapters =
    envoy.get("AUTH_ADAPTERS")
    |> result.unwrap("")
    |> string.split(",")
    |> list.map(fn(s) { string.lowercase(string.trim(s)) })
    |> list.filter(fn(s) { s != "" })

  let pubsub_adapter = case
    envoy.get("PUBSUB_ADAPTER")
    |> result.unwrap("")
    |> parse_pubsub_adapter
  {
    Ok(adapter) -> adapter
    Error(invalid) -> {
      wisp.log_warning(
        "Unknown PUBSUB_ADAPTER \""
        <> invalid
        <> "\", falling back to \"memory\"",
      )
      MemoryPubSub
    }
  }

  let default_rate_limit = case pubsub_adapter {
    MemoryPubSub -> MemoryRateLimit
    PostgresPubSub -> PostgresRateLimit
  }
  let rate_limit_adapter = case
    envoy.get("RATE_LIMIT_ADAPTER")
    |> result.unwrap("")
    |> parse_rate_limit_adapter(default_rate_limit)
  {
    Ok(adapter) -> adapter
    Error(invalid) -> {
      wisp.log_warning(
        "Unknown RATE_LIMIT_ADAPTER \""
        <> invalid
        <> "\", falling back to default",
      )
      default_rate_limit
    }
  }

  let trusted_proxy_hops = case
    envoy.get("TRUSTED_PROXY_HOPS")
    |> result.unwrap("")
    |> parse_trusted_proxy_hops
  {
    Ok(hops) -> hops
    Error(invalid) -> {
      wisp.log_warning(
        "Invalid TRUSTED_PROXY_HOPS \"" <> invalid <> "\", falling back to 0",
      )
      0
    }
  }

  Config(
    port:,
    secret_key_base:,
    database_url:,
    issuer_url:,
    oidc_signing_key_pem:,
    oidc_verify_keys_pem:,
    auth_adapters:,
    pubsub_adapter:,
    rate_limit_adapter:,
    trusted_proxy_hops:,
  )
}

pub fn default_issuer_url(port: Int) -> String {
  case port {
    80 -> "http://localhost"
    _ -> "http://localhost:" <> int.to_string(port)
  }
}

pub fn parse_issuer_url(raw: String, port: Int) -> Result(String, String) {
  let trimmed = string.trim(raw)
  case trimmed {
    "" -> Ok(default_issuer_url(port))
    _ ->
      case uri.parse(trimmed) {
        Error(_) -> Error(trimmed)
        Ok(parsed) ->
          case
            parsed.scheme,
            parsed.host,
            parsed.userinfo,
            parsed.query,
            parsed.fragment
          {
            Some(scheme), Some(host), None, None, None if host != "" -> {
              let lower_scheme = string.lowercase(scheme)
              case
                lower_scheme == "http" || lower_scheme == "https",
                normalize_issuer_port(lower_scheme, parsed.port)
              {
                True, Ok(normalized_port) -> {
                  let clean_path = trim_trailing_slashes(parsed.path)
                  let normalized =
                    uri.Uri(
                      scheme: Some(lower_scheme),
                      userinfo: None,
                      host: Some(string.lowercase(host)),
                      port: normalized_port,
                      path: clean_path,
                      query: None,
                      fragment: None,
                    )
                  Ok(uri.to_string(normalized))
                }
                _, _ -> Error(trimmed)
              }
            }
            _, _, _, _, _ -> Error(trimmed)
          }
      }
  }
}

fn normalize_issuer_port(
  scheme: String,
  port: Option(Int),
) -> Result(Option(Int), Nil) {
  case scheme, port {
    _, None -> Ok(None)
    "http", Some(80) -> Ok(None)
    "https", Some(443) -> Ok(None)
    _, Some(p) if p >= 1 && p <= 65_535 -> Ok(Some(p))
    _, Some(_) -> Error(Nil)
  }
}

fn trim_trailing_slashes(path: String) -> String {
  case string.ends_with(path, "/") {
    True ->
      path
      |> string.drop_end(up_to: 1)
      |> trim_trailing_slashes
    False -> path
  }
}

pub fn parse_optional_pem(raw: String) -> Option(String) {
  case string.trim(raw) {
    "" -> None
    trimmed -> Some(trimmed)
  }
}

pub fn parse_pubsub_adapter(raw: String) -> Result(PubSubAdapter, String) {
  let trimmed = string.trim(raw)
  case string.lowercase(trimmed) {
    "" | "memory" -> Ok(MemoryPubSub)
    "postgres" | "postgresql" -> Ok(PostgresPubSub)
    _ -> Error(trimmed)
  }
}

pub fn parse_rate_limit_adapter(
  raw: String,
  default: RateLimitAdapter,
) -> Result(RateLimitAdapter, String) {
  let trimmed = string.trim(raw)
  case string.lowercase(trimmed) {
    "" -> Ok(default)
    "memory" -> Ok(MemoryRateLimit)
    "postgres" | "postgresql" -> Ok(PostgresRateLimit)
    _ -> Error(trimmed)
  }
}

pub fn parse_trusted_proxy_hops(raw: String) -> Result(Int, String) {
  let trimmed = string.trim(raw)
  case trimmed {
    "" -> Ok(0)
    _ ->
      case int.parse(trimmed) {
        Ok(n) if n >= 0 -> Ok(n)
        _ -> Error(trimmed)
      }
  }
}
