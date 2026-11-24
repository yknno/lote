import envoy
import gleam/int
import gleam/list
import gleam/result
import gleam/string
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
    auth_adapters:,
    pubsub_adapter:,
    rate_limit_adapter:,
    trusted_proxy_hops:,
  )
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
