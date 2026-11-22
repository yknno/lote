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

pub type Config {
  Config(
    port: Int,
    secret_key_base: String,
    database_url: String,
    auth_adapters: List(String),
    pubsub_adapter: PubSubAdapter,
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

  Config(
    port:,
    secret_key_base:,
    database_url:,
    auth_adapters:,
    pubsub_adapter:,
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
