import envoy
import gleam/int
import gleam/list
import gleam/result
import gleam/string
import wisp

pub type Config {
  Config(
    port: Int,
    secret_key_base: String,
    database_url: String,
    auth_adapters: List(String),
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

  Config(port:, secret_key_base:, database_url:, auth_adapters:)
}
