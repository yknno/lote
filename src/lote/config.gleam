import envoy
import gleam/int
import gleam/result
import wisp

pub type Config {
  Config(port: Int, secret_key_base: String)
}

pub fn load() -> Config {
  let port =
    envoy.get("PORT")
    |> result.try(int.parse)
    |> result.unwrap(8080)

  let secret_key_base =
    envoy.get("SECRET_KEY_BASE")
    |> result.lazy_unwrap(fn() { wisp.random_string(64) })

  Config(port:, secret_key_base:)
}
