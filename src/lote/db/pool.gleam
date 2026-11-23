import gleam/erlang/process.{type Name}
import gleam/otp/supervision.{type ChildSpecification}
import pog

pub fn config(
  pool_name: Name(pog.Message),
  database_url: String,
) -> pog.Config {
  let assert Ok(db_config) = pog.url_config(pool_name, database_url)
  pog.connection_parameter(db_config, "timezone", "UTC")
}

pub fn supervised(db_config: pog.Config) -> ChildSpecification(pog.Connection) {
  pog.supervised(db_config)
}

pub fn start(database_url: String) -> pog.Connection {
  let pool_name = process.new_name("lote_db")
  let db_config = config(pool_name, database_url)
  let assert Ok(started) = pog.start(db_config)
  started.data
}
