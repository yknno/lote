import gleam/erlang/process
import pog

pub fn start(database_url: String) -> pog.Connection {
  let pool_name = process.new_name("lote_db")
  let assert Ok(db_config) = pog.url_config(pool_name, database_url)
  let assert Ok(started) = pog.start(db_config)
  started.data
}
