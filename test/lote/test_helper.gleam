import gleam/erlang/process
import lote/config
import pog

pub fn with_db(run: fn(pog.Connection) -> Nil) -> Nil {
  let cfg = config.load()
  let pool_name = process.new_name("lote_test_db")
  let assert Ok(db_config) = pog.url_config(pool_name, cfg.database_url)
  let db_config =
    db_config
    |> pog.pool_size(1)
    |> pog.connection_parameter("timezone", "UTC")
  let assert Ok(started) = pog.start(db_config)
  let db = started.data

  let assert Error(pog.TransactionRolledBack(Nil)) =
    pog.transaction(db, fn(tx) {
      run(tx)
      Error(Nil)
    })

  process.send_exit(started.pid)
}
