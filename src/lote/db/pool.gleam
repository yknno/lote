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

@external(erlang, "lote_db_ffi", "is_single_connection")
fn is_single_connection(db: pog.Connection) -> Bool

/// Run `callback` inside a PostgreSQL transaction when `db` is a connection pool.
/// When `db` is already a checked-out single connection (for example inside an
/// outer `pog.transaction` such as `test_helper.with_db`), run `callback(db)`
/// directly so we do not issue a nested `BEGIN`/`COMMIT` that would prematurely
/// commit the caller's transaction.
pub fn with_transaction(
  db: pog.Connection,
  callback: fn(pog.Connection) -> Result(a, err),
) -> Result(a, pog.TransactionError(err)) {
  case is_single_connection(db) {
    False -> pog.transaction(db, callback)
    True ->
      case callback(db) {
        Ok(value) -> Ok(value)
        Error(err) -> Error(pog.TransactionRolledBack(err))
      }
  }
}
