import gleam/io
import lote/auth/password
import lote/auth/user
import lote/config
import lote/db/pool
import pog

pub type SeedOutcome {
  Created
  AlreadyExists
}

pub type SeedError {
  LookupFailed
  UserCreateFailed
  PasswordCreateFailed(password.Error)
}

pub fn main() -> Nil {
  let cfg = config.load()
  let db = pool.start(cfg.database_url)

  run_seed_user(db, "alice", "Alice", "password1234")
  run_seed_user(db, "bob", "Bob", "password1234")
}

fn run_seed_user(
  db: pog.Connection,
  login_id: String,
  name: String,
  pass: String,
) -> Nil {
  case pog.transaction(db, fn(tx) { seed_user(tx, login_id, name, pass) }) {
    Ok(Created) -> io.println("Created user: " <> login_id)
    Ok(AlreadyExists) -> io.println("User already exists: " <> login_id)
    Error(pog.TransactionRolledBack(PasswordCreateFailed(password.AlreadyExists))) ->
      io.println("User already exists: " <> login_id)
    Error(pog.TransactionRolledBack(LookupFailed)) ->
      io.println("Failed to check existing user: " <> login_id)
    Error(pog.TransactionRolledBack(UserCreateFailed)) ->
      io.println("Failed to create user: " <> login_id)
    Error(pog.TransactionRolledBack(PasswordCreateFailed(_))) ->
      io.println("Failed to create password: " <> login_id)
    Error(pog.TransactionQueryError(_)) ->
      io.println("Database error while seeding user: " <> login_id)
  }
}

pub fn seed_user(
  db: pog.Connection,
  login_id: String,
  name: String,
  pass: String,
) -> Result(SeedOutcome, SeedError) {
  case password.exists(db, login_id) {
    Ok(True) -> Ok(AlreadyExists)
    Error(_) -> Error(LookupFailed)
    Ok(False) ->
      case user.create(db, name) {
        Ok(created) ->
          case password.create(db, created.id, login_id, pass) {
            Ok(_) -> Ok(Created)
            Error(err) -> Error(PasswordCreateFailed(err))
          }
        Error(_) -> Error(UserCreateFailed)
      }
  }
}
