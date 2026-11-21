import gleam/io
import lote/auth/password
import lote/auth/user
import lote/config
import lote/db/pool

pub fn main() -> Nil {
  let cfg = config.load()
  let db = pool.start(cfg.database_url)

  seed_user(db, "alice", "Alice", "password1234")
  seed_user(db, "bob", "Bob", "password1234")
}

fn seed_user(db, login_id: String, name: String, pass: String) -> Nil {
  case password.authenticate(db, login_id, pass) {
    Ok(_) -> io.println("User already exists: " <> login_id)
    Error(_) ->
      case user.create(db, name) {
        Ok(created) ->
          case password.create(db, created.id, login_id, pass) {
            Ok(_) -> io.println("Created user: " <> login_id)
            Error(_) -> io.println("Failed to create password: " <> login_id)
          }
        Error(_) -> io.println("Failed to create user: " <> login_id)
      }
  }
}
