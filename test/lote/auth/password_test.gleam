import lote/auth/password
import lote/auth/user
import lote/test_helper

pub fn create_and_authenticate_with_valid_password_test() {
  use tx <- test_helper.with_db

  let assert Ok(created) = user.create(tx, "Alice Test")
  let assert Ok(Nil) =
    password.create(tx, created.id, "alice_test", "secretpass123")

  assert password.authenticate(tx, "alice_test", "secretpass123") == Ok(created)
}

pub fn authenticate_fails_with_wrong_password_or_unknown_id_test() {
  use tx <- test_helper.with_db

  let assert Ok(created) = user.create(tx, "Bob Test")
  let assert Ok(Nil) =
    password.create(tx, created.id, "bob_test", "secretpass123")

  assert password.authenticate(tx, "bob_test", "wrongpass")
    == Error(password.InvalidCredentials)
  assert password.authenticate(tx, "unknown_id", "secretpass123")
    == Error(password.InvalidCredentials)
}

pub fn create_rejects_short_password_and_duplicate_login_id_test() {
  use tx <- test_helper.with_db

  let assert Ok(u1) = user.create(tx, "User 1")
  let assert Ok(u2) = user.create(tx, "User 2")

  assert password.create(tx, u1.id, "short_user", "short")
    == Error(password.InvalidInput("Password must be at least 8 characters"))

  let assert Ok(Nil) = password.create(tx, u1.id, "dup_id", "secretpass123")
  assert password.create(tx, u2.id, "dup_id", "secretpass123")
    == Error(password.AlreadyExists)
}
