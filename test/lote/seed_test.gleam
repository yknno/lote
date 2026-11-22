import gleam/dynamic/decode
import lote/auth/password
import lote/seed
import lote/test_helper
import pog

fn count_users_by_name(db: pog.Connection, name: String) -> Int {
  let decoder = {
    use count <- decode.field(0, decode.int)
    decode.success(count)
  }

  let assert Ok(returned) =
    pog.query("SELECT COUNT(*) FROM users WHERE name = $1")
    |> pog.parameter(pog.text(name))
    |> pog.returning(decoder)
    |> pog.execute(db)

  let assert [count] = returned.rows
  count
}

pub fn seed_user_is_idempotent_by_login_id_regardless_of_password_test() {
  use tx <- test_helper.with_db

  assert seed.seed_user(
      tx,
      "seed_identity_user",
      "Seed Identity",
      "initialpass123",
    )
    == Ok(seed.Created)
  assert count_users_by_name(tx, "Seed Identity") == 1

  // Re-seeding with the same password is a no-op
  assert seed.seed_user(
      tx,
      "seed_identity_user",
      "Seed Identity",
      "initialpass123",
    )
    == Ok(seed.AlreadyExists)
  assert count_users_by_name(tx, "Seed Identity") == 1

  // Re-seeding with a DIFFERENT password must still treat the identity as
  // existing and must not create an orphan row in users.
  assert seed.seed_user(
      tx,
      "seed_identity_user",
      "Seed Identity",
      "differentpass456",
    )
    == Ok(seed.AlreadyExists)
  assert count_users_by_name(tx, "Seed Identity") == 1

  // Original password remains valid
  let assert Ok(auth_user) =
    password.authenticate(tx, "seed_identity_user", "initialpass123")
  assert auth_user.name == "Seed Identity"
}
