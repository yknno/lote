import gleam/dynamic/decode
import gleam/list
import gleam/string
import lote/auth/password
import lote/auth/user
import lote/test_helper
import pog

pub fn create_and_authenticate_with_ascii_case_insensitive_login_id_and_case_sensitive_password_test() {
  use tx <- test_helper.with_db

  let assert Ok(created) = user.create(tx, "Alice Test")
  let assert Ok(Nil) =
    password.create(
      tx,
      created.id,
      "\t Alice.Test-01@Example.COM \r\n",
      "SecretPass123",
    )

  assert password.authenticate(tx, "alice.test-01@example.com", "SecretPass123")
    == Ok(created)
  assert password.authenticate(
      tx,
      "  ALICE.TEST-01@EXAMPLE.COM  ",
      "SecretPass123",
    )
    == Ok(created)
  assert password.exists(tx, "ALICE.TEST-01@EXAMPLE.COM") == Ok(True)

  // Passwords remain strictly case-sensitive
  assert password.authenticate(tx, "alice.test-01@example.com", "secretpass123")
    == Error(password.InvalidCredentials)
}

pub fn normalize_login_id_rejects_non_ascii_unicode_case_folds_and_disallowed_chars_test() {
  use tx <- test_helper.with_db

  let assert Ok(u) = user.create(tx, "NonAsciiGuardUser")
  let assert Ok(Nil) = password.create(tx, u.id, "kelvin", "secretpass123")

  // Non-ASCII inputs — including characters whose Unicode lowercase/trim would
  // produce ASCII (`K` U+212A -> 'k', `İ` U+0130 -> 'i\u0307', fullwidth `ＡＬＩＣＥ`,
  // fullwidth space U+3000 `　kelvin　`) — MUST be rejected rather than silently folded!
  let rejected_ids = [
    "ありす",
    "ＡＬＩＣＥ",
    "café",
    "İd",
    "\u{212A}elvin",
    "　kelvin　",
    "alice bob",
    "alice/bob",
  ]

  list.each(rejected_ids, fn(bad_id) {
    let assert Error(password.InvalidInput(_)) =
      password.normalize_login_id(bad_id)
    let assert Error(password.InvalidInput(_)) =
      password.create(tx, u.id, bad_id, "secretpass123")
    assert password.exists(tx, bad_id) == Ok(False)
    assert password.authenticate(tx, bad_id, "secretpass123")
      == Error(password.InvalidCredentials)
  })

  // Genuine ASCII "kelvin" still authenticates cleanly
  assert password.authenticate(tx, "KELVIN", "secretpass123") == Ok(u)
}

pub fn non_ascii_passwords_preserve_raw_utf8_and_case_and_enforce_byte_bounds_test() {
  use tx <- test_helper.with_db

  let assert Ok(u1) = user.create(tx, "UnicodePwUser1")
  let assert Ok(u2) = user.create(tx, "UnicodePwUser2")

  // Existing or newly created NFD passwords ("は\u{309A}..." / "Cafe\u{0301}...")
  // preserve exact UTF-8 bytes so pre-existing NFD hashes continue to authenticate
  let nfd_pw = "は\u{309A}すわーどCafe\u{0301}12"
  let nfc_pw = "ぱすわーどCafé12"
  let assert Ok(Nil) = password.create(tx, u1.id, "unicode_pw_user", nfd_pw)

  assert password.authenticate(tx, "unicode_pw_user", nfd_pw) == Ok(u1)
  assert password.authenticate(tx, "unicode_pw_user", nfc_pw)
    == Error(password.InvalidCredentials)
  // Non-ASCII case ("CAFE\u{0301}" vs "Cafe\u{0301}") is preserved
  assert password.authenticate(
      tx,
      "unicode_pw_user",
      "は\u{309A}すわーどCAFE\u{0301}12",
    )
    == Error(password.InvalidCredentials)

  // Multibyte UTF-8 password byte bound: 341 * 3 bytes ("あ") = 1023 bytes <= 1024 succeeds;
  // 342 * 3 bytes ("あ") = 1026 bytes > 1024 is rejected
  let multibyte_ok = string.repeat("あ", 341)
  let multibyte_over = string.repeat("あ", 342)
  assert password.create(tx, u2.id, "multibyte_pw", multibyte_over)
    == Error(password.InvalidInput("Password must be at most 1024 bytes"))
  let assert Ok(Nil) = password.create(tx, u2.id, "multibyte_pw", multibyte_ok)
  assert password.authenticate(tx, "multibyte_pw", multibyte_ok) == Ok(u2)
  assert password.authenticate(tx, "multibyte_pw", multibyte_over)
    == Error(password.InvalidCredentials)
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

pub fn create_rejects_blank_oversized_short_and_case_duplicate_login_id_test() {
  use tx <- test_helper.with_db

  let assert Ok(u1) = user.create(tx, "User 1")
  let assert Ok(u2) = user.create(tx, "User 2")

  assert password.create(tx, u1.id, "   ", "secretpass123")
    == Error(password.InvalidInput("Login ID is required"))

  let over_login_id = string.repeat("a", password.max_login_id_bytes + 1)
  assert password.create(tx, u1.id, over_login_id, "secretpass123")
    == Error(password.InvalidInput("Login ID must be at most 255 bytes"))
  assert password.exists(tx, over_login_id) == Ok(False)

  assert password.create(tx, u1.id, "short_user", "short")
    == Error(password.InvalidInput("Password must be at least 8 characters"))

  // Exact 1024-byte password succeeds; 1025-byte password fails fast before Argon2id
  let exact_max_pw = string.repeat("p", password.max_password_bytes)
  let over_max_pw = exact_max_pw <> "x"
  assert password.create(tx, u1.id, "too_long_pw", over_max_pw)
    == Error(password.InvalidInput("Password must be at most 1024 bytes"))

  let assert Ok(Nil) = password.create(tx, u1.id, "Dup_Id", exact_max_pw)
  assert password.authenticate(tx, "dup_id", exact_max_pw) == Ok(u1)
  assert password.authenticate(tx, "dup_id", over_max_pw)
    == Error(password.InvalidCredentials)

  // Case-variant duplicate login_id is rejected as AlreadyExists
  assert password.create(tx, u2.id, "DUP_ID", "secretpass123")
    == Error(password.AlreadyExists)

  // Foreign-key violation on nonexistent user_id returns InternalError, NOT AlreadyExists
  assert password.create(tx, -999_999, "orphan_login_id", "secretpass123")
    == Error(password.InternalError)
}

pub fn db_check_constraint_rejects_uppercase_whitespace_and_non_ascii_login_id_test() {
  list.each(["UpperCaseId", "ありす", "äbc", " leading", ""], fn(invalid_raw) {
    use tx <- test_helper.with_db
    let assert Ok(u) = user.create(tx, "ConstraintUser")

    let assert Error(pog.ConstraintViolated(_, constraint:, ..)) =
      pog.query(
        "INSERT INTO password_credentials (user_id, login_id, password_hash) VALUES ($1, $2, $3)",
      )
      |> pog.parameter(pog.int(u.id))
      |> pog.parameter(pog.text(invalid_raw))
      |> pog.parameter(pog.text("dummy_hash"))
      |> pog.returning(decode.dynamic)
      |> pog.execute(tx)

    assert constraint == "password_credentials_login_id_normalized_check"
  })
}

pub fn exists_checks_login_id_presence_test() {
  use tx <- test_helper.with_db

  assert password.exists(tx, "check_user") == Ok(False)

  let assert Ok(created) = user.create(tx, "Check User")
  let assert Ok(Nil) =
    password.create(tx, created.id, "check_user", "secretpass123")

  assert password.exists(tx, "check_user") == Ok(True)
  assert password.exists(tx, "  CHECK_USER  ") == Ok(True)
  assert password.exists(tx, "other_user") == Ok(False)
}
