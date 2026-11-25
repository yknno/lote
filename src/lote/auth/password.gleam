import argus
import cake/adapter/postgres
import cake/insert as i
import cake/join as j
import cake/select as s
import cake/where as w
import gleam/bit_array
import gleam/dynamic/decode
import gleam/result
import gleam/string
import lote/auth/user.{type AuthUser, AuthUser}
import pog

pub const min_password_length = 8

pub const max_password_bytes = 1024

pub const max_login_id_bytes = 255

const max_raw_login_id_bytes = 1024

pub type Error {
  InvalidInput(String)
  AlreadyExists
  InvalidCredentials
  InternalError
}

/// Normalize and validate `login_id` strictly using locale-independent ASCII rules:
/// - Rejects unbounded payloads (`> 1024` raw bytes) in O(1)
/// - Trims leading/trailing ASCII whitespace (`' '`, `'\t'`, `'\n'`, `'\r'`) only
/// - Lowercases ASCII `'A'..'Z'` to `'a'..'z'` only (never folds non-ASCII such as `K` or `İ`)
/// - Requires 1..=255 bytes consisting strictly of `[a-z0-9._@-]`
pub fn normalize_login_id(raw: String) -> Result(String, Error) {
  let raw_bits = <<raw:utf8>>
  case bit_array.byte_size(raw_bits) > max_raw_login_id_bytes {
    True -> Error(InvalidInput("Login ID must be at most 255 bytes"))
    False -> {
      let trimmed =
        raw_bits
        |> trim_leading_ascii_whitespace
        |> trim_trailing_ascii_whitespace
      let size = bit_array.byte_size(trimmed)
      case size {
        0 -> Error(InvalidInput("Login ID is required"))
        _ if size > max_login_id_bytes ->
          Error(InvalidInput("Login ID must be at most 255 bytes"))
        _ -> ascii_lowercase_login_id(trimmed, <<>>)
      }
    }
  }
}

pub fn create(
  db: pog.Connection,
  user_id: Int,
  login_id: String,
  password: String,
) -> Result(Nil, Error) {
  use login_id <- result.try(normalize_login_id(login_id))

  case bit_array.byte_size(<<password:utf8>>) > max_password_bytes {
    True -> Error(InvalidInput("Password must be at most 1024 bytes"))
    False ->
      case string.length(password) >= min_password_length {
        False -> Error(InvalidInput("Password must be at least 8 characters"))
        True -> {
          use hashed <- result.try(
            argus.hasher()
            |> argus.hash(password)
            |> result.replace_error(InternalError),
          )

          let query =
            [
              i.row([
                i.int(user_id),
                i.string(login_id),
                i.string(hashed.encoded_hash),
              ]),
            ]
            |> i.from_values(table_name: "password_credentials", columns: [
              "user_id",
              "login_id",
              "password_hash",
            ])
            |> i.to_query

          case postgres.run_write_query(query, decode.dynamic, db) {
            Ok(_) -> Ok(Nil)
            Error(pog.ConstraintViolated(_, constraint, _))
              if constraint == "password_credentials_login_id_key"
            -> Error(AlreadyExists)
            Error(_) -> Error(InternalError)
          }
        }
      }
  }
}

pub fn exists(db: pog.Connection, login_id: String) -> Result(Bool, Error) {
  case normalize_login_id(login_id) {
    Error(_) -> Ok(False)
    Ok(login_id) -> {
      let query =
        s.new()
        |> s.from_table("password_credentials")
        |> s.select(s.col("id"))
        |> s.where(w.eq(w.col("login_id"), w.string(login_id)))
        |> s.limit(1)
        |> s.to_query

      case postgres.run_read_query(query, decode.dynamic, db) {
        Ok([_, ..]) -> Ok(True)
        Ok([]) -> Ok(False)
        Error(_) -> Error(InternalError)
      }
    }
  }
}

pub fn authenticate(
  db: pog.Connection,
  login_id: String,
  password: String,
) -> Result(AuthUser, Error) {
  case
    normalize_login_id(login_id),
    bit_array.byte_size(<<password:utf8>>) <= max_password_bytes
  {
    Ok(login_id), True ->
      case find_credential(db, login_id) {
        Ok(#(auth_user, password_hash)) ->
          case argus.verify(password_hash, password) {
            Ok(True) -> Ok(auth_user)
            Ok(False) -> Error(InvalidCredentials)
            Error(_) -> Error(InternalError)
          }
        Error(InvalidCredentials) -> {
          // login_id が存在しない場合も Argon2id ハッシュ計算を実行し、
          // レスポンス時間の差からユーザーの存在有無を推測されるのを防ぐ。
          let _ = argus.hasher() |> argus.hash(password)
          Error(InvalidCredentials)
        }
        Error(err) -> Error(err)
      }
    _, _ -> Error(InvalidCredentials)
  }
}

fn find_credential(
  db: pog.Connection,
  login_id: String,
) -> Result(#(AuthUser, String), Error) {
  let query =
    s.new()
    |> s.from_table("password_credentials")
    |> s.join(j.inner(
      with: j.table("users"),
      on: w.eq(w.col("users.id"), w.col("password_credentials.user_id")),
      alias: "users",
    ))
    |> s.selects([
      s.col("users.id"),
      s.col("users.name"),
      s.col("password_credentials.password_hash"),
    ])
    |> s.where(w.eq(w.col("password_credentials.login_id"), w.string(login_id)))
    |> s.limit(1)
    |> s.to_query

  let decoder = {
    use id <- decode.field(0, decode.int)
    use name <- decode.field(1, decode.string)
    use password_hash <- decode.field(2, decode.string)
    decode.success(#(AuthUser(id:, name:), password_hash))
  }

  case postgres.run_read_query(query, decoder, db) {
    Ok([found, ..]) -> Ok(found)
    Ok([]) -> Error(InvalidCredentials)
    Error(_) -> Error(InternalError)
  }
}

fn is_ascii_whitespace(byte: Int) -> Bool {
  case byte {
    0x20 | 0x09 | 0x0A | 0x0D -> True
    _ -> False
  }
}

fn trim_leading_ascii_whitespace(bits: BitArray) -> BitArray {
  case bits {
    <<byte, rest:bytes>> ->
      case is_ascii_whitespace(byte) {
        True -> trim_leading_ascii_whitespace(rest)
        False -> bits
      }
    _ -> bits
  }
}

fn trim_trailing_ascii_whitespace(bits: BitArray) -> BitArray {
  let size = bit_array.byte_size(bits)
  case size > 0 {
    False -> bits
    True ->
      case bit_array.slice(bits, size - 1, 1) {
        Ok(<<byte>>) ->
          case is_ascii_whitespace(byte) {
            True -> {
              let assert Ok(prefix) = bit_array.slice(bits, 0, size - 1)
              trim_trailing_ascii_whitespace(prefix)
            }
            False -> bits
          }
        _ -> bits
      }
  }
}

fn ascii_lowercase_login_id(
  bits: BitArray,
  acc: BitArray,
) -> Result(String, Error) {
  case bits {
    <<>> ->
      bit_array.to_string(acc)
      |> result.replace_error(InternalError)
    <<byte, rest:bytes>> ->
      case normalize_login_id_byte(byte) {
        Ok(normalized) ->
          ascii_lowercase_login_id(rest, <<acc:bits, normalized>>)
        Error(Nil) ->
          Error(InvalidInput(
            "Login ID may only contain ASCII letters, digits, '.', '_', '-', or '@'",
          ))
      }
    _ ->
      Error(InvalidInput(
        "Login ID may only contain ASCII letters, digits, '.', '_', '-', or '@'",
      ))
  }
}

fn normalize_login_id_byte(byte: Int) -> Result(Int, Nil) {
  case byte {
    // 'A'..'Z' -> 'a'..'z'
    b if b >= 0x41 && b <= 0x5A -> Ok(b + 32)
    // 'a'..'z'
    b if b >= 0x61 && b <= 0x7A -> Ok(b)
    // '0'..'9'
    b if b >= 0x30 && b <= 0x39 -> Ok(b)
    // '.', '_', '-', '@'
    0x2E | 0x5F | 0x2D | 0x40 -> Ok(byte)
    _ -> Error(Nil)
  }
}
