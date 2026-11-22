import argus
import cake/adapter/postgres
import cake/insert as i
import cake/join as j
import cake/select as s
import cake/where as w
import gleam/dynamic/decode
import gleam/result
import gleam/string
import lote/auth/user.{type AuthUser, AuthUser}
import pog

pub type Error {
  InvalidInput(String)
  AlreadyExists
  InvalidCredentials
  InternalError
}

pub fn create(
  db: pog.Connection,
  user_id: Int,
  login_id: String,
  password: String,
) -> Result(Nil, Error) {
  let login_id = string.trim(login_id)

  case login_id, string.length(password) >= 8 {
    "", _ -> Error(InvalidInput("Login ID is required"))
    _, False -> Error(InvalidInput("Password must be at least 8 characters"))
    _, True -> {
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
        Error(pog.ConstraintViolated(_, _, _)) -> Error(AlreadyExists)
        Error(_) -> Error(InternalError)
      }
    }
  }
}

pub fn exists(db: pog.Connection, login_id: String) -> Result(Bool, Error) {
  let login_id = string.trim(login_id)
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

pub fn authenticate(
  db: pog.Connection,
  login_id: String,
  password: String,
) -> Result(AuthUser, Error) {
  let login_id = string.trim(login_id)
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
