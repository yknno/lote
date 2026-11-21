import cake/adapter/postgres
import cake/insert as i
import gleam/dynamic/decode
import pog

pub type AuthUser {
  AuthUser(id: Int, name: String)
}

pub fn create(
  db: pog.Connection,
  name: String,
) -> Result(AuthUser, pog.QueryError) {
  let query =
    [i.row([i.string(name)])]
    |> i.from_values(table_name: "users", columns: ["name"])
    |> i.returning(["id", "name"])
    |> i.to_query

  let decoder = {
    use id <- decode.field(0, decode.int)
    use name <- decode.field(1, decode.string)
    decode.success(AuthUser(id:, name:))
  }

  case postgres.run_write_query(query, decoder, db) {
    Ok([auth_user, ..]) -> Ok(auth_user)
    Ok([]) -> Error(pog.ConnectionUnavailable)
    Error(err) -> Error(err)
  }
}
