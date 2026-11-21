//// This module contains the code to run the sql queries defined in
//// `./src/lote/db/sql`.
//// > 🐿️ This module was generated automatically using v4.7.0 of
//// > the [squirrel package](https://github.com/giacomocavalieri/squirrel).
////

import gleam/dynamic/decode
import gleam/time/timestamp.{type Timestamp}
import pog

/// A row you get from running the `create_post` query
/// defined in `./src/lote/db/sql/create_post.sql`.
///
/// > 🐿️ This type definition was generated automatically using v4.7.0 of the
/// > [squirrel package](https://github.com/giacomocavalieri/squirrel).
///
pub type CreatePostRow {
  CreatePostRow(id: Int, body: String, created_at: Timestamp)
}

/// Runs the `create_post` query
/// defined in `./src/lote/db/sql/create_post.sql`.
///
/// > 🐿️ This function was generated automatically using v4.7.0 of
/// > the [squirrel package](https://github.com/giacomocavalieri/squirrel).
///
pub fn create_post(
  db: pog.Connection,
  arg_1: String,
) -> Result(pog.Returned(CreatePostRow), pog.QueryError) {
  let decoder = {
    use id <- decode.field(0, decode.int)
    use body <- decode.field(1, decode.string)
    use created_at <- decode.field(2, pog.timestamp_decoder())
    decode.success(CreatePostRow(id:, body:, created_at:))
  }

  "INSERT INTO posts (body)
VALUES ($1)
RETURNING id, body, created_at;
"
  |> pog.query
  |> pog.parameter(pog.text(arg_1))
  |> pog.returning(decoder)
  |> pog.execute(db)
}

/// A row you get from running the `list_posts` query
/// defined in `./src/lote/db/sql/list_posts.sql`.
///
/// > 🐿️ This type definition was generated automatically using v4.7.0 of the
/// > [squirrel package](https://github.com/giacomocavalieri/squirrel).
///
pub type ListPostsRow {
  ListPostsRow(id: Int, body: String, created_at: Timestamp)
}

/// Runs the `list_posts` query
/// defined in `./src/lote/db/sql/list_posts.sql`.
///
/// > 🐿️ This function was generated automatically using v4.7.0 of
/// > the [squirrel package](https://github.com/giacomocavalieri/squirrel).
///
pub fn list_posts(
  db: pog.Connection,
  arg_1: Int,
) -> Result(pog.Returned(ListPostsRow), pog.QueryError) {
  let decoder = {
    use id <- decode.field(0, decode.int)
    use body <- decode.field(1, decode.string)
    use created_at <- decode.field(2, pog.timestamp_decoder())
    decode.success(ListPostsRow(id:, body:, created_at:))
  }

  "SELECT id, body, created_at
FROM posts
ORDER BY created_at DESC, id DESC
LIMIT $1;
"
  |> pog.query
  |> pog.parameter(pog.int(arg_1))
  |> pog.returning(decoder)
  |> pog.execute(db)
}
