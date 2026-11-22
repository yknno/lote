import gleam/list
import lote/auth/user
import lote/db/post_repo
import lote/test_helper

pub fn create_and_list_recent_returns_posts_in_descending_id_order_test() {
  use tx <- test_helper.with_db

  let assert Ok(author) = user.create(tx, "TestAuthor")
  let assert Ok(first) = post_repo.create(tx, author.id, "first post")
  let assert Ok(second) = post_repo.create(tx, author.id, "second post")

  assert first.body == "first post"
  assert second.body == "second post"
  assert second.id > first.id

  let assert Ok(rows) = post_repo.list_recent(tx, 2)
  let bodies = list.map(rows, fn(r) { #(r.id, r.author_name, r.body) })

  assert bodies
    == [
      #(second.id, "TestAuthor", "second post"),
      #(first.id, "TestAuthor", "first post"),
    ]
}
