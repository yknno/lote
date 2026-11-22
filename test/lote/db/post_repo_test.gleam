import gleam/list
import gleam/option.{None, Some}
import gleam/order
import gleam/string
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
  assert string.length(first.id) == 36
  assert string.length(second.id) == 36
  // RFC 9562 UUIDv7 version nibble is '7' at index 14
  assert string.slice(first.id, at_index: 14, length: 1) == "7"
  assert string.slice(second.id, at_index: 14, length: 1) == "7"
  assert string.compare(second.id, first.id) == order.Gt

  let assert Ok(rows) = post_repo.list_recent(tx, 2)
  let bodies = list.map(rows, fn(r) { #(r.id, r.author_name, r.body) })

  assert bodies
    == [
      #(second.id, "TestAuthor", "second post"),
      #(first.id, "TestAuthor", "first post"),
    ]
}

pub fn find_by_id_returns_matching_post_or_none_test() {
  use tx <- test_helper.with_db

  let assert Ok(author) = user.create(tx, "FindAuthor")
  let assert Ok(created) = post_repo.create(tx, author.id, "findable post")

  let assert Ok(Some(found)) = post_repo.find_by_id(tx, created.id)
  assert found.id == created.id
  assert found.author_name == "FindAuthor"
  assert found.body == "findable post"

  // Uppercase UUID input is normalized cleanly
  let assert Ok(Some(found_upper)) =
    post_repo.find_by_id(tx, string.uppercase(created.id))
  assert found_upper.id == created.id

  // Unknown valid UUID -> Ok(None)
  assert post_repo.find_by_id(tx, "00000000-0000-7000-8000-000000000000")
    == Ok(None)

  // Invalid non-UUID input -> Ok(None) without DB error
  assert post_repo.find_by_id(tx, "not-a-uuid") == Ok(None)
}
