import gleam/bit_array
import gleam/dynamic/decode
import gleam/list
import gleam/option.{None, Some}
import gleam/order
import gleam/string
import lote/auth/user
import lote/db/post_repo
import lote/test_helper
import pog

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

pub fn delete_removes_only_owners_post_test() {
  use tx <- test_helper.with_db

  let assert Ok(alice) = user.create(tx, "Alice")
  let assert Ok(bob) = user.create(tx, "Bob")
  let assert Ok(created) = post_repo.create(tx, alice.id, "ephemeral post")

  // Another user cannot delete Alice's post
  assert post_repo.delete(tx, created.id, bob.id) == Ok(False)
  let assert Ok(Some(_)) = post_repo.find_by_id(tx, created.id)

  // Invalid or unknown UUID returns Ok(False) without DB error
  assert post_repo.delete(tx, "not-a-uuid", alice.id) == Ok(False)
  assert post_repo.delete(tx, "00000000-0000-7000-8000-000000000000", alice.id)
    == Ok(False)

  // Owner can delete (including with uppercase UUID input)
  assert post_repo.delete(tx, string.uppercase(created.id), alice.id)
    == Ok(True)
  assert post_repo.find_by_id(tx, created.id) == Ok(None)

  // Deleting an already-deleted post returns Ok(False)
  assert post_repo.delete(tx, created.id, alice.id) == Ok(False)
}

pub fn list_before_paginates_older_posts_in_descending_order_test() {
  use tx <- test_helper.with_db

  let assert Ok(author) = user.create(tx, "PageAuthor")
  let assert Ok(p1) = post_repo.create(tx, author.id, "post 1")
  let assert Ok(p2) = post_repo.create(tx, author.id, "post 2")
  let assert Ok(p3) = post_repo.create(tx, author.id, "post 3")
  let assert Ok(p4) = post_repo.create(tx, author.id, "post 4")
  let assert Ok(p5) = post_repo.create(tx, author.id, "post 5")

  let assert Ok(page1) = post_repo.list_recent(tx, 2)
  assert list.map(page1, fn(r) { r.id }) == [p5.id, p4.id]

  let assert Ok(page2) = post_repo.list_before(tx, p4.id, 2)
  assert list.map(page2, fn(r) { r.id }) == [p3.id, p2.id]

  // Uppercase UUID cursor works
  let assert Ok(page3) = post_repo.list_before(tx, string.uppercase(p2.id), 2)
  assert list.map(page3, fn(r) { r.id }) == [p1.id]

  // Before oldest post returns empty list
  assert post_repo.list_before(tx, p1.id, 2) == Ok([])

  // Invalid UUID cursor returns Ok([]) without DB error
  assert post_repo.list_before(tx, "not-a-uuid", 2) == Ok([])
}

pub fn list_after_fetches_only_newer_posts_in_descending_order_test() {
  use tx <- test_helper.with_db

  let assert Ok(author) = user.create(tx, "AfterAuthor")
  let assert Ok(p1) = post_repo.create(tx, author.id, "post 1")
  let assert Ok(p2) = post_repo.create(tx, author.id, "post 2")
  let assert Ok(p3) = post_repo.create(tx, author.id, "post 3")
  let assert Ok(p4) = post_repo.create(tx, author.id, "post 4")

  let assert Ok(after_p2) = post_repo.list_after(tx, p2.id, 10)
  assert list.map(after_p2, fn(r) { r.id }) == [p4.id, p3.id]

  // Limit returns the newest matching rows in descending order
  let assert Ok(limited) = post_repo.list_after(tx, p1.id, 2)
  assert list.map(limited, fn(r) { r.id }) == [p4.id, p3.id]

  // Uppercase UUID cursor works
  let assert Ok(after_upper) =
    post_repo.list_after(tx, string.uppercase(p3.id), 10)
  assert list.map(after_upper, fn(r) { r.id }) == [p4.id]

  // After newest post returns empty list
  assert post_repo.list_after(tx, p4.id, 10) == Ok([])

  // Invalid UUID cursor returns Ok([]) without DB error
  assert post_repo.list_after(tx, "not-a-uuid", 10) == Ok([])
}

pub fn validate_body_and_create_enforce_length_limit_test() {
  use tx <- test_helper.with_db

  let assert Ok(author) = user.create(tx, "LimitAuthor")

  // Blank body is rejected
  assert post_repo.validate_body("   \n\t  ") == Error(post_repo.EmptyBody)
  assert post_repo.create(tx, author.id, "   ")
    == Error(post_repo.InvalidBody(post_repo.EmptyBody))

  // Exactly 300 graphemes (including ZWJ family emoji counted as 1 grapheme) succeeds
  let exact_300 = string.repeat("あ", post_repo.max_body_length - 1) <> "👨‍👩‍👧‍👦"
  assert string.length(exact_300) == post_repo.max_body_length
  assert post_repo.validate_body("  " <> exact_300 <> "  ") == Ok(exact_300)
  let assert Ok(created) = post_repo.create(tx, author.id, exact_300)
  assert created.body == exact_300

  // 301 graphemes is rejected without inserting
  let over_301 = string.repeat("a", post_repo.max_body_length + 1)
  assert post_repo.validate_body(over_301)
    == Error(post_repo.BodyTooLong(
      length: post_repo.max_body_length + 1,
      max: post_repo.max_body_length,
    ))
  assert post_repo.create(tx, author.id, over_301)
    == Error(
      post_repo.InvalidBody(post_repo.BodyTooLong(
        length: post_repo.max_body_length + 1,
        max: post_repo.max_body_length,
      )),
    )
}

pub fn validate_body_rejects_oversized_byte_payloads_before_grapheme_count_test() {
  use tx <- test_helper.with_db

  let assert Ok(author) = user.create(tx, "BytesAuthor")

  // 300 ZWJ family emojis (7,500 UTF-8 bytes <= 16,384) succeeds cleanly
  let exact_300_emojis = string.repeat("👨‍👩‍👧‍👦", post_repo.max_body_length)
  assert string.length(exact_300_emojis) == post_repo.max_body_length
  assert bit_array.byte_size(<<exact_300_emojis:utf8>>)
    < post_repo.max_body_bytes
  let assert Ok(created) = post_repo.create(tx, author.id, exact_300_emojis)
  assert created.body == exact_300_emojis

  // Combining-mark bomb: 1 grapheme, but > 16,384 UTF-8 bytes -> rejected before grapheme scan
  let zalgo_bomb = "a" <> string.repeat("\u{0301}", 9000)
  let zalgo_bytes = bit_array.byte_size(<<zalgo_bomb:utf8>>)
  assert zalgo_bytes > post_repo.max_body_bytes
  assert post_repo.validate_body(zalgo_bomb)
    == Error(post_repo.BodyTooLarge(
      bytes: zalgo_bytes,
      max_bytes: post_repo.max_body_bytes,
    ))
  assert post_repo.create(tx, author.id, zalgo_bomb)
    == Error(
      post_repo.InvalidBody(post_repo.BodyTooLarge(
        bytes: zalgo_bytes,
        max_bytes: post_repo.max_body_bytes,
      )),
    )

  // Huge whitespace-padded raw payload exceeds max_raw_body_bytes before trimming
  let huge_raw = string.repeat(" ", post_repo.max_raw_body_bytes) <> "hi"
  let huge_raw_bytes = bit_array.byte_size(<<huge_raw:utf8>>)
  assert huge_raw_bytes > post_repo.max_raw_body_bytes
  assert post_repo.validate_body(huge_raw)
    == Error(post_repo.BodyTooLarge(
      bytes: huge_raw_bytes,
      max_bytes: post_repo.max_body_bytes,
    ))
}

pub fn validate_body_trims_unicode_whitespace_including_fullwidth_space_test() {
  use tx <- test_helper.with_db

  let assert Ok(author) = user.create(tx, "FullwidthAuthor")

  // Full-width spaces (U+3000) alone are treated as EmptyBody
  assert post_repo.validate_body("　　\t\n ") == Error(post_repo.EmptyBody)
  assert post_repo.create(tx, author.id, "　")
    == Error(post_repo.InvalidBody(post_repo.EmptyBody))

  // Leading/trailing full-width spaces are trimmed while inner ones are preserved
  assert post_repo.validate_body("　こんに　ちは　") == Ok("こんに　ちは")

  // Full-width space surrounding a 300-grapheme post still fits within 300 graphemes
  let exact_300 = string.repeat("あ", post_repo.max_body_length)
  assert post_repo.validate_body("　" <> exact_300 <> "　") == Ok(exact_300)
}

pub fn posts_body_check_constraint_enforces_non_blank_and_byte_limit_in_db_test() {
  // Direct SQL insert of blank ASCII / tab / newline / full-width space violates posts_body_check
  {
    use tx <- test_helper.with_db
    let assert Ok(author) = user.create(tx, "CheckBlankAuthor")
    let assert Error(pog.ConstraintViolated(_, constraint: blank_constraint, ..)) =
      pog.query("INSERT INTO posts (user_id, body) VALUES ($1, $2)")
      |> pog.parameter(pog.int(author.id))
      |> pog.parameter(pog.text("   \t\n　"))
      |> pog.returning(decode.dynamic)
      |> pog.execute(tx)
    assert blank_constraint == "posts_body_check"
  }

  // Direct SQL insert exceeding 16,384 bytes must violate posts_body_check
  {
    use tx <- test_helper.with_db
    let assert Ok(author) = user.create(tx, "CheckSizeAuthor")
    let over_bytes = string.repeat("a", post_repo.max_body_bytes + 1)
    let assert Error(pog.ConstraintViolated(_, constraint: size_constraint, ..)) =
      pog.query("INSERT INTO posts (user_id, body) VALUES ($1, $2)")
      |> pog.parameter(pog.int(author.id))
      |> pog.parameter(pog.text(over_bytes))
      |> pog.returning(decode.dynamic)
      |> pog.execute(tx)
    assert size_constraint == "posts_body_check"
  }
}
