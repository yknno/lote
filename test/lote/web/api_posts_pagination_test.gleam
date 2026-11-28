import gleam/dynamic/decode
import gleam/http
import gleam/http/request
import gleam/json
import gleam/option.{None}
import gleam/set
import gleam/string
import lote/auth.{Auth, Password}
import lote/auth/user
import lote/db/post_repo
import lote/oidc
import lote/oidc/client
import lote/oidc/scope
import lote/oidc/token
import lote/rate_limit
import lote/realtime/pubsub
import lote/test_helper
import lote/web/router
import wisp/simulate

pub fn api_get_posts_after_cursor_walks_forward_without_dropping_posts_test() {
  use tx <- test_helper.with_db
  let assert Ok(session_revocations) = pubsub.start()
  let assert Ok(grant_revocations) = pubsub.start()
  let assert Ok(post_pubsub) = pubsub.start()

  let secret = "api_pagination_test_secret_key_base_0123456789abcdefghijkl"
  let issuer = "https://lote.example"
  let limiter = rate_limit.disabled()

  let auth_ctx =
    Auth(
      db: tx,
      secret_key_base: secret,
      methods: [Password],
      session_revocations:,
      rate_limiter: limiter,
    )
  let oidc_ctx = oidc.new(tx, issuer, grant_revocations, limiter)

  let assert Ok(alice) = user.create(tx, "CursorAlice")
  let assert Ok(p0) = post_repo.create(tx, alice.id, "p0")
  let assert Ok(p1) = post_repo.create(tx, alice.id, "p1")
  let assert Ok(p2) = post_repo.create(tx, alice.id, "p2")
  let assert Ok(p3) = post_repo.create(tx, alice.id, "p3")
  let assert Ok(p4) = post_repo.create(tx, alice.id, "p4")
  let assert Ok(p5) = post_repo.create(tx, alice.id, "p5")

  let assert Ok(bot) =
    client.create_subordinate_bot(
      tx,
      alice.id,
      "Polling Bot",
      set.from_list([scope.PostsRead]),
      "v1",
      None,
    )
  let assert Ok(issued) =
    token.issue_client_credentials(
      oidc_ctx,
      bot.client.client_id,
      bot.secret.secret,
      None,
      None,
      "PollBot/1.0",
    )

  let ids_decoder = {
    use ids <- decode.field(
      "posts",
      decode.list({
        use id <- decode.field("id", decode.string)
        decode.success(id)
      }),
    )
    decode.success(ids)
  }

  let fetch_after = fn(cursor: String) -> List(String) {
    let resp =
      simulate.request(http.Get, "/api/v1/posts?after=" <> cursor <> "&limit=2")
      |> request.set_header("authorization", "Bearer " <> issued.access_token)
      |> router.handle_request_with_oidc(
        auth_ctx,
        oidc_ctx,
        post_pubsub,
        "127.0.0.1",
      )
    assert resp.status == 200
    let assert Ok(ids) = json.parse(simulate.read_body(resp), ids_decoder)
    ids
  }

  // Polling forward from p0 with limit=2 delivers every unread post in contiguous batches:
  // batch 1: [p2, p1] -> advance cursor to p2
  let batch1 = fetch_after(p0.id)
  assert batch1 == [p2.id, p1.id]

  // batch 2: [p4, p3] -> advance cursor to p4
  let assert [cursor1, ..] = batch1
  let batch2 = fetch_after(cursor1)
  assert batch2 == [p4.id, p3.id]

  // batch 3: [p5] -> advance cursor to p5
  let assert [cursor2, ..] = batch2
  let batch3 = fetch_after(cursor2)
  assert batch3 == [p5.id]

  // batch 4: caught up -> []
  let assert [cursor3, ..] = batch3
  assert fetch_after(cursor3) == []
}

pub fn oversized_json_and_oauth_form_bodies_are_rejected_test() {
  use tx <- test_helper.with_db
  let assert Ok(session_revocations) = pubsub.start()
  let assert Ok(grant_revocations) = pubsub.start()
  let assert Ok(post_pubsub) = pubsub.start()

  let secret = "max_body_size_test_secret_key_base_0123456789abcdefghijkl"
  let issuer = "https://lote.example"
  let limiter = rate_limit.disabled()

  let auth_ctx =
    Auth(
      db: tx,
      secret_key_base: secret,
      methods: [Password],
      session_revocations:,
      rate_limiter: limiter,
    )
  let oidc_ctx = oidc.new(tx, issuer, grant_revocations, limiter)

  let assert Ok(alice) = user.create(tx, "MaxBodyAlice")
  let assert Ok(bot) =
    client.create_subordinate_bot(
      tx,
      alice.id,
      "Write Bot",
      set.from_list([scope.PostsWrite]),
      "v1",
      None,
    )
  let assert Ok(issued) =
    token.issue_client_credentials(
      oidc_ctx,
      bot.client.client_id,
      bot.secret.secret,
      None,
      None,
      "WriteBot/1.0",
    )

  // POST /api/v1/posts with >64 KB JSON body is rejected with 413 payload_too_large
  let large_json = "{\"body\":\"" <> string.repeat("a", 65_600) <> "\"}"
  let posts_resp =
    simulate.request(http.Post, "/api/v1/posts")
    |> request.set_header("authorization", "Bearer " <> issued.access_token)
    |> simulate.string_body(large_json)
    |> request.set_header("content-type", "application/json")
    |> router.handle_request_with_oidc(
      auth_ctx,
      oidc_ctx,
      post_pubsub,
      "127.0.0.1",
    )
  assert posts_resp.status == 413
  assert string.contains(simulate.read_body(posts_resp), "payload_too_large")

  // POST /oidc/token with >16 KB form body is rejected with 400 invalid_request
  let large_form =
    "grant_type=client_credentials&pad=" <> string.repeat("a", 16_500)
  let token_resp =
    simulate.request(http.Post, "/oidc/token")
    |> simulate.string_body(large_form)
    |> request.set_header("content-type", "application/x-www-form-urlencoded")
    |> router.handle_request_with_oidc(
      auth_ctx,
      oidc_ctx,
      post_pubsub,
      "127.0.0.1",
    )
  assert token_resp.status == 400
  assert string.contains(simulate.read_body(token_resp), "invalid_request")
}
