import gleam/bit_array
import gleam/dynamic/decode
import gleam/erlang/process
import gleam/http
import gleam/http/request
import gleam/json
import gleam/option.{None, Some}
import gleam/set
import gleam/string
import lote/auth.{Auth, Password}
import lote/auth/session
import lote/auth/user
import lote/oidc
import lote/oidc/client
import lote/oidc/grant
import lote/oidc/scope
import lote/oidc/token
import lote/rate_limit
import lote/realtime/pubsub
import lote/test_helper
import lote/web/csrf
import lote/web/router
import wisp
import wisp/simulate

fn basic_header(cid: String, secret: String) -> String {
  "Basic " <> bit_array.base64_encode(<<{ cid <> ":" <> secret }:utf8>>, True)
}

fn parse_issued_tokens(
  resp: wisp.Response,
) -> #(String, option.Option(String)) {
  let decoder = {
    use at <- decode.field("access_token", decode.string)
    use rt <- decode.optional_field(
      "refresh_token",
      None,
      decode.optional(decode.string),
    )
    decode.success(#(at, rt))
  }
  let assert Ok(parsed) = json.parse(simulate.read_body(resp), decoder)
  parsed
}

import gleam/list

fn extract_csrf_from_html(html_body: String) -> String {
  let needle = "name=\"" <> csrf.form_field_name <> "\""
  let assert Ok(#(before, after)) = string.split_once(html_body, needle)
  let tag_start = case string.split(before, "<") {
    [] -> ""
    parts -> {
      let assert Ok(last) = list.last(parts)
      last
    }
  }
  let assert Ok(#(tag_end, _)) = string.split_once(after, ">")
  let tag = tag_start <> needle <> tag_end
  let assert Ok(#(_, rest)) = string.split_once(tag, "value=\"")
  let assert Ok(#(val, _)) = string.split_once(rest, "\"")
  val
}

pub fn revoking_bot_secret_immediately_invalidates_its_tokens_and_preserves_rotated_secret_tokens_test() {
  use tx <- test_helper.with_db
  let assert Ok(session_revocations) = pubsub.start()
  let assert Ok(grant_revocations) = pubsub.start()
  let assert Ok(post_pubsub) = pubsub.start()
  let grant_rev_sub = process.new_subject()
  pubsub.subscribe(grant_revocations, grant_rev_sub)

  let secret_key =
    "secret_revocation_test_key_base_0123456789abcdefghijklmnopqr"
  let issuer = "https://lote.example"
  let limiter = rate_limit.disabled()

  let auth_ctx =
    Auth(
      db: tx,
      secret_key_base: secret_key,
      methods: [Password],
      session_revocations:,
      rate_limiter: limiter,
    )
  let oidc_ctx = oidc.new(tx, issuer, grant_revocations, limiter)

  let dispatch = fn(req: wisp.Request) {
    router.handle_request_with_oidc(
      req,
      auth_ctx,
      oidc_ctx,
      post_pubsub,
      "127.0.0.1",
    )
  }

  let assert Ok(alice) = user.create(tx, "SecretRotateAlice")
  let assert Ok(bot) =
    client.create_subordinate_bot(
      tx,
      alice.id,
      "Rotatable Bot",
      set.from_list([scope.PostsRead, scope.PostsWrite]),
      "v1-leaked",
      None,
    )
  let assert Ok(secret_v2) =
    client.create_secret(tx, alice.id, bot.client.client_id, "v2-rotated", None)

  // Mint access token 1 via HTTP /oidc/token with secret v1, and access token 2 with secret v2
  let tok1_resp =
    simulate.request(http.Post, "/oidc/token")
    |> request.set_header(
      "authorization",
      basic_header(bot.client.client_id, bot.secret.secret),
    )
    |> simulate.form_body([#("grant_type", "client_credentials")])
    |> dispatch
  assert tok1_resp.status == 200
  let assert #(at_v1, None) = parse_issued_tokens(tok1_resp)

  let tok2_resp =
    simulate.request(http.Post, "/oidc/token")
    |> request.set_header(
      "authorization",
      basic_header(bot.client.client_id, secret_v2.secret),
    )
    |> simulate.form_body([#("grant_type", "client_credentials")])
    |> dispatch
  assert tok2_resp.status == 200
  let assert #(at_v2, None) = parse_issued_tokens(tok2_resp)

  // Both tokens work on GET /api/v1/posts prior to secret revocation
  assert dispatch(
      simulate.request(http.Get, "/api/v1/posts")
      |> request.set_header("authorization", "Bearer " <> at_v1),
    ).status
    == 200
  assert dispatch(
      simulate.request(http.Get, "/api/v1/posts")
      |> request.set_header("authorization", "Bearer " <> at_v2),
    ).status
    == 200

  let assert Ok([grant_a, grant_b]) =
    grant.list_active_grants_for_user(tx, alice.id)
  assert grant_a.public_id != grant_b.public_id

  // Alice revokes secret v1 via Web UI POST /settings/clients/:client_id/secrets/:secret_id/revoke
  let login_req = simulate.browser_request(http.Post, "/auth/password/login")
  let assert Ok(alice_login) =
    session.create(wisp.ok(), login_req, tx, secret_key, alice)
  let clients_page_req =
    simulate.browser_request(http.Get, "/settings/clients")
    |> simulate.session(login_req, alice_login)
  let clients_page_resp = dispatch(clients_page_req)
  assert clients_page_resp.status == 200
  let csrf_token = extract_csrf_from_html(simulate.read_body(clients_page_resp))

  let revoke_resp =
    simulate.browser_request(
      http.Post,
      "/settings/clients/"
        <> bot.client.client_id
        <> "/secrets/"
        <> bot.secret.info.public_id
        <> "/revoke",
    )
    |> simulate.session(clients_page_req, clients_page_resp)
    |> simulate.form_body([#(csrf.form_field_name, csrf_token)])
    |> dispatch
  assert revoke_resp.status == 303

  // Grant revocation event is published for the grant minted by secret v1!
  let assert Ok(revoked_grant_id) = process.receive(grant_rev_sub, 200)
  assert revoked_grant_id == grant_a.public_id
    || revoked_grant_id == grant_b.public_id
  assert process.receive(grant_rev_sub, 20) == Error(Nil)

  // at_v1 is IMMEDIATELY rejected with 401 on /api/v1/posts and inactive on /oidc/introspect!
  let at_v1_api =
    simulate.request(http.Get, "/api/v1/posts")
    |> request.set_header("authorization", "Bearer " <> at_v1)
    |> dispatch
  assert at_v1_api.status == 401

  let introspect_v1 =
    simulate.request(http.Post, "/oidc/introspect")
    |> request.set_header(
      "authorization",
      basic_header(bot.client.client_id, secret_v2.secret),
    )
    |> simulate.form_body([#("token", at_v1)])
    |> dispatch
  assert introspect_v1.status == 200
  assert simulate.read_body(introspect_v1) == "{\"active\":false}"

  // Meanwhile, at_v2 (minted with rotated secret v2) continues working uninterrupted!
  let at_v2_api =
    simulate.request(http.Get, "/api/v1/posts")
    |> request.set_header("authorization", "Bearer " <> at_v2)
    |> dispatch
  assert at_v2_api.status == 200
}

pub fn revoking_confidential_app_secret_invalidates_access_token_while_preserving_refresh_grant_test() {
  use tx <- test_helper.with_db
  let assert Ok(session_revocations) = pubsub.start()
  let assert Ok(grant_revocations) = pubsub.start()
  let assert Ok(post_pubsub) = pubsub.start()
  let grant_rev_sub = process.new_subject()
  pubsub.subscribe(grant_revocations, grant_rev_sub)

  let secret_key = "conf_app_secret_revocation_key_base_0123456789abcdefghijkl"
  let issuer = "https://lote.example"
  let limiter = rate_limit.disabled()

  let auth_ctx =
    Auth(
      db: tx,
      secret_key_base: secret_key,
      methods: [Password],
      session_revocations:,
      rate_limiter: limiter,
    )
  let oidc_ctx = oidc.new(tx, issuer, grant_revocations, limiter)

  let dispatch = fn(req: wisp.Request) {
    router.handle_request_with_oidc(
      req,
      auth_ctx,
      oidc_ctx,
      post_pubsub,
      "127.0.0.1",
    )
  }

  let assert Ok(alice) = user.create(tx, "ConfRotateAlice")
  let redirect_uri = "https://app.example/callback"
  let scopes =
    set.from_list([scope.OpenId, scope.OfflineAccess, scope.PostsRead])

  let assert Ok(#(conf_app, Some(secret_1))) =
    client.create_app(
      tx,
      alice.id,
      "Confidential Web App",
      True,
      client.Private,
      client.Web,
      [redirect_uri],
      scopes,
    )
  let assert Ok(secret_2) =
    client.create_secret(tx, alice.id, conf_app.client_id, "rotated", None)

  let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  let challenge = token.compute_pkce_s256_challenge(verifier)
  let assert Ok(#(consent_id, _, _)) =
    grant.upsert_consent(tx, alice.id, conf_app.id, scopes)
  let assert Ok(#(auth_code, _)) =
    token.issue_authorization_code(
      tx,
      consent_id,
      scopes,
      issuer,
      redirect_uri,
      challenge,
      None,
      "Browser/1.0",
    )

  // Exchange auth code using secret_1 -> mints access_token_1 (bound to secret_1) + refresh_token_1
  let ex_resp =
    simulate.request(http.Post, "/oidc/token")
    |> request.set_header(
      "authorization",
      basic_header(conf_app.client_id, secret_1.secret),
    )
    |> simulate.form_body([
      #("grant_type", "authorization_code"),
      #("code", auth_code),
      #("redirect_uri", redirect_uri),
      #("code_verifier", verifier),
    ])
    |> dispatch
  assert ex_resp.status == 200
  let assert #(at_1, Some(rt_1)) = parse_issued_tokens(ex_resp)

  let assert Ok([active_grant]) =
    grant.list_active_grants_for_user(tx, alice.id)

  // Revoke secret_1 -> at_1 is immediately invalidated (401), revoke_secret_returning_grants
  // reports active_grant.public_id for PubSub notification, while the offline_access grant survives!
  assert client.revoke_secret_returning_grants(
      tx,
      alice.id,
      conf_app.client_id,
      secret_1.info.public_id,
    )
    == Ok(Some([active_grant.public_id]))

  assert dispatch(
      simulate.request(http.Get, "/api/v1/posts")
      |> request.set_header("authorization", "Bearer " <> at_1),
    ).status
    == 401

  // Confidential app can seamlessly refresh using rotated secret_2 and receive a working access_token_2!
  let refresh_resp =
    simulate.request(http.Post, "/oidc/token")
    |> request.set_header(
      "authorization",
      basic_header(conf_app.client_id, secret_2.secret),
    )
    |> simulate.form_body([
      #("grant_type", "refresh_token"),
      #("refresh_token", rt_1),
    ])
    |> dispatch
  assert refresh_resp.status == 200
  let assert #(at_2, Some(_rt_2)) = parse_issued_tokens(refresh_resp)

  assert dispatch(
      simulate.request(http.Get, "/api/v1/posts")
      |> request.set_header("authorization", "Bearer " <> at_2),
    ).status
    == 200

  // Revoking at_2 via RFC 7009 /oidc/revoke publishes a grant_revocations PubSub event
  // even though the parent offline_access grant still has an active refresh token.
  let revoke_at_resp =
    simulate.request(http.Post, "/oidc/revoke")
    |> request.set_header(
      "authorization",
      basic_header(conf_app.client_id, secret_2.secret),
    )
    |> simulate.form_body([#("token", at_2)])
    |> dispatch
  assert revoke_at_resp.status == 200
  assert process.receive(grant_rev_sub, 200) == Ok(active_grant.public_id)

  // Parent grant still survives because rt_2 is still active
  assert grant.list_active_grants_for_user(tx, alice.id) == Ok([active_grant])
}
