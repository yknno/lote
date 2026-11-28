import gleam/dynamic/decode
import gleam/erlang/process
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/set
import gleam/string
import lote/auth/user
import lote/oidc
import lote/oidc/cimd
import lote/oidc/cleanup
import lote/oidc/client
import lote/oidc/grant
import lote/oidc/jwt
import lote/oidc/scope
import lote/oidc/token
import lote/rate_limit
import lote/realtime/pubsub
import lote/test_helper
import pog

const valid_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

pub fn redirect_uri_validation_and_rfc8252_loopback_matching_test() {
  use tx <- test_helper.with_db

  // Valid redirect URIs
  assert client.validate_redirect_uri("https://app.example.com/callback")
    == Ok("https://app.example.com/callback")
  assert client.validate_redirect_uri("http://127.0.0.1:8080/cb")
    == Ok("http://127.0.0.1:8080/cb")
  assert client.validate_redirect_uri("http://[::1]:9000/cb")
    == Ok("http://[::1]:9000/cb")
  assert client.validate_redirect_uri("http://localhost:3000/cb")
    == Ok("http://localhost:3000/cb")

  // Invalid redirect URIs
  let assert Error(_) = client.validate_redirect_uri("")
  let assert Error(_) =
    client.validate_redirect_uri(" https://app.example.com/cb ")
  let assert Error(_) =
    client.validate_redirect_uri("http://app.example.com/cb")
  let assert Error(_) =
    client.validate_redirect_uri("https://app.example.com/cb#frag")
  let assert Error(_) =
    client.validate_redirect_uri("https://user:pass@app.example.com/cb")
  let assert Error(_) = client.validate_redirect_uri("customscheme://callback")

  let assert Ok(alice) = user.create(tx, "RedirectOwner")
  let scopes = set.from_list([scope.OpenId, scope.PostsRead])

  // Web client requires exact port match even on loopback
  let assert Ok(#(web_client, None)) =
    client.create_app(
      tx,
      alice.id,
      "Web Loopback App",
      False,
      client.Private,
      client.Web,
      ["http://127.0.0.1:8080/cb", "https://app.example.com/cb"],
      scopes,
    )
  assert client.matches_redirect_uri(web_client, "http://127.0.0.1:8080/cb")
  assert !client.matches_redirect_uri(web_client, "http://127.0.0.1:9999/cb")

  // Native client allows ephemeral port on 127.0.0.1 and [::1], NOT localhost
  let assert Ok(#(native_client, None)) =
    client.create_app(
      tx,
      alice.id,
      "Native CLI App",
      False,
      client.Public,
      client.Native,
      [
        "http://127.0.0.1/oauth/cb",
        "http://[::1]/oauth/cb",
        "http://localhost:3000/oauth/cb",
      ],
      scopes,
    )

  assert client.matches_redirect_uri(
    native_client,
    "http://127.0.0.1:54321/oauth/cb",
  )
  assert client.matches_redirect_uri(
    native_client,
    "http://[::1]:51234/oauth/cb",
  )
  // Path and query must still match strictly
  assert !client.matches_redirect_uri(
    native_client,
    "http://127.0.0.1:54321/other",
  )
  assert !client.matches_redirect_uri(
    native_client,
    "http://127.0.0.1:54321/oauth/cb?extra=1",
  )
  // localhost requires exact port match per RFC 8252
  assert client.matches_redirect_uri(
    native_client,
    "http://localhost:3000/oauth/cb",
  )
  assert !client.matches_redirect_uri(
    native_client,
    "http://localhost:4444/oauth/cb",
  )
}

pub fn subordinate_bot_creation_auto_consent_and_validation_test() {
  use tx <- test_helper.with_db

  let assert Ok(alice) = user.create(tx, "AliceBotOwner")
  let assert Ok(bob) = user.create(tx, "BobOther")

  // Rejects non-bot scopes (openid, profile, offline_access)
  let assert Error(client.InvalidScope(_)) =
    client.create_subordinate_bot(
      tx,
      alice.id,
      "Bad Bot",
      set.from_list([scope.OpenId, scope.PostsRead]),
      "prod",
      None,
    )
  let assert Error(client.InvalidScope(_)) =
    client.create_subordinate_bot(
      tx,
      alice.id,
      "Offline Bot",
      set.from_list([scope.OfflineAccess]),
      "prod",
      None,
    )
  let assert Error(client.InvalidScope(_)) =
    client.create_subordinate_bot(
      tx,
      alice.id,
      "Empty Bot",
      set.new(),
      "",
      None,
    )
  let assert Error(client.InvalidInput(_)) =
    client.create_subordinate_bot(
      tx,
      alice.id,
      "   ",
      set.from_list([scope.PostsRead]),
      "prod",
      None,
    )
  let assert Error(client.InvalidInput(_)) =
    client.create_subordinate_bot(
      tx,
      alice.id,
      "Zero TTL Bot",
      set.from_list([scope.PostsRead]),
      "prod",
      Some(0),
    )

  let bot_scopes = set.from_list([scope.PostsRead, scope.PostsWrite])
  let assert Ok(created_bot) =
    client.create_subordinate_bot(
      tx,
      alice.id,
      "  Alice Auto Poster  ",
      bot_scopes,
      "  primary  ",
      Some(86_400),
    )

  assert created_bot.client.name == "Alice Auto Poster"
  assert created_bot.client.kind == client.SubordinateBot
  assert created_bot.client.visibility == client.Private
  assert created_bot.client.owner_user_id == Some(alice.id)
  assert created_bot.client.redirect_uris == []
  assert created_bot.client.allowed_scopes == bot_scopes
  assert string.starts_with(created_bot.client.client_id, "cli_")
  assert string.starts_with(created_bot.secret.secret, "lote_cs_")
  assert created_bot.secret.info.label == "primary"
  assert created_bot.secret.info.secret_prefix
    == string.slice(created_bot.secret.secret, at_index: 0, length: 12)
  assert created_bot.secret.info.expires_at != None

  // Owner consent was atomically created
  let assert Ok(Some(#(_cid, consent_pub_id, consent_scopes))) =
    grant.find_consent(tx, alice.id, created_bot.client.id)
  assert consent_pub_id == created_bot.consent_public_id
  assert consent_scopes == bot_scopes

  let assert Ok(consents) = grant.list_consents_for_user(tx, alice.id)
  assert list.length(consents) == 1

  let assert Ok(listed) = client.list_for_owner(tx, alice.id)
  let assert [#(listed_client, [listed_secret])] = listed
  assert listed_client.client_id == created_bot.client.client_id
  assert listed_secret.public_id == created_bot.secret.info.public_id

  let assert Ok(Some(found)) =
    client.find_by_client_id(tx, created_bot.client.client_id)
  assert found.id == created_bot.client.id

  // Bob cannot delete Alice's bot
  assert client.delete_for_owner(tx, bob.id, created_bot.client.client_id)
    == Ok(None)
  // Alice deletes her bot (0 active grants -> Some([]))
  assert client.delete_for_owner(tx, alice.id, created_bot.client.client_id)
    == Ok(Some([]))
  assert client.find_by_client_id(tx, created_bot.client.client_id) == Ok(None)
}

pub fn multi_secret_zero_downtime_rotation_expiry_and_limit_test() {
  use tx <- test_helper.with_db

  let assert Ok(alice) = user.create(tx, "SecretRotator")
  let assert Ok(bob) = user.create(tx, "Intruder")

  let assert Ok(bot) =
    client.create_subordinate_bot(
      tx,
      alice.id,
      "Rotation Bot",
      set.from_list([scope.PostsRead]),
      "v1",
      None,
    )
  let cid = bot.client.client_id
  let s1 = bot.secret

  // Mint second secret while v1 is still active
  let assert Ok(s2) = client.create_secret(tx, alice.id, cid, "v2", Some(3600))

  // Both secrets authenticate simultaneously (zero-downtime rotation)
  let assert Ok(authed1) = client.authenticate_secret(tx, cid, s1.secret)
  let assert Ok(authed2) = client.authenticate_secret(tx, cid, s2.secret)
  assert authed1.id == bot.client.id
  assert authed2.id == bot.client.id

  // Wrong secret or wrong client_id fails
  assert client.authenticate_secret(tx, cid, "lote_cs_wrong")
    == Error(client.InvalidClientCredentials)
  assert client.authenticate_secret(tx, "cli_nonexistent", s1.secret)
    == Error(client.InvalidClientCredentials)

  // Bob cannot mint or revoke secrets on Alice's bot
  assert client.create_secret(tx, bob.id, cid, "evil", None)
    == Error(client.NotFound)
  assert client.revoke_secret(tx, bob.id, cid, s1.info.public_id) == Ok(False)
  assert client.revoke_secret(tx, alice.id, cid, "not-a-uuid") == Ok(False)

  // Alice revokes old secret v1 -> v1 stops working, v2 continues working!
  assert client.revoke_secret(tx, alice.id, cid, s1.info.public_id) == Ok(True)
  assert client.authenticate_secret(tx, cid, s1.secret)
    == Error(client.InvalidClientCredentials)
  let assert Ok(_) = client.authenticate_secret(tx, cid, s2.secret)

  // Mint s3 and expire it in Postgres -> expired secret fails auth and does not count toward limit
  let assert Ok(s3) =
    client.create_secret(tx, alice.id, cid, "expiring", Some(60))
  let assert Ok(_) =
    pog.query(
      "UPDATE oidc_client_secrets SET expires_at = NOW() - INTERVAL '1 second' WHERE public_id = $1::uuid",
    )
    |> pog.parameter(pog.text(s3.info.public_id))
    |> pog.returning(decode.dynamic)
    |> pog.execute(tx)

  assert client.authenticate_secret(tx, cid, s3.secret)
    == Error(client.InvalidClientCredentials)

  // Currently 1 active secret (s2). Mint 4 more to reach max_active_secrets_per_client (5)
  let assert Ok(_) = client.create_secret(tx, alice.id, cid, "k2", None)
  let assert Ok(_) = client.create_secret(tx, alice.id, cid, "k3", None)
  let assert Ok(_) = client.create_secret(tx, alice.id, cid, "k4", None)
  let assert Ok(_) = client.create_secret(tx, alice.id, cid, "k5", None)

  // 6th active secret is rejected with SecretLimitExceeded
  assert client.create_secret(tx, alice.id, cid, "k6", None)
    == Error(client.SecretLimitExceeded)
}

pub fn client_credentials_audience_binding_and_owner_cascade_test() {
  use tx <- test_helper.with_db

  let oidc_ctx = make_oidc(tx, None)
  let assert Ok(alice) = user.create(tx, "BotPrincipalAlice")

  let assert Ok(bot) =
    client.create_subordinate_bot(
      tx,
      alice.id,
      "Scoped Bot",
      set.from_list([scope.PostsRead, scope.PostsWrite]),
      "default",
      None,
    )

  // ConfidentialApp cannot use client_credentials (SubordinateBot only)
  let assert Ok(#(conf_app, Some(conf_secret))) =
    client.create_app(
      tx,
      alice.id,
      "Regular Web App",
      True,
      client.Private,
      client.Web,
      ["https://web.example.com/cb"],
      set.from_list([scope.OpenId, scope.PostsRead]),
    )
  assert token.issue_client_credentials(
      oidc_ctx,
      conf_app.client_id,
      conf_secret.secret,
      None,
      None,
      "TestAgent/1.0",
    )
    == Error(token.UnauthorizedClient)

  // Default scopes (None) -> inherits full bot consent scopes + default issuer audience
  let assert Ok(issued_default) =
    token.issue_client_credentials(
      oidc_ctx,
      bot.client.client_id,
      bot.secret.secret,
      None,
      None,
      "BotRunner/1.0",
    )
  assert string.starts_with(issued_default.access_token, "lote_at_")
  assert issued_default.token_type == "Bearer"
  assert issued_default.refresh_token == None
  assert issued_default.scopes
    == set.from_list([scope.PostsRead, scope.PostsWrite])
  assert issued_default.audience == oidc.default_issuer
  assert issued_default.user == alice
  assert string.length(issued_default.sub) == 36

  // Narrowed scopes + explicit RFC 8707 resource audience
  let custom_resource = "https://api.lote.example/mcp"
  let assert Ok(issued_narrow) =
    token.issue_client_credentials(
      oidc_ctx,
      bot.client.client_id,
      bot.secret.secret,
      Some(set.from_list([scope.PostsRead])),
      Some(custom_resource),
      "BotRunner/1.0",
    )
  assert issued_narrow.scopes == set.from_list([scope.PostsRead])
  assert issued_narrow.audience == custom_resource

  // Unconsented scope (posts:delete) and non-bot scope (openid) rejected
  assert token.issue_client_credentials(
      oidc_ctx,
      bot.client.client_id,
      bot.secret.secret,
      Some(set.from_list([scope.PostsDelete])),
      None,
      "BotRunner/1.0",
    )
    == Error(token.InvalidScope)
  assert token.issue_client_credentials(
      oidc_ctx,
      bot.client.client_id,
      bot.secret.secret,
      Some(set.from_list([scope.OpenId])),
      None,
      "BotRunner/1.0",
    )
    == Error(token.InvalidScope)

  // Invalid RFC 8707 resource target (fragment or bad scheme) rejected
  assert token.issue_client_credentials(
      oidc_ctx,
      bot.client.client_id,
      bot.secret.secret,
      None,
      Some("https://api.lote.example/mcp#frag"),
      "BotRunner/1.0",
    )
    == Error(token.InvalidTarget)

  // Authenticate access token checks expected_audience strictly
  let assert Ok(principal) =
    token.authenticate_access_token(
      tx,
      issued_narrow.access_token,
      Some(custom_resource),
    )
  assert principal.user == alice
  assert principal.sub == issued_default.sub
  assert principal.client_id == bot.client.client_id
  assert principal.scopes == set.from_list([scope.PostsRead])
  assert principal.audience == custom_resource

  assert token.authenticate_access_token(
      tx,
      issued_narrow.access_token,
      Some(oidc.default_issuer),
    )
    == Error(Nil)

  // Deleting owner user row cascades and invalidates every issued token, grant, and bot
  let assert Ok(_) =
    pog.query("DELETE FROM users WHERE id = $1")
    |> pog.parameter(pog.int(alice.id))
    |> pog.returning(decode.dynamic)
    |> pog.execute(tx)

  assert token.authenticate_access_token(tx, issued_default.access_token, None)
    == Error(Nil)
  assert token.authenticate_access_token(tx, issued_narrow.access_token, None)
    == Error(Nil)
  assert client.find_by_client_id(tx, bot.client.client_id) == Ok(None)
}

pub fn authorization_code_pkce_s256_and_replay_protection_test() {
  use tx <- test_helper.with_db

  let assert Ok(revocations) = pubsub.start()
  let rev_sub = process.new_subject()
  pubsub.subscribe(revocations, rev_sub)
  let oidc_ctx = make_oidc(tx, Some(revocations))

  let assert Ok(alice) = user.create(tx, "AuthCodeAlice")
  let redirect_uri = "http://127.0.0.1:43210/callback"
  let allowed =
    set.from_list([
      scope.OpenId,
      scope.Profile,
      scope.OfflineAccess,
      scope.PostsRead,
    ])
  let assert Ok(#(app, None)) =
    client.create_app(
      tx,
      alice.id,
      "CLI PKCE Client",
      False,
      client.Public,
      client.Native,
      ["http://127.0.0.1/callback"],
      allowed,
    )

  // Upsert consent merges scopes incrementally
  let assert Ok(#(consent_id, _pub1, merged1)) =
    grant.upsert_consent(
      tx,
      alice.id,
      app.id,
      set.from_list([scope.OpenId, scope.PostsRead]),
    )
  assert merged1 == set.from_list([scope.OpenId, scope.PostsRead])
  let assert Ok(#(consent_id2, _pub2, merged2)) =
    grant.upsert_consent(
      tx,
      alice.id,
      app.id,
      set.from_list([scope.OfflineAccess, scope.Profile]),
    )
  assert consent_id2 == consent_id
  assert merged2 == allowed

  let challenge = token.compute_pkce_s256_challenge(valid_verifier)
  // Verify known RFC 7636 Appendix B test vector!
  assert challenge == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

  let assert Ok(#(raw_code, grant_public_id)) =
    token.issue_authorization_code(
      tx,
      consent_id,
      allowed,
      oidc.default_issuer,
      redirect_uri,
      challenge,
      Some("nonce-xyz-123"),
      "Mozilla/5.0 PKCE Test",
    )
  assert string.starts_with(raw_code, "lote_ac_")

  // Wrong PKCE verifier and wrong redirect_uri fail without consuming the code
  assert token.exchange_authorization_code(
      oidc_ctx,
      app,
      raw_code,
      redirect_uri,
      "wrong_verifier_that_is_at_least_43_characters_long_012345",
      None,
    )
    == Error(token.InvalidGrant)
  assert token.exchange_authorization_code(
      oidc_ctx,
      app,
      raw_code,
      "http://127.0.0.1:9999/callback",
      valid_verifier,
      None,
    )
    == Error(token.InvalidGrant)
  assert token.exchange_authorization_code(
      oidc_ctx,
      app,
      raw_code,
      redirect_uri,
      valid_verifier,
      Some("https://other.resource.example"),
    )
    == Error(token.InvalidTarget)

  // Legitimate exchange succeeds, minting access + refresh tokens and returning nonce
  let assert Ok(issued) =
    token.exchange_authorization_code(
      oidc_ctx,
      app,
      raw_code,
      redirect_uri,
      valid_verifier,
      None,
    )
  assert issued.nonce == Some("nonce-xyz-123")
  assert issued.grant_public_id == grant_public_id
  let assert Some(raw_rt) = issued.refresh_token
  assert string.starts_with(raw_rt, "lote_rt_")
  let assert Ok(_) =
    token.authenticate_access_token(tx, issued.access_token, None)

  // REPLAY ATTACK: exchanging the already-used authorization code revokes the entire Grant!
  assert token.exchange_authorization_code(
      oidc_ctx,
      app,
      raw_code,
      redirect_uri,
      valid_verifier,
      None,
    )
    == Error(token.InvalidGrant)

  let assert Ok(revoked_gid) = process.receive(rev_sub, 500)
  assert revoked_gid == grant_public_id

  // Previously issued access token and refresh token are both immediately dead!
  assert token.authenticate_access_token(tx, issued.access_token, None)
    == Error(Nil)
  assert token.rotate_refresh_token(oidc_ctx, app, raw_rt, None, None)
    == Error(token.InvalidGrant)

  pubsub.stop(revocations)
}

pub fn refresh_token_rotation_reuse_detection_and_grant_isolation_test() {
  use tx <- test_helper.with_db

  let assert Ok(revocations) = pubsub.start()
  let rev_sub = process.new_subject()
  pubsub.subscribe(revocations, rev_sub)
  let oidc_ctx = make_oidc(tx, Some(revocations))

  let assert Ok(alice) = user.create(tx, "RefreshAlice")
  let scopes =
    set.from_list([
      scope.OpenId,
      scope.OfflineAccess,
      scope.PostsRead,
      scope.PostsWrite,
    ])
  let redirect_uri = "https://client.example.com/cb"
  let assert Ok(#(app, Some(_secret))) =
    client.create_app(
      tx,
      alice.id,
      "Refresh App",
      True,
      client.Private,
      client.Web,
      [redirect_uri],
      scopes,
    )
  let assert Ok(#(consent_id, _cpub, _)) =
    grant.upsert_consent(tx, alice.id, app.id, scopes)
  let challenge = token.compute_pkce_s256_challenge(valid_verifier)

  // Create TWO independent concurrent Grants (Device A and Device B) for the same (alice, app)
  let assert Ok(#(code_a, grant_a_pub)) =
    token.issue_authorization_code(
      tx,
      consent_id,
      scopes,
      oidc.default_issuer,
      redirect_uri,
      challenge,
      None,
      "Device A",
    )
  let assert Ok(tokens_a1) =
    token.exchange_authorization_code(
      oidc_ctx,
      app,
      code_a,
      redirect_uri,
      valid_verifier,
      None,
    )
  let assert Some(rt_a1) = tokens_a1.refresh_token

  let assert Ok(#(code_b, grant_b_pub)) =
    token.issue_authorization_code(
      tx,
      consent_id,
      scopes,
      oidc.default_issuer,
      redirect_uri,
      challenge,
      None,
      "Device B",
    )
  let assert Ok(tokens_b1) =
    token.exchange_authorization_code(
      oidc_ctx,
      app,
      code_b,
      redirect_uri,
      valid_verifier,
      None,
    )
  let assert Some(rt_b1) = tokens_b1.refresh_token
  assert grant_a_pub != grant_b_pub

  // Rotate rt_a1 with narrowed scopes -> produces at_a2 + rt_a2
  let narrowed = set.from_list([scope.PostsRead])
  let assert Ok(tokens_a2) =
    token.rotate_refresh_token(oidc_ctx, app, rt_a1, Some(narrowed), None)
  let assert Some(rt_a2) = tokens_a2.refresh_token
  assert rt_a2 != rt_a1
  assert tokens_a2.scopes == narrowed
  assert tokens_a2.grant_public_id == grant_a_pub

  // Scope escalation beyond grant scopes is rejected without burning rt_a2
  assert token.rotate_refresh_token(
      oidc_ctx,
      app,
      rt_a2,
      Some(set.from_list([scope.PostsDelete])),
      None,
    )
    == Error(token.InvalidScope)

  // REUSE DETECTION: replaying already-rotated rt_a1 kills Grant A (at_a2 + rt_a2),
  // publishes Grant A revocation, and leaves Grant B completely intact!
  assert token.rotate_refresh_token(oidc_ctx, app, rt_a1, None, None)
    == Error(token.InvalidGrant)

  let assert Ok(revoked_gid) = process.receive(rev_sub, 500)
  assert revoked_gid == grant_a_pub

  assert token.authenticate_access_token(tx, tokens_a2.access_token, None)
    == Error(Nil)
  assert token.rotate_refresh_token(oidc_ctx, app, rt_a2, None, None)
    == Error(token.InvalidGrant)

  // Device B (same user & client!) is completely unaffected!
  let assert Ok(_) =
    token.authenticate_access_token(tx, tokens_b1.access_token, None)
  let assert Ok(tokens_b2) =
    token.rotate_refresh_token(oidc_ctx, app, rt_b1, None, None)
  let assert Ok(_) =
    token.authenticate_access_token(tx, tokens_b2.access_token, None)

  // User grant & consent listing and revocation work as expected
  let assert Ok(active_grants) = grant.list_active_grants_for_user(tx, alice.id)
  assert list.length(active_grants) == 1
  let assert [only_grant] = active_grants
  assert only_grant.public_id == grant_b_pub

  let assert Ok(Some(revoked_consent_grants)) =
    grant.revoke_consent_by_public_id(
      tx,
      only_grant.consent_public_id,
      alice.id,
    )
  assert revoked_consent_grants == [grant_b_pub]
  assert token.authenticate_access_token(tx, tokens_b2.access_token, None)
    == Error(Nil)

  pubsub.stop(revocations)
}

pub fn token_revocation_introspection_and_cleanup_actor_test() {
  use tx <- test_helper.with_db

  let assert Ok(revocations) = pubsub.start()
  let rev_sub = process.new_subject()
  pubsub.subscribe(revocations, rev_sub)
  let oidc_ctx = make_oidc(tx, Some(revocations))

  let assert Ok(alice) = user.create(tx, "IntrospectAlice")
  let assert Ok(bot1) =
    client.create_subordinate_bot(
      tx,
      alice.id,
      "Bot One",
      set.from_list([scope.PostsRead]),
      "default",
      None,
    )
  let assert Ok(bot2) =
    client.create_subordinate_bot(
      tx,
      alice.id,
      "Bot Two",
      set.from_list([scope.PostsRead]),
      "default",
      None,
    )

  let assert Ok(t1) =
    token.issue_client_credentials(
      oidc_ctx,
      bot1.client.client_id,
      bot1.secret.secret,
      None,
      None,
      "Bot1",
    )

  // Introspection by owning client returns Active with exp > iat
  let assert Ok(token.Active(principal:, exp:, iat:)) =
    token.introspect_raw_token(tx, bot1.client, t1.access_token)
  assert principal.client_id == bot1.client.client_id
  assert exp > iat

  // Introspection by a DIFFERENT client returns Inactive (cross-client isolation)
  assert token.introspect_raw_token(tx, bot2.client, t1.access_token)
    == Ok(token.Inactive)
  assert token.introspect_raw_token(tx, bot1.client, "lote_at_unknown")
    == Ok(token.Inactive)

  // Revoking via wrong client is a safe no-op (RFC 7009) and does NOT revoke t1
  assert token.revoke_by_raw_token(oidc_ctx, bot2.client, t1.access_token)
    == Ok(Nil)
  let assert Ok(token.Active(..)) =
    token.introspect_raw_token(tx, bot1.client, t1.access_token)

  // Revoking via owning client deletes access token + grant (since no refresh token) and publishes
  assert token.revoke_by_raw_token(oidc_ctx, bot1.client, t1.access_token)
    == Ok(Nil)
  let assert Ok(rev_id1) = process.receive(rev_sub, 500)
  assert rev_id1 == t1.grant_public_id
  assert token.introspect_raw_token(tx, bot1.client, t1.access_token)
    == Ok(token.Inactive)

  // Create 1 active grant and 3 expired grants + tokens to verify cleanup batching & OTP actor
  let assert Ok(active_tok) =
    token.issue_client_credentials(
      oidc_ctx,
      bot1.client.client_id,
      bot1.secret.secret,
      None,
      None,
      "ActiveBot",
    )

  let expired_grant_ids =
    list.map([1, 2, 3], fn(_) {
      let assert Ok(tok) =
        token.issue_client_credentials(
          oidc_ctx,
          bot1.client.client_id,
          bot1.secret.secret,
          None,
          None,
          "ExpiringBot",
        )
      let assert Ok(_) =
        pog.query(
          "UPDATE oidc_grants SET expires_at = NOW() - INTERVAL '5 minutes' WHERE public_id = $1::uuid",
        )
        |> pog.parameter(pog.text(tok.grant_public_id))
        |> pog.returning(decode.dynamic)
        |> pog.execute(tx)
      let assert Ok(_) =
        pog.query(
          "UPDATE oidc_access_tokens SET expires_at = NOW() - INTERVAL '5 minutes'
           WHERE grant_id = (SELECT id FROM oidc_grants WHERE public_id = $1::uuid)",
        )
        |> pog.parameter(pog.text(tok.grant_public_id))
        |> pog.returning(decode.dynamic)
        |> pog.execute(tx)
      // Expired tokens must introspect as Inactive even before cleanup runs
      assert token.introspect_raw_token(tx, bot1.client, tok.access_token)
        == Ok(token.Inactive)
      tok.grant_public_id
    })

  // Start periodic cleanup actor with batch_limit=2 and interval=30ms
  let assert Ok(started) = cleanup.start(tx, Some(revocations), 30, 2)

  let assert Ok(g1) = process.receive(rev_sub, 500)
  let assert Ok(g2) = process.receive(rev_sub, 500)
  let assert Ok(g3) = process.receive(rev_sub, 500)
  let notified = [g1, g2, g3]
  list.each(expired_grant_ids, fn(id) {
    assert list.contains(notified, id)
  })

  // Stop actor cleanly before transaction rollback
  let mon = process.monitor(started.pid)
  cleanup.stop(started.data)
  let down_selector =
    process.new_selector()
    |> process.select_specific_monitor(mon, fn(down) { down })
  let assert Ok(_) = process.selector_receive(down_selector, 500)

  // Nothing expired remains, and active_tok is still valid
  assert cleanup.run_once(tx, None, 10) == Ok(0)
  let assert Ok(_) =
    token.authenticate_access_token(tx, active_tok.access_token, None)

  pubsub.stop(revocations)
}

pub fn offline_token_introspection_revocation_and_client_delete_grants_test() {
  use tx <- test_helper.with_db

  let assert Ok(revocations) = pubsub.start()
  let rev_sub = process.new_subject()
  pubsub.subscribe(revocations, rev_sub)
  let oidc_ctx = make_oidc(tx, Some(revocations))

  let assert Ok(alice) = user.create(tx, "OfflineRevokeAlice")
  let assert Ok(bob) = user.create(tx, "OfflineRevokeBob")

  let scopes =
    set.from_list([scope.OpenId, scope.OfflineAccess, scope.PostsRead])
  let redirect_uri = "https://offline.example.com/cb"
  let assert Ok(#(app, Some(_))) =
    client.create_app(
      tx,
      alice.id,
      "Offline App",
      True,
      client.Private,
      client.Web,
      [redirect_uri],
      scopes,
    )
  let assert Ok(#(consent_id, _, _)) =
    grant.upsert_consent(tx, alice.id, app.id, scopes)
  let challenge = token.compute_pkce_s256_challenge(valid_verifier)

  let assert Ok(#(code1, grant1_pub)) =
    token.issue_authorization_code(
      tx,
      consent_id,
      scopes,
      oidc.default_issuer,
      redirect_uri,
      challenge,
      None,
      "UA1",
    )
  let assert Ok(issued1) =
    token.exchange_authorization_code(
      oidc_ctx,
      app,
      code1,
      redirect_uri,
      valid_verifier,
      None,
    )
  let assert Some(rt1) = issued1.refresh_token

  // Refresh token introspects as Active while unused
  let assert Ok(token.Active(principal: rt_principal, ..)) =
    token.introspect_raw_token(tx, app, rt1)
  assert rt_principal.grant_public_id == grant1_pub

  // Revoking access_token on an offline_access grant deletes the access_token
  // while keeping the refresh_token active on the grant
  assert token.revoke_by_raw_token(oidc_ctx, app, issued1.access_token)
    == Ok(Nil)
  assert token.introspect_raw_token(tx, app, issued1.access_token)
    == Ok(token.Inactive)
  let assert Ok(token.Active(..)) = token.introspect_raw_token(tx, app, rt1)

  // Rotating rt1 marks rt1 used -> rt1 introspects as Inactive, rt2 introspects as Active
  let assert Ok(issued2) =
    token.rotate_refresh_token(oidc_ctx, app, rt1, None, None)
  let assert Some(rt2) = issued2.refresh_token
  assert token.introspect_raw_token(tx, app, rt1) == Ok(token.Inactive)
  let assert Ok(token.Active(..)) = token.introspect_raw_token(tx, app, rt2)

  // Revoking refresh_token rt2 deletes the entire grant and publishes revocation
  assert token.revoke_by_raw_token(oidc_ctx, app, rt2) == Ok(Nil)
  let assert Ok(rev_gid) = process.receive(rev_sub, 500)
  assert rev_gid == grant1_pub
  assert token.introspect_raw_token(tx, app, rt2) == Ok(token.Inactive)
  assert token.introspect_raw_token(tx, app, issued2.access_token)
    == Ok(token.Inactive)

  // Test grant.create_grant, grant.revoke_grant_by_public_id, and client.delete_for_owner
  let assert Ok(#(_gid_a, gpub_a, _)) =
    grant.create_grant(
      tx,
      consent_id,
      scopes,
      oidc.default_issuer,
      "DirectGrantA",
      3600,
    )
  let assert Ok(#(_gid_b, gpub_b, _)) =
    grant.create_grant(
      tx,
      consent_id,
      scopes,
      oidc.default_issuer,
      "DirectGrantB",
      3600,
    )

  // Bob cannot revoke Alice's grant
  assert grant.revoke_grant_by_public_id(tx, gpub_a, bob.id) == Ok(None)
  assert grant.revoke_grant_by_public_id(tx, "invalid-uuid", alice.id)
    == Ok(None)
  // Alice revokes grant A
  assert grant.revoke_grant_by_public_id(tx, gpub_a, alice.id)
    == Ok(Some(gpub_a))

  // Deleting client returns remaining active grant B's public_id
  assert client.delete_for_owner(tx, alice.id, app.client_id)
    == Ok(Some([gpub_b]))
  assert grant.list_active_grants_for_user(tx, alice.id) == Ok([])

  pubsub.stop(revocations)
}

pub fn cleanup_preserves_used_auth_code_for_replay_detection_and_cleans_expired_refresh_tokens_test() {
  use tx <- test_helper.with_db

  let assert Ok(revocations) = pubsub.start()
  let rev_sub = process.new_subject()
  pubsub.subscribe(revocations, rev_sub)
  let oidc_ctx = make_oidc(tx, Some(revocations))

  let assert Ok(alice) = user.create(tx, "ReplayCleanupAlice")
  let scopes =
    set.from_list([scope.OpenId, scope.OfflineAccess, scope.PostsRead])
  let redirect_uri = "https://replay-cleanup.example.com/cb"
  let assert Ok(#(app, None)) =
    client.create_app(
      tx,
      alice.id,
      "Replay Cleanup App",
      False,
      client.Private,
      client.Web,
      [redirect_uri],
      scopes,
    )
  let assert Ok(#(consent_id, _, _)) =
    grant.upsert_consent(tx, alice.id, app.id, scopes)

  // 1. Exchange auth code -> mark auth code expired -> run cleanup -> replay must still revoke grant
  let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  let challenge = token.compute_pkce_s256_challenge(verifier)
  let assert Ok(#(code1, _)) =
    token.issue_authorization_code(
      tx,
      consent_id,
      scopes,
      oidc.default_issuer,
      redirect_uri,
      challenge,
      None,
      "TestAgent/1.0",
    )
  let assert Ok(issued1) =
    token.exchange_authorization_code(
      oidc_ctx,
      app,
      code1,
      redirect_uri,
      verifier,
      None,
    )

  // Backdate used auth code expires_at while parent grant remains active
  let assert Ok(_) =
    pog.query(
      "UPDATE oidc_auth_codes SET expires_at = NOW() - INTERVAL '1 hour'",
    )
    |> pog.returning(decode.dynamic)
    |> pog.execute(tx)

  assert cleanup.run_once(tx, Some(revocations), 50) == Ok(0)

  // Replaying the used auth code still triggers compromised-grant revocation!
  assert token.exchange_authorization_code(
      oidc_ctx,
      app,
      code1,
      redirect_uri,
      verifier,
      None,
    )
    == Error(token.InvalidGrant)
  assert process.receive(rev_sub, 200) == Ok(issued1.grant_public_id)
  assert token.authenticate_access_token(tx, issued1.access_token, None)
    == Error(Nil)

  // 2. Rotated refresh tokens are deleted once their own 30-day expires_at elapses
  // so long-lived sliding-window grants do not accumulate unbounded RT rows.
  let assert Ok(#(code2, _)) =
    token.issue_authorization_code(
      tx,
      consent_id,
      scopes,
      oidc.default_issuer,
      redirect_uri,
      challenge,
      None,
      "TestAgent/1.0",
    )
  let assert Ok(issued2) =
    token.exchange_authorization_code(
      oidc_ctx,
      app,
      code2,
      redirect_uri,
      verifier,
      None,
    )
  let assert Some(rt1) = issued2.refresh_token
  let assert Ok(_rotated) =
    token.rotate_refresh_token(oidc_ctx, app, rt1, None, None)

  let assert Ok(_) =
    pog.query(
      "UPDATE oidc_refresh_tokens SET expires_at = NOW() - INTERVAL '1 hour' WHERE used_at IS NOT NULL",
    )
    |> pog.returning(decode.dynamic)
    |> pog.execute(tx)

  assert cleanup.run_once(tx, Some(revocations), 50) == Ok(1)

  pubsub.stop(revocations)
}

fn make_oidc(
  db: pog.Connection,
  grant_revocations: Option(pubsub.PubSub(String)),
) -> oidc.Oidc {
  oidc.Oidc(
    db:,
    issuer: oidc.default_issuer,
    keyring: jwt.default_keyring(),
    cimd_fetcher: cimd.default_fetcher(),
    grant_revocations:,
    rate_limiter: rate_limit.disabled(),
  )
}
