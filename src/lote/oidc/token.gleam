import gleam/bit_array
import gleam/crypto
import gleam/dynamic/decode
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/set.{type Set}
import gleam/string
import gleam/time/calendar
import gleam/time/timestamp.{type Timestamp}
import gleam/uri
import lote/auth/user.{type AuthUser, AuthUser}
import lote/db/uuid
import lote/oidc.{type Oidc, type Principal, Principal}
import lote/oidc/client.{type Client}
import lote/oidc/scope.{type Scope}
import pog

pub const access_token_ttl_seconds = 3600

pub const refresh_token_ttl_seconds = 2_592_000

pub const auth_code_ttl_seconds = 90

const max_user_agent_length = 512

pub type IssuedTokens {
  IssuedTokens(
    access_token: String,
    token_type: String,
    expires_in: Int,
    refresh_token: Option(String),
    scopes: Set(Scope),
    audience: String,
    sub: String,
    user: AuthUser,
    nonce: Option(String),
    grant_public_id: String,
  )
}

pub type TokenError {
  InvalidRequest(String)
  InvalidClient
  InvalidGrant
  UnauthorizedClient
  UnsupportedGrantType
  InvalidScope
  InvalidTarget
  InternalError
}

pub type Introspection {
  Active(principal: Principal, exp: Int, iat: Int)
  Inactive
}

pub fn normalize_audience(
  requested_resource: Option(String),
  default_issuer: String,
) -> Result(String, Nil) {
  case requested_resource {
    None | Some("") -> Ok(default_issuer)
    Some(raw) ->
      case string.trim(raw) == raw && !contains_whitespace(raw) {
        False -> Error(Nil)
        True -> {
          use parsed <- result.try(uri.parse(raw))
          case
            parsed.scheme,
            parsed.userinfo,
            parsed.fragment,
            valid_port(parsed.port),
            parsed.host
          {
            Some("http"), None, None, True, Some(host)
            | Some("https"), None, None, True, Some(host)
            ->
              case string.trim(host) != "" {
                True -> Ok(raw)
                False -> Error(Nil)
              }
            _, _, _, _, _ -> Error(Nil)
          }
        }
      }
  }
}

pub fn is_valid_token_format(prefix: String, raw: String) -> Bool {
  let expected_bytes = bit_array.byte_size(<<prefix:utf8>>) + 43
  case
    bit_array.byte_size(<<raw:utf8>>) == expected_bytes
    && string.starts_with(raw, prefix)
  {
    False -> False
    True -> {
      let rand_part = string.drop_start(raw, up_to: string.length(prefix))
      is_base64url_43(rand_part)
    }
  }
}

pub fn compute_pkce_s256_challenge(code_verifier: String) -> String {
  crypto.hash(crypto.Sha256, <<code_verifier:utf8>>)
  |> bit_array.base64_url_encode(False)
}

pub fn issue_client_credentials(
  oidc_ctx: Oidc,
  client_id: String,
  client_secret: String,
  requested_scopes: Option(Set(Scope)),
  requested_resource: Option(String),
  user_agent: String,
) -> Result(IssuedTokens, TokenError) {
  use authed_client <- result.try(
    case client.authenticate_secret(oidc_ctx.db, client_id, client_secret) {
      Ok(c) -> Ok(c)
      Error(client.InvalidClientCredentials) -> Error(InvalidClient)
      Error(_) -> Error(InternalError)
    },
  )

  issue_client_credentials_for_client(
    oidc_ctx,
    authed_client,
    requested_scopes,
    requested_resource,
    user_agent,
  )
}

pub fn issue_client_credentials_for_client(
  oidc_ctx: Oidc,
  authed_client: Client,
  requested_scopes: Option(Set(Scope)),
  requested_resource: Option(String),
  user_agent: String,
) -> Result(IssuedTokens, TokenError) {
  use owner_id <- result.try(
    case authed_client.kind, authed_client.owner_user_id {
      client.SubordinateBot, Some(uid) -> Ok(uid)
      _, _ -> Error(UnauthorizedClient)
    },
  )

  let consent_sql =
    "SELECT con.id, con.scopes, u.id, u.name, u.public_id
    FROM oidc_consents con
    INNER JOIN users u ON u.id = con.user_id
    WHERE con.user_id = $1 AND con.client_ref_id = $2
    LIMIT 1"

  let consent_decoder = {
    use consent_id <- decode.field(0, decode.int)
    use consent_scopes <- decode.field(1, scopes_decoder())
    use uid <- decode.field(2, decode.int)
    use uname <- decode.field(3, decode.string)
    use user_public_id <- decode.field(4, uuid.decoder())
    decode.success(#(
      consent_id,
      consent_scopes,
      AuthUser(id: uid, name: uname),
      user_public_id,
    ))
  }

  use #(consent_id, consent_scopes, auth_user, sub) <- result.try(
    case
      pog.query(consent_sql)
      |> pog.parameter(pog.int(owner_id))
      |> pog.parameter(pog.int(authed_client.id))
      |> pog.returning(consent_decoder)
      |> pog.execute(oidc_ctx.db)
    {
      Ok(pog.Returned(rows: [row, ..], ..)) -> Ok(row)
      Ok(pog.Returned(rows: [], ..)) -> Error(InvalidGrant)
      Error(_) -> Error(InternalError)
    },
  )

  use effective_scopes <- result.try(resolve_bot_scopes(
    requested_scopes,
    consent_scopes,
  ))

  use audience <- result.try(
    normalize_audience(requested_resource, oidc_ctx.issuer)
    |> result.replace_error(InvalidTarget),
  )

  let #(raw_at, at_hash) = generate_token("lote_at_")
  let scope_strings = scope.to_sorted_strings(effective_scopes)
  let clean_ua = sanitize_user_agent(user_agent)

  let insert_sql =
    "WITH new_grant AS (
      INSERT INTO oidc_grants (
        consent_id,
        scopes,
        audience,
        user_agent,
        expires_at
      )
      VALUES ($1, $2, $3, $4, NOW() + ($5::bigint * INTERVAL '1 second'))
      RETURNING id, public_id
    ),
    new_token AS (
      INSERT INTO oidc_access_tokens (
        token_hash,
        grant_id,
        scopes,
        audience,
        expires_at
      )
      SELECT $6, id, $2, $3, NOW() + ($5::bigint * INTERVAL '1 second')
      FROM new_grant
    )
    SELECT public_id FROM new_grant"

  let grant_id_decoder = {
    use grant_public_id <- decode.field(0, uuid.decoder())
    decode.success(grant_public_id)
  }

  let insert_res =
    pog.query(insert_sql)
    |> pog.parameter(pog.int(consent_id))
    |> pog.parameter(pog.array(pog.text, scope_strings))
    |> pog.parameter(pog.text(audience))
    |> pog.parameter(pog.text(clean_ua))
    |> pog.parameter(pog.int(access_token_ttl_seconds))
    |> pog.parameter(pog.bytea(at_hash))
    |> pog.returning(grant_id_decoder)
    |> pog.execute(oidc_ctx.db)

  case insert_res {
    Ok(pog.Returned(rows: [grant_public_id, ..], ..)) ->
      Ok(IssuedTokens(
        access_token: raw_at,
        token_type: "Bearer",
        expires_in: access_token_ttl_seconds,
        refresh_token: None,
        scopes: effective_scopes,
        audience:,
        sub:,
        user: auth_user,
        nonce: None,
        grant_public_id:,
      ))
    _ -> Error(InternalError)
  }
}

pub fn issue_authorization_code(
  db: pog.Connection,
  consent_id: Int,
  scopes: Set(Scope),
  audience: String,
  redirect_uri: String,
  code_challenge: String,
  nonce: Option(String),
  user_agent: String,
) -> Result(#(String, String), TokenError) {
  use _ <- result.try(case is_valid_code_challenge(code_challenge) {
    True -> Ok(Nil)
    False -> Error(InvalidRequest("Invalid PKCE code_challenge"))
  })
  use _ <- result.try(case set.is_empty(scopes) {
    True -> Error(InvalidScope)
    False -> Ok(Nil)
  })
  use _ <- result.try(case redirect_uri != "" && audience != "" {
    True -> Ok(Nil)
    False -> Error(InvalidRequest("Missing redirect_uri or audience"))
  })

  let grant_ttl = case set.contains(scopes, scope.OfflineAccess) {
    True -> refresh_token_ttl_seconds
    False -> access_token_ttl_seconds
  }
  let #(raw_code, code_hash) = generate_token("lote_ac_")
  let scope_strings = scope.to_sorted_strings(scopes)
  let clean_ua = sanitize_user_agent(user_agent)

  let sql =
    "WITH new_grant AS (
      INSERT INTO oidc_grants (
        consent_id,
        scopes,
        audience,
        user_agent,
        expires_at
      )
      VALUES ($1, $2, $3, $4, NOW() + ($5::bigint * INTERVAL '1 second'))
      RETURNING id, public_id
    ),
    new_code AS (
      INSERT INTO oidc_auth_codes (
        code_hash,
        grant_id,
        redirect_uri,
        code_challenge,
        nonce,
        expires_at
      )
      SELECT
        $6,
        id,
        $7,
        $8,
        $9,
        NOW() + ($10::bigint * INTERVAL '1 second')
      FROM new_grant
    )
    SELECT public_id FROM new_grant"

  let decoder = {
    use grant_public_id <- decode.field(0, uuid.decoder())
    decode.success(grant_public_id)
  }

  let res =
    pog.query(sql)
    |> pog.parameter(pog.int(consent_id))
    |> pog.parameter(pog.array(pog.text, scope_strings))
    |> pog.parameter(pog.text(audience))
    |> pog.parameter(pog.text(clean_ua))
    |> pog.parameter(pog.int(grant_ttl))
    |> pog.parameter(pog.bytea(code_hash))
    |> pog.parameter(pog.text(redirect_uri))
    |> pog.parameter(pog.text(code_challenge))
    |> pog.parameter(pog.nullable(pog.text, nonce))
    |> pog.parameter(pog.int(auth_code_ttl_seconds))
    |> pog.returning(decoder)
    |> pog.execute(db)

  case res {
    Ok(pog.Returned(rows: [grant_public_id, ..], ..)) ->
      Ok(#(raw_code, grant_public_id))
    _ -> Error(InternalError)
  }
}

pub fn exchange_authorization_code(
  oidc_ctx: Oidc,
  client: Client,
  raw_code: String,
  redirect_uri: String,
  code_verifier: String,
  requested_resource: Option(String),
) -> Result(IssuedTokens, TokenError) {
  use _ <- result.try(case is_valid_token_format("lote_ac_", raw_code) {
    True -> Ok(Nil)
    False -> Error(InvalidGrant)
  })
  let code_hash = sha256(raw_code)

  let lookup_sql =
    "SELECT
      g.id,
      g.public_id,
      g.scopes,
      g.audience,
      (g.expires_at > NOW()) AS grant_active,
      con.client_ref_id,
      u.id,
      u.name,
      u.public_id,
      ac.redirect_uri,
      ac.code_challenge,
      ac.nonce,
      (ac.used_at IS NOT NULL) AS is_used,
      (ac.expires_at > NOW()) AS code_active
    FROM oidc_auth_codes ac
    INNER JOIN oidc_grants g ON g.id = ac.grant_id
    INNER JOIN oidc_consents con ON con.id = g.consent_id
    INNER JOIN users u ON u.id = con.user_id
    WHERE ac.code_hash = $1
    LIMIT 1"

  let lookup_decoder = {
    use grant_id <- decode.field(0, decode.int)
    use grant_public_id <- decode.field(1, uuid.decoder())
    use grant_scopes <- decode.field(2, scopes_decoder())
    use grant_audience <- decode.field(3, decode.string)
    use grant_active <- decode.field(4, decode.bool)
    use client_ref_id <- decode.field(5, decode.int)
    use uid <- decode.field(6, decode.int)
    use uname <- decode.field(7, decode.string)
    use sub <- decode.field(8, uuid.decoder())
    use stored_redirect_uri <- decode.field(9, decode.string)
    use stored_challenge <- decode.field(10, decode.string)
    use nonce <- decode.field(11, decode.optional(decode.string))
    use is_used <- decode.field(12, decode.bool)
    use code_active <- decode.field(13, decode.bool)
    decode.success(#(
      grant_id,
      grant_public_id,
      grant_scopes,
      grant_audience,
      grant_active,
      client_ref_id,
      AuthUser(id: uid, name: uname),
      sub,
      stored_redirect_uri,
      stored_challenge,
      nonce,
      is_used,
      code_active,
    ))
  }

  use row <- result.try(
    case
      pog.query(lookup_sql)
      |> pog.parameter(pog.bytea(code_hash))
      |> pog.returning(lookup_decoder)
      |> pog.execute(oidc_ctx.db)
    {
      Ok(pog.Returned(rows: [r, ..], ..)) -> Ok(r)
      Ok(pog.Returned(rows: [], ..)) -> Error(InvalidGrant)
      Error(_) -> Error(InternalError)
    },
  )

  let #(
    grant_id,
    grant_public_id,
    grant_scopes,
    grant_audience,
    grant_active,
    client_ref_id,
    auth_user,
    sub,
    stored_redirect_uri,
    stored_challenge,
    nonce,
    is_used,
    code_active,
  ) = row

  case client_ref_id == client.id {
    False -> Error(InvalidGrant)
    True ->
      case is_used {
        True -> {
          revoke_compromised_grant(oidc_ctx, grant_id, grant_public_id)
          Error(InvalidGrant)
        }
        False -> {
          use _ <- result.try(
            case
              code_active
              && grant_active
              && redirect_uri == stored_redirect_uri
              && verify_pkce_s256(code_verifier, stored_challenge)
            {
              True -> Ok(Nil)
              False -> Error(InvalidGrant)
            },
          )

          use audience <- result.try(verify_bound_audience(
            requested_resource,
            grant_audience,
            oidc_ctx.issuer,
          ))

          let #(raw_at, at_hash) = generate_token("lote_at_")
          let scope_strings = scope.to_sorted_strings(grant_scopes)
          let issue_refresh = set.contains(grant_scopes, scope.OfflineAccess)

          case issue_refresh {
            True -> {
              let #(raw_rt, rt_hash) = generate_token("lote_rt_")
              let exchange_sql =
                "WITH mark_used AS (
                  UPDATE oidc_auth_codes
                  SET used_at = NOW()
                  WHERE code_hash = $1
                    AND used_at IS NULL
                    AND expires_at > NOW()
                  RETURNING grant_id
                ),
                touch_grant AS (
                  UPDATE oidc_grants
                  SET last_used_at = NOW()
                  FROM mark_used
                  WHERE oidc_grants.id = mark_used.grant_id
                    AND oidc_grants.expires_at > NOW()
                  RETURNING oidc_grants.id
                ),
                new_at AS (
                  INSERT INTO oidc_access_tokens (
                    token_hash,
                    grant_id,
                    scopes,
                    audience,
                    expires_at
                  )
                  SELECT
                    $2,
                    id,
                    $3,
                    $4,
                    NOW() + ($5::bigint * INTERVAL '1 second')
                  FROM touch_grant
                ),
                new_rt AS (
                  INSERT INTO oidc_refresh_tokens (
                    token_hash,
                    grant_id,
                    expires_at
                  )
                  SELECT
                    $6,
                    id,
                    NOW() + ($7::bigint * INTERVAL '1 second')
                  FROM touch_grant
                )
                SELECT id FROM touch_grant"

              let res =
                pog.query(exchange_sql)
                |> pog.parameter(pog.bytea(code_hash))
                |> pog.parameter(pog.bytea(at_hash))
                |> pog.parameter(pog.array(pog.text, scope_strings))
                |> pog.parameter(pog.text(audience))
                |> pog.parameter(pog.int(access_token_ttl_seconds))
                |> pog.parameter(pog.bytea(rt_hash))
                |> pog.parameter(pog.int(refresh_token_ttl_seconds))
                |> pog.returning(decode.dynamic)
                |> pog.execute(oidc_ctx.db)

              case res {
                Ok(pog.Returned(rows: [_, ..], ..)) ->
                  Ok(IssuedTokens(
                    access_token: raw_at,
                    token_type: "Bearer",
                    expires_in: access_token_ttl_seconds,
                    refresh_token: Some(raw_rt),
                    scopes: grant_scopes,
                    audience:,
                    sub:,
                    user: auth_user,
                    nonce:,
                    grant_public_id:,
                  ))
                Ok(pog.Returned(rows: [], ..)) -> {
                  revoke_compromised_grant(oidc_ctx, grant_id, grant_public_id)
                  Error(InvalidGrant)
                }
                Error(_) -> Error(InternalError)
              }
            }

            False -> {
              let exchange_sql =
                "WITH mark_used AS (
                  UPDATE oidc_auth_codes
                  SET used_at = NOW()
                  WHERE code_hash = $1
                    AND used_at IS NULL
                    AND expires_at > NOW()
                  RETURNING grant_id
                ),
                touch_grant AS (
                  UPDATE oidc_grants
                  SET last_used_at = NOW()
                  FROM mark_used
                  WHERE oidc_grants.id = mark_used.grant_id
                    AND oidc_grants.expires_at > NOW()
                  RETURNING oidc_grants.id
                ),
                new_at AS (
                  INSERT INTO oidc_access_tokens (
                    token_hash,
                    grant_id,
                    scopes,
                    audience,
                    expires_at
                  )
                  SELECT
                    $2,
                    id,
                    $3,
                    $4,
                    NOW() + ($5::bigint * INTERVAL '1 second')
                  FROM touch_grant
                )
                SELECT id FROM touch_grant"

              let res =
                pog.query(exchange_sql)
                |> pog.parameter(pog.bytea(code_hash))
                |> pog.parameter(pog.bytea(at_hash))
                |> pog.parameter(pog.array(pog.text, scope_strings))
                |> pog.parameter(pog.text(audience))
                |> pog.parameter(pog.int(access_token_ttl_seconds))
                |> pog.returning(decode.dynamic)
                |> pog.execute(oidc_ctx.db)

              case res {
                Ok(pog.Returned(rows: [_, ..], ..)) ->
                  Ok(IssuedTokens(
                    access_token: raw_at,
                    token_type: "Bearer",
                    expires_in: access_token_ttl_seconds,
                    refresh_token: None,
                    scopes: grant_scopes,
                    audience:,
                    sub:,
                    user: auth_user,
                    nonce:,
                    grant_public_id:,
                  ))
                Ok(pog.Returned(rows: [], ..)) -> {
                  revoke_compromised_grant(oidc_ctx, grant_id, grant_public_id)
                  Error(InvalidGrant)
                }
                Error(_) -> Error(InternalError)
              }
            }
          }
        }
      }
  }
}

pub fn rotate_refresh_token(
  oidc_ctx: Oidc,
  client: Client,
  raw_refresh_token: String,
  requested_scopes: Option(Set(Scope)),
  requested_resource: Option(String),
) -> Result(IssuedTokens, TokenError) {
  use _ <- result.try(
    case is_valid_token_format("lote_rt_", raw_refresh_token) {
      True -> Ok(Nil)
      False -> Error(InvalidGrant)
    },
  )
  let rt_hash = sha256(raw_refresh_token)

  let lookup_sql =
    "SELECT
      g.id,
      g.public_id,
      g.scopes,
      g.audience,
      (g.expires_at > NOW()) AS grant_active,
      con.client_ref_id,
      u.id,
      u.name,
      u.public_id,
      (rt.used_at IS NOT NULL) AS is_used,
      (rt.expires_at > NOW()) AS rt_active
    FROM oidc_refresh_tokens rt
    INNER JOIN oidc_grants g ON g.id = rt.grant_id
    INNER JOIN oidc_consents con ON con.id = g.consent_id
    INNER JOIN users u ON u.id = con.user_id
    WHERE rt.token_hash = $1
    LIMIT 1"

  let lookup_decoder = {
    use grant_id <- decode.field(0, decode.int)
    use grant_public_id <- decode.field(1, uuid.decoder())
    use grant_scopes <- decode.field(2, scopes_decoder())
    use grant_audience <- decode.field(3, decode.string)
    use grant_active <- decode.field(4, decode.bool)
    use client_ref_id <- decode.field(5, decode.int)
    use uid <- decode.field(6, decode.int)
    use uname <- decode.field(7, decode.string)
    use sub <- decode.field(8, uuid.decoder())
    use is_used <- decode.field(9, decode.bool)
    use rt_active <- decode.field(10, decode.bool)
    decode.success(#(
      grant_id,
      grant_public_id,
      grant_scopes,
      grant_audience,
      grant_active,
      client_ref_id,
      AuthUser(id: uid, name: uname),
      sub,
      is_used,
      rt_active,
    ))
  }

  use row <- result.try(
    case
      pog.query(lookup_sql)
      |> pog.parameter(pog.bytea(rt_hash))
      |> pog.returning(lookup_decoder)
      |> pog.execute(oidc_ctx.db)
    {
      Ok(pog.Returned(rows: [r, ..], ..)) -> Ok(r)
      Ok(pog.Returned(rows: [], ..)) -> Error(InvalidGrant)
      Error(_) -> Error(InternalError)
    },
  )

  let #(
    grant_id,
    grant_public_id,
    grant_scopes,
    grant_audience,
    grant_active,
    client_ref_id,
    auth_user,
    sub,
    is_used,
    rt_active,
  ) = row

  case client_ref_id == client.id {
    False -> Error(InvalidGrant)
    True ->
      case is_used {
        True -> {
          revoke_compromised_grant(oidc_ctx, grant_id, grant_public_id)
          Error(InvalidGrant)
        }
        False -> {
          use _ <- result.try(case rt_active && grant_active {
            True -> Ok(Nil)
            False -> Error(InvalidGrant)
          })

          use effective_scopes <- result.try(resolve_refresh_scopes(
            requested_scopes,
            grant_scopes,
          ))

          use audience <- result.try(verify_bound_audience(
            requested_resource,
            grant_audience,
            oidc_ctx.issuer,
          ))

          let #(new_raw_at, new_at_hash) = generate_token("lote_at_")
          let #(new_raw_rt, new_rt_hash) = generate_token("lote_rt_")
          let scope_strings = scope.to_sorted_strings(effective_scopes)

          let rotate_sql =
            "WITH mark_used AS (
              UPDATE oidc_refresh_tokens
              SET used_at = NOW()
              WHERE token_hash = $1
                AND used_at IS NULL
                AND expires_at > NOW()
              RETURNING grant_id
            ),
            touch_grant AS (
              UPDATE oidc_grants
              SET
                expires_at = NOW() + ($2::bigint * INTERVAL '1 second'),
                last_used_at = NOW()
              FROM mark_used
              WHERE oidc_grants.id = mark_used.grant_id
                AND oidc_grants.expires_at > NOW()
              RETURNING oidc_grants.id
            ),
            new_at AS (
              INSERT INTO oidc_access_tokens (
                token_hash,
                grant_id,
                scopes,
                audience,
                expires_at
              )
              SELECT
                $3,
                id,
                $4,
                $5,
                NOW() + ($6::bigint * INTERVAL '1 second')
              FROM touch_grant
            ),
            new_rt AS (
              INSERT INTO oidc_refresh_tokens (
                token_hash,
                grant_id,
                expires_at
              )
              SELECT
                $7,
                id,
                NOW() + ($2::bigint * INTERVAL '1 second')
              FROM touch_grant
            )
            SELECT id FROM touch_grant"

          let res =
            pog.query(rotate_sql)
            |> pog.parameter(pog.bytea(rt_hash))
            |> pog.parameter(pog.int(refresh_token_ttl_seconds))
            |> pog.parameter(pog.bytea(new_at_hash))
            |> pog.parameter(pog.array(pog.text, scope_strings))
            |> pog.parameter(pog.text(audience))
            |> pog.parameter(pog.int(access_token_ttl_seconds))
            |> pog.parameter(pog.bytea(new_rt_hash))
            |> pog.returning(decode.dynamic)
            |> pog.execute(oidc_ctx.db)

          case res {
            Ok(pog.Returned(rows: [_, ..], ..)) ->
              Ok(IssuedTokens(
                access_token: new_raw_at,
                token_type: "Bearer",
                expires_in: access_token_ttl_seconds,
                refresh_token: Some(new_raw_rt),
                scopes: effective_scopes,
                audience:,
                sub:,
                user: auth_user,
                nonce: None,
                grant_public_id:,
              ))
            Ok(pog.Returned(rows: [], ..)) -> {
              revoke_compromised_grant(oidc_ctx, grant_id, grant_public_id)
              Error(InvalidGrant)
            }
            Error(_) -> Error(InternalError)
          }
        }
      }
  }
}

pub fn authenticate_access_token(
  db: pog.Connection,
  raw_token: String,
  expected_audience: Option(String),
) -> Result(Principal, Nil) {
  case is_valid_token_format("lote_at_", raw_token) {
    False -> Error(Nil)
    True -> {
      let token_hash = sha256(raw_token)

      let sql =
        "WITH matched AS (
          SELECT
            at.token_hash,
            at.scopes,
            at.audience,
            g.id AS grant_id,
            g.public_id AS grant_public_id,
            c.client_id,
            u.id AS user_id,
            u.name AS user_name,
            u.public_id AS user_public_id
          FROM oidc_access_tokens at
          INNER JOIN oidc_grants g ON g.id = at.grant_id
          INNER JOIN oidc_consents con ON con.id = g.consent_id
          INNER JOIN oidc_clients c ON c.id = con.client_ref_id
          INNER JOIN users u ON u.id = con.user_id
          WHERE at.token_hash = $1
            AND at.expires_at > NOW()
            AND g.expires_at > NOW()
            AND ($2::text IS NULL OR at.audience = $2::text)
          LIMIT 1
        ),
        touch_at AS (
          UPDATE oidc_access_tokens
          SET last_used_at = NOW()
          FROM matched
          WHERE oidc_access_tokens.token_hash = matched.token_hash
            AND (
              oidc_access_tokens.last_used_at IS NULL
              OR oidc_access_tokens.last_used_at < NOW() - INTERVAL '60 seconds'
            )
        ),
        touch_grant AS (
          UPDATE oidc_grants
          SET last_used_at = NOW()
          FROM matched
          WHERE oidc_grants.id = matched.grant_id
            AND (
              oidc_grants.last_used_at IS NULL
              OR oidc_grants.last_used_at < NOW() - INTERVAL '60 seconds'
            )
        )
        SELECT
          user_id,
          user_name,
          user_public_id,
          client_id,
          grant_public_id,
          scopes,
          audience,
          token_hash
        FROM matched"

      let decoder = {
        use uid <- decode.field(0, decode.int)
        use uname <- decode.field(1, decode.string)
        use sub <- decode.field(2, uuid.decoder())
        use client_id <- decode.field(3, decode.string)
        use grant_public_id <- decode.field(4, uuid.decoder())
        use scopes <- decode.field(5, scopes_decoder())
        use audience <- decode.field(6, decode.string)
        use stored_hash <- decode.field(7, decode.bit_array)
        decode.success(#(
          Principal(
            user: AuthUser(id: uid, name: uname),
            sub:,
            client_id:,
            grant_public_id:,
            scopes:,
            audience:,
          ),
          stored_hash,
        ))
      }

      let res =
        pog.query(sql)
        |> pog.parameter(pog.bytea(token_hash))
        |> pog.parameter(pog.nullable(pog.text, expected_audience))
        |> pog.returning(decoder)
        |> pog.execute(db)

      case res {
        Ok(pog.Returned(rows: [#(principal, stored_hash), ..], ..)) ->
          case crypto.secure_compare(token_hash, stored_hash) {
            True -> Ok(principal)
            False -> Error(Nil)
          }
        _ -> Error(Nil)
      }
    }
  }
}

pub fn revoke_by_raw_token(
  oidc_ctx: Oidc,
  client: Client,
  raw_token: String,
) -> Result(Nil, pog.QueryError) {
  let uuid_col_decoder = {
    use gid <- decode.field(0, uuid.decoder())
    decode.success(gid)
  }

  case
    is_valid_token_format("lote_rt_", raw_token),
    is_valid_token_format("lote_at_", raw_token)
  {
    True, _ -> {
      let token_hash = sha256(raw_token)
      let rt_sql =
        "DELETE FROM oidc_grants g
        USING oidc_refresh_tokens rt, oidc_consents con
        WHERE rt.grant_id = g.id
          AND g.consent_id = con.id
          AND rt.token_hash = $1
          AND con.client_ref_id = $2
        RETURNING g.public_id"

      use rt_returned <- result.map(
        pog.query(rt_sql)
        |> pog.parameter(pog.bytea(token_hash))
        |> pog.parameter(pog.int(client.id))
        |> pog.returning(uuid_col_decoder)
        |> pog.execute(oidc_ctx.db),
      )

      case rt_returned.rows {
        [grant_public_id, ..] ->
          oidc.publish_revocation(oidc_ctx, grant_public_id)
        [] -> Nil
      }
    }

    False, True -> {
      let token_hash = sha256(raw_token)
      let at_sql =
        "WITH deleted_at AS (
          DELETE FROM oidc_access_tokens at
          USING oidc_grants g, oidc_consents con
          WHERE at.grant_id = g.id
            AND g.consent_id = con.id
            AND at.token_hash = $1
            AND con.client_ref_id = $2
          RETURNING g.id AS grant_id
        ),
        deleted_grant AS (
          DELETE FROM oidc_grants g
          USING deleted_at da
          WHERE g.id = da.grant_id
            AND NOT EXISTS (
              SELECT 1 FROM oidc_refresh_tokens rt WHERE rt.grant_id = g.id
            )
          RETURNING g.public_id
        )
        SELECT public_id FROM deleted_grant"

      use at_returned <- result.map(
        pog.query(at_sql)
        |> pog.parameter(pog.bytea(token_hash))
        |> pog.parameter(pog.int(client.id))
        |> pog.returning(uuid_col_decoder)
        |> pog.execute(oidc_ctx.db),
      )

      case at_returned.rows {
        [grant_public_id, ..] ->
          oidc.publish_revocation(oidc_ctx, grant_public_id)
        [] -> Nil
      }
    }

    False, False -> Ok(Nil)
  }
}

pub fn introspect_raw_token(
  db: pog.Connection,
  client: Client,
  raw_token: String,
) -> Result(Introspection, pog.QueryError) {
  let decoder = {
    use uid <- decode.field(0, decode.int)
    use uname <- decode.field(1, decode.string)
    use sub <- decode.field(2, uuid.decoder())
    use client_id <- decode.field(3, decode.string)
    use grant_public_id <- decode.field(4, uuid.decoder())
    use scopes <- decode.field(5, scopes_decoder())
    use audience <- decode.field(6, decode.string)
    use expires_at <- decode.field(7, timestamptz_decoder())
    use created_at <- decode.field(8, timestamptz_decoder())
    use stored_hash <- decode.field(9, decode.bit_array)
    let #(exp, _) = timestamp.to_unix_seconds_and_nanoseconds(expires_at)
    let #(iat, _) = timestamp.to_unix_seconds_and_nanoseconds(created_at)
    decode.success(#(
      Active(
        principal: Principal(
          user: AuthUser(id: uid, name: uname),
          sub:,
          client_id:,
          grant_public_id:,
          scopes:,
          audience:,
        ),
        exp:,
        iat:,
      ),
      stored_hash,
    ))
  }

  case
    is_valid_token_format("lote_at_", raw_token),
    is_valid_token_format("lote_rt_", raw_token)
  {
    True, _ -> {
      let token_hash = sha256(raw_token)
      let at_sql =
        "SELECT
          u.id,
          u.name,
          u.public_id,
          c.client_id,
          g.public_id,
          at.scopes,
          at.audience,
          at.expires_at,
          at.created_at,
          at.token_hash
        FROM oidc_access_tokens at
        INNER JOIN oidc_grants g ON g.id = at.grant_id
        INNER JOIN oidc_consents con ON con.id = g.consent_id
        INNER JOIN oidc_clients c ON c.id = con.client_ref_id
        INNER JOIN users u ON u.id = con.user_id
        WHERE at.token_hash = $1
          AND con.client_ref_id = $2
          AND at.expires_at > NOW()
          AND g.expires_at > NOW()
        LIMIT 1"

      use at_returned <- result.map(
        pog.query(at_sql)
        |> pog.parameter(pog.bytea(token_hash))
        |> pog.parameter(pog.int(client.id))
        |> pog.returning(decoder)
        |> pog.execute(db),
      )

      case at_returned.rows {
        [#(active, stored_hash), ..] ->
          case crypto.secure_compare(token_hash, stored_hash) {
            True -> active
            False -> Inactive
          }
        [] -> Inactive
      }
    }

    False, True -> {
      let token_hash = sha256(raw_token)
      let rt_sql =
        "SELECT
          u.id,
          u.name,
          u.public_id,
          c.client_id,
          g.public_id,
          g.scopes,
          g.audience,
          rt.expires_at,
          rt.created_at,
          rt.token_hash
        FROM oidc_refresh_tokens rt
        INNER JOIN oidc_grants g ON g.id = rt.grant_id
        INNER JOIN oidc_consents con ON con.id = g.consent_id
        INNER JOIN oidc_clients c ON c.id = con.client_ref_id
        INNER JOIN users u ON u.id = con.user_id
        WHERE rt.token_hash = $1
          AND con.client_ref_id = $2
          AND rt.used_at IS NULL
          AND rt.expires_at > NOW()
          AND g.expires_at > NOW()
        LIMIT 1"

      use rt_returned <- result.map(
        pog.query(rt_sql)
        |> pog.parameter(pog.bytea(token_hash))
        |> pog.parameter(pog.int(client.id))
        |> pog.returning(decoder)
        |> pog.execute(db),
      )

      case rt_returned.rows {
        [#(active, stored_hash), ..] ->
          case crypto.secure_compare(token_hash, stored_hash) {
            True -> active
            False -> Inactive
          }
        [] -> Inactive
      }
    }

    False, False -> Ok(Inactive)
  }
}

fn revoke_compromised_grant(
  oidc_ctx: Oidc,
  grant_id: Int,
  grant_public_id: String,
) -> Nil {
  let _ =
    pog.query("DELETE FROM oidc_grants WHERE id = $1")
    |> pog.parameter(pog.int(grant_id))
    |> pog.returning(decode.dynamic)
    |> pog.execute(oidc_ctx.db)
  oidc.publish_revocation(oidc_ctx, grant_public_id)
}

fn resolve_bot_scopes(
  requested_scopes: Option(Set(Scope)),
  consent_scopes: Set(Scope),
) -> Result(Set(Scope), TokenError) {
  let candidate = case requested_scopes {
    None -> consent_scopes
    Some(req) ->
      case set.is_empty(req) {
        True -> consent_scopes
        False -> req
      }
  }

  case
    !set.is_empty(candidate)
    && list.all(set.to_list(candidate), scope.is_bot_assignable)
    && scope.is_subset(candidate, consent_scopes)
  {
    True -> Ok(candidate)
    False -> Error(InvalidScope)
  }
}

fn resolve_refresh_scopes(
  requested_scopes: Option(Set(Scope)),
  grant_scopes: Set(Scope),
) -> Result(Set(Scope), TokenError) {
  case requested_scopes {
    None -> Ok(grant_scopes)
    Some(req) ->
      case set.is_empty(req) {
        True -> Ok(grant_scopes)
        False ->
          case scope.is_subset(req, grant_scopes) {
            True -> Ok(req)
            False -> Error(InvalidScope)
          }
      }
  }
}

fn verify_bound_audience(
  requested_resource: Option(String),
  grant_audience: String,
  default_issuer: String,
) -> Result(String, TokenError) {
  case requested_resource {
    None | Some("") -> Ok(grant_audience)
    Some(r) ->
      case normalize_audience(Some(r), default_issuer) {
        Ok(normalized) if normalized == grant_audience -> Ok(grant_audience)
        _ -> Error(InvalidTarget)
      }
  }
}

fn verify_pkce_s256(code_verifier: String, stored_challenge: String) -> Bool {
  case is_valid_code_verifier(code_verifier) {
    False -> False
    True -> {
      let computed = compute_pkce_s256_challenge(code_verifier)
      crypto.secure_compare(<<computed:utf8>>, <<stored_challenge:utf8>>)
    }
  }
}

fn is_valid_code_verifier(s: String) -> Bool {
  let len = string.length(s)
  len >= 43
  && len <= 128
  && s
  |> string.to_utf_codepoints
  |> list.all(fn(cp) {
    case string.utf_codepoint_to_int(cp) {
      n if n >= 0x41 && n <= 0x5A -> True
      n if n >= 0x61 && n <= 0x7A -> True
      n if n >= 0x30 && n <= 0x39 -> True
      0x2D | 0x2E | 0x5F | 0x7E -> True
      _ -> False
    }
  })
}

fn is_valid_code_challenge(s: String) -> Bool {
  let len = string.length(s)
  len >= 43
  && len <= 128
  && s
  |> string.to_utf_codepoints
  |> list.all(fn(cp) {
    case string.utf_codepoint_to_int(cp) {
      n if n >= 0x41 && n <= 0x5A -> True
      n if n >= 0x61 && n <= 0x7A -> True
      n if n >= 0x30 && n <= 0x39 -> True
      0x2D | 0x5F -> True
      _ -> False
    }
  })
}

fn is_base64url_43(s: String) -> Bool {
  string.length(s) == 43
  && s
  |> string.to_utf_codepoints
  |> list.all(fn(cp) {
    case string.utf_codepoint_to_int(cp) {
      n if n >= 0x41 && n <= 0x5A -> True
      n if n >= 0x61 && n <= 0x7A -> True
      n if n >= 0x30 && n <= 0x39 -> True
      0x2D | 0x5F -> True
      _ -> False
    }
  })
}

fn generate_token(prefix: String) -> #(String, BitArray) {
  let rand =
    crypto.strong_random_bytes(32)
    |> bit_array.base64_url_encode(False)
  let raw = prefix <> rand
  #(raw, sha256(raw))
}

fn sha256(raw: String) -> BitArray {
  crypto.hash(crypto.Sha256, <<raw:utf8>>)
}

fn sanitize_user_agent(user_agent: String) -> String {
  user_agent
  |> string.trim
  |> string.slice(at_index: 0, length: max_user_agent_length)
}

fn valid_port(port: Option(Int)) -> Bool {
  case port {
    None -> True
    Some(p) -> p >= 1 && p <= 65_535
  }
}

fn contains_whitespace(s: String) -> Bool {
  s
  |> string.to_utf_codepoints
  |> list.any(fn(cp) {
    case string.utf_codepoint_to_int(cp) {
      n if n <= 0x20 || n == 0x7F -> True
      _ -> False
    }
  })
}

fn scopes_decoder() -> decode.Decoder(Set(Scope)) {
  use raw <- decode.then(decode.list(decode.string))
  case scope.parse_list(raw) {
    Ok(scopes) -> decode.success(scopes)
    Error(_) -> decode.failure(set.new(), "Set(Scope)")
  }
}

fn timestamptz_decoder() -> decode.Decoder(Timestamp) {
  use date <- decode.field(0, pog.calendar_date_decoder())
  use time <- decode.field(1, pog.calendar_time_of_day_decoder())
  decode.success(timestamp.from_calendar(date, time, calendar.utc_offset))
}
