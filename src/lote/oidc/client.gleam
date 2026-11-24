import gleam/bit_array
import gleam/crypto
import gleam/dict
import gleam/dynamic/decode
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/set.{type Set}
import gleam/string
import gleam/time/calendar
import gleam/time/timestamp.{type Timestamp}
import gleam/uri.{type Uri}
import lote/db/uuid
import lote/oidc/scope.{type Scope}
import pog

pub const max_active_secrets_per_client = 5

const max_name_length = 100

const max_secret_label_length = 100

pub type Kind {
  SubordinateBot
  ConfidentialApp
  PublicApp
  Cimd
}

pub type Visibility {
  Private
  Public
}

pub type ApplicationType {
  Web
  Native
}

pub type Client {
  Client(
    id: Int,
    client_id: String,
    owner_user_id: Option(Int),
    kind: Kind,
    visibility: Visibility,
    application_type: ApplicationType,
    name: String,
    redirect_uris: List(String),
    allowed_scopes: Set(Scope),
    created_at: Timestamp,
  )
}

pub type SecretInfo {
  SecretInfo(
    public_id: String,
    label: String,
    secret_prefix: String,
    expires_at: Option(Timestamp),
    last_used_at: Option(Timestamp),
    created_at: Timestamp,
  )
}

pub type CreatedSecret {
  CreatedSecret(secret: String, info: SecretInfo)
}

pub type CreatedBot {
  CreatedBot(client: Client, secret: CreatedSecret, consent_public_id: String)
}

pub type Error {
  InvalidInput(String)
  InvalidRedirectUri(String)
  InvalidScope(String)
  SecretLimitExceeded
  NotFound
  InvalidClientCredentials
  InternalError
}

pub fn kind_to_string(kind: Kind) -> String {
  case kind {
    SubordinateBot -> "subordinate_bot"
    ConfidentialApp -> "confidential_app"
    PublicApp -> "public_app"
    Cimd -> "cimd"
  }
}

pub fn kind_from_string(raw: String) -> Result(Kind, String) {
  case raw {
    "subordinate_bot" -> Ok(SubordinateBot)
    "confidential_app" -> Ok(ConfidentialApp)
    "public_app" -> Ok(PublicApp)
    "cimd" -> Ok(Cimd)
    _ -> Error(raw)
  }
}

pub fn visibility_to_string(visibility: Visibility) -> String {
  case visibility {
    Private -> "private"
    Public -> "public"
  }
}

pub fn visibility_from_string(raw: String) -> Result(Visibility, String) {
  case raw {
    "private" -> Ok(Private)
    "public" -> Ok(Public)
    _ -> Error(raw)
  }
}

pub fn application_type_to_string(application_type: ApplicationType) -> String {
  case application_type {
    Web -> "web"
    Native -> "native"
  }
}

pub fn application_type_from_string(
  raw: String,
) -> Result(ApplicationType, String) {
  case raw {
    "web" -> Ok(Web)
    "native" -> Ok(Native)
    _ -> Error(raw)
  }
}

pub fn validate_redirect_uri(raw: String) -> Result(String, String) {
  case raw != "" && string.trim(raw) == raw && !contains_whitespace(raw) {
    False -> Error("Redirect URI must be a non-empty URI without whitespace")
    True ->
      case uri.parse(raw) {
        Error(_) -> Error("Invalid redirect URI syntax")
        Ok(parsed) ->
          case parsed.fragment, parsed.userinfo, valid_port(parsed.port) {
            Some(_), _, _ -> Error("Redirect URI must not contain a fragment")
            _, Some(_), _ -> Error("Redirect URI must not contain userinfo")
            _, _, False -> Error("Redirect URI has an invalid port")
            None, None, True ->
              case parsed.scheme, parsed.host {
                Some("https"), Some(host) ->
                  case string.trim(host) != "" {
                    True -> Ok(raw)
                    False -> Error("HTTPS redirect URI must include a host")
                  }
                Some("http"), Some(host) ->
                  case is_loopback_host(host) {
                    True -> Ok(raw)
                    False ->
                      Error(
                        "HTTP redirect URI is only allowed for loopback hosts",
                      )
                  }
                _, _ ->
                  Error("Redirect URI must use https or an http loopback host")
              }
          }
      }
  }
}

pub fn matches_redirect_uri(client: Client, requested_uri: String) -> Bool {
  case validate_redirect_uri(requested_uri) {
    Error(_) -> False
    Ok(_) ->
      case list.contains(client.redirect_uris, requested_uri) {
        True -> True
        False ->
          case client.application_type {
            Web -> False
            Native ->
              matches_native_loopback(client.redirect_uris, requested_uri)
          }
      }
  }
}

pub fn create_subordinate_bot(
  db: pog.Connection,
  owner_user_id: Int,
  name: String,
  scopes: Set(Scope),
  secret_label: String,
  secret_ttl_seconds: Option(Int),
) -> Result(CreatedBot, Error) {
  use trimmed_name <- result.try(validate_name(name))
  use trimmed_label <- result.try(validate_secret_label(secret_label))
  use _ <- result.try(validate_bot_scopes(scopes))
  use _ <- result.try(validate_ttl(secret_ttl_seconds))

  let client_id = generate_client_id()
  let #(raw_secret, secret_prefix, secret_hash) = generate_client_secret()
  let scope_strings = scope.to_sorted_strings(scopes)

  let sql =
    "WITH new_client AS (
      INSERT INTO oidc_clients (
        client_id,
        owner_user_id,
        kind,
        visibility,
        application_type,
        name,
        redirect_uris,
        allowed_scopes
      )
      VALUES ($1, $2, 'subordinate_bot', 'private', 'web', $3, '{}', $4)
      RETURNING
        id,
        client_id,
        owner_user_id,
        kind,
        visibility,
        application_type,
        name,
        redirect_uris,
        allowed_scopes,
        created_at
    ),
    new_secret AS (
      INSERT INTO oidc_client_secrets (
        client_ref_id,
        label,
        secret_prefix,
        secret_hash,
        expires_at
      )
      SELECT
        id,
        $5,
        $6,
        $7,
        CASE
          WHEN $8::bigint IS NULL THEN NULL
          ELSE NOW() + ($8::bigint * INTERVAL '1 second')
        END
      FROM new_client
      RETURNING
        public_id,
        label,
        secret_prefix,
        expires_at,
        last_used_at,
        created_at
    ),
    new_consent AS (
      INSERT INTO oidc_consents (user_id, client_ref_id, scopes)
      SELECT $2, id, $4
      FROM new_client
      RETURNING public_id
    )
    SELECT
      c.id,
      c.client_id,
      c.owner_user_id,
      c.kind,
      c.visibility,
      c.application_type,
      c.name,
      c.redirect_uris,
      c.allowed_scopes,
      c.created_at,
      s.public_id,
      s.label,
      s.secret_prefix,
      s.expires_at,
      s.last_used_at,
      s.created_at,
      con.public_id
    FROM new_client c
    CROSS JOIN new_secret s
    CROSS JOIN new_consent con"

  let decoder = {
    use client <- decode.then(client_decoder_at(0))
    use secret_info <- decode.then(secret_info_decoder_at(10))
    use consent_public_id <- decode.field(16, uuid.decoder())
    decode.success(CreatedBot(
      client:,
      secret: CreatedSecret(secret: raw_secret, info: secret_info),
      consent_public_id:,
    ))
  }

  let result =
    pog.query(sql)
    |> pog.parameter(pog.text(client_id))
    |> pog.parameter(pog.int(owner_user_id))
    |> pog.parameter(pog.text(trimmed_name))
    |> pog.parameter(pog.array(pog.text, scope_strings))
    |> pog.parameter(pog.text(trimmed_label))
    |> pog.parameter(pog.text(secret_prefix))
    |> pog.parameter(pog.bytea(secret_hash))
    |> pog.parameter(pog.nullable(pog.int, secret_ttl_seconds))
    |> pog.returning(decoder)
    |> pog.execute(db)

  case result {
    Ok(pog.Returned(rows: [bot, ..], ..)) -> Ok(bot)
    Ok(pog.Returned(rows: [], ..)) -> Error(InternalError)
    Error(pog.ConstraintViolated(constraint:, ..)) ->
      case string.contains(constraint, "owner_user_id") {
        True -> Error(NotFound)
        False -> Error(InternalError)
      }
    Error(_) -> Error(InternalError)
  }
}

pub fn create_app(
  db: pog.Connection,
  owner_user_id: Int,
  name: String,
  confidential: Bool,
  visibility: Visibility,
  application_type: ApplicationType,
  redirect_uris: List(String),
  allowed_scopes: Set(Scope),
) -> Result(#(Client, Option(CreatedSecret)), Error) {
  use trimmed_name <- result.try(validate_name(name))
  use validated_uris <- result.try(validate_redirect_uris(redirect_uris))
  use _ <- result.try(case set.is_empty(allowed_scopes) {
    True -> Error(InvalidScope("At least one scope is required"))
    False -> Ok(Nil)
  })

  let client_id = generate_client_id()
  let scope_strings = scope.to_sorted_strings(allowed_scopes)
  let visibility_str = visibility_to_string(visibility)
  let app_type_str = application_type_to_string(application_type)

  case confidential {
    True -> {
      let #(raw_secret, secret_prefix, secret_hash) = generate_client_secret()
      let sql =
        "WITH new_client AS (
          INSERT INTO oidc_clients (
            client_id,
            owner_user_id,
            kind,
            visibility,
            application_type,
            name,
            redirect_uris,
            allowed_scopes
          )
          VALUES ($1, $2, 'confidential_app', $3, $4, $5, $6, $7)
          RETURNING
            id,
            client_id,
            owner_user_id,
            kind,
            visibility,
            application_type,
            name,
            redirect_uris,
            allowed_scopes,
            created_at
        ),
        new_secret AS (
          INSERT INTO oidc_client_secrets (
            client_ref_id,
            label,
            secret_prefix,
            secret_hash
          )
          SELECT id, 'default', $8, $9
          FROM new_client
          RETURNING
            public_id,
            label,
            secret_prefix,
            expires_at,
            last_used_at,
            created_at
        )
        SELECT
          c.id,
          c.client_id,
          c.owner_user_id,
          c.kind,
          c.visibility,
          c.application_type,
          c.name,
          c.redirect_uris,
          c.allowed_scopes,
          c.created_at,
          s.public_id,
          s.label,
          s.secret_prefix,
          s.expires_at,
          s.last_used_at,
          s.created_at
        FROM new_client c
        CROSS JOIN new_secret s"

      let decoder = {
        use client <- decode.then(client_decoder_at(0))
        use secret_info <- decode.then(secret_info_decoder_at(10))
        decode.success(#(
          client,
          Some(CreatedSecret(secret: raw_secret, info: secret_info)),
        ))
      }

      let result =
        pog.query(sql)
        |> pog.parameter(pog.text(client_id))
        |> pog.parameter(pog.int(owner_user_id))
        |> pog.parameter(pog.text(visibility_str))
        |> pog.parameter(pog.text(app_type_str))
        |> pog.parameter(pog.text(trimmed_name))
        |> pog.parameter(pog.array(pog.text, validated_uris))
        |> pog.parameter(pog.array(pog.text, scope_strings))
        |> pog.parameter(pog.text(secret_prefix))
        |> pog.parameter(pog.bytea(secret_hash))
        |> pog.returning(decoder)
        |> pog.execute(db)

      case result {
        Ok(pog.Returned(rows: [created, ..], ..)) -> Ok(created)
        Ok(pog.Returned(rows: [], ..)) -> Error(InternalError)
        Error(pog.ConstraintViolated(constraint:, ..)) ->
          case string.contains(constraint, "owner_user_id") {
            True -> Error(NotFound)
            False -> Error(InternalError)
          }
        Error(_) -> Error(InternalError)
      }
    }

    False -> {
      let sql =
        "INSERT INTO oidc_clients (
          client_id,
          owner_user_id,
          kind,
          visibility,
          application_type,
          name,
          redirect_uris,
          allowed_scopes
        )
        VALUES ($1, $2, 'public_app', $3, $4, $5, $6, $7)
        RETURNING
          id,
          client_id,
          owner_user_id,
          kind,
          visibility,
          application_type,
          name,
          redirect_uris,
          allowed_scopes,
          created_at"

      let result =
        pog.query(sql)
        |> pog.parameter(pog.text(client_id))
        |> pog.parameter(pog.int(owner_user_id))
        |> pog.parameter(pog.text(visibility_str))
        |> pog.parameter(pog.text(app_type_str))
        |> pog.parameter(pog.text(trimmed_name))
        |> pog.parameter(pog.array(pog.text, validated_uris))
        |> pog.parameter(pog.array(pog.text, scope_strings))
        |> pog.returning(client_decoder_at(0))
        |> pog.execute(db)

      case result {
        Ok(pog.Returned(rows: [client, ..], ..)) -> Ok(#(client, None))
        Ok(pog.Returned(rows: [], ..)) -> Error(InternalError)
        Error(pog.ConstraintViolated(constraint:, ..)) ->
          case string.contains(constraint, "owner_user_id") {
            True -> Error(NotFound)
            False -> Error(InternalError)
          }
        Error(_) -> Error(InternalError)
      }
    }
  }
}

pub fn list_for_owner(
  db: pog.Connection,
  owner_user_id: Int,
) -> Result(List(#(Client, List(SecretInfo))), pog.QueryError) {
  let clients_sql =
    "SELECT
      id,
      client_id,
      owner_user_id,
      kind,
      visibility,
      application_type,
      name,
      redirect_uris,
      allowed_scopes,
      created_at
    FROM oidc_clients
    WHERE owner_user_id = $1
    ORDER BY created_at DESC, id DESC"

  use clients_returned <- result.try(
    pog.query(clients_sql)
    |> pog.parameter(pog.int(owner_user_id))
    |> pog.returning(client_decoder_at(0))
    |> pog.execute(db),
  )

  case clients_returned.rows {
    [] -> Ok([])
    clients -> {
      let client_ids = list.map(clients, fn(c) { c.id })
      let secrets_sql =
        "SELECT
          client_ref_id,
          public_id,
          label,
          secret_prefix,
          expires_at,
          last_used_at,
          created_at
        FROM oidc_client_secrets
        WHERE client_ref_id = ANY($1::bigint[])
          AND (expires_at IS NULL OR expires_at > NOW())
        ORDER BY created_at DESC, id DESC"

      let secret_row_decoder = {
        use client_ref_id <- decode.field(0, decode.int)
        use info <- decode.then(secret_info_decoder_at(1))
        decode.success(#(client_ref_id, info))
      }

      use secrets_returned <- result.map(
        pog.query(secrets_sql)
        |> pog.parameter(pog.array(pog.int, client_ids))
        |> pog.returning(secret_row_decoder)
        |> pog.execute(db),
      )

      let grouped =
        list.fold_right(secrets_returned.rows, dict.new(), fn(acc, pair) {
          let #(cid, info) = pair
          let existing = dict.get(acc, cid) |> result.unwrap([])
          dict.insert(acc, cid, [info, ..existing])
        })

      list.map(clients, fn(c) {
        let secrets = dict.get(grouped, c.id) |> result.unwrap([])
        #(c, secrets)
      })
    }
  }
}

pub fn is_valid_client_id_format(raw: String) -> Bool {
  case bit_array.byte_size(<<raw:utf8>>) == 36 {
    False -> False
    True ->
      case raw {
        "cli_" <> hex_part -> is_lowercase_hex(hex_part)
        _ -> False
      }
  }
}

pub fn is_valid_secret_format(raw: String) -> Bool {
  case bit_array.byte_size(<<raw:utf8>>) == 51 {
    False -> False
    True ->
      case raw {
        "lote_cs_" <> b64_part -> is_base64url_unpadded(b64_part)
        _ -> False
      }
  }
}

pub fn find_by_client_id(
  db: pog.Connection,
  client_id: String,
) -> Result(Option(Client), pog.QueryError) {
  case is_valid_client_id_format(client_id) {
    False -> Ok(None)
    True -> {
      let sql =
        "SELECT
          id,
          client_id,
          owner_user_id,
          kind,
          visibility,
          application_type,
          name,
          redirect_uris,
          allowed_scopes,
          created_at
        FROM oidc_clients
        WHERE client_id = $1
        LIMIT 1"

      use returned <- result.map(
        pog.query(sql)
        |> pog.parameter(pog.text(client_id))
        |> pog.returning(client_decoder_at(0))
        |> pog.execute(db),
      )

      case returned.rows {
        [client, ..] -> Some(client)
        [] -> None
      }
    }
  }
}

pub fn create_secret(
  db: pog.Connection,
  owner_user_id: Int,
  client_id: String,
  label: String,
  ttl_seconds: Option(Int),
) -> Result(CreatedSecret, Error) {
  case is_valid_client_id_format(client_id) {
    False -> Error(NotFound)
    True -> {
      use trimmed_label <- result.try(validate_secret_label(label))
      use _ <- result.try(validate_ttl(ttl_seconds))

      let lookup_sql =
        "SELECT id, kind
        FROM oidc_clients
        WHERE client_id = $1 AND owner_user_id = $2
        FOR UPDATE"

      let lookup_decoder = {
        use id <- decode.field(0, decode.int)
        use kind <- decode.field(1, kind_decoder())
        decode.success(#(id, kind))
      }

      let lookup_result =
        pog.query(lookup_sql)
        |> pog.parameter(pog.text(client_id))
        |> pog.parameter(pog.int(owner_user_id))
        |> pog.returning(lookup_decoder)
        |> pog.execute(db)

      case lookup_result {
        Error(_) -> Error(InternalError)
        Ok(pog.Returned(rows: [], ..)) -> Error(NotFound)
        Ok(pog.Returned(rows: [#(_, PublicApp), ..], ..))
        | Ok(pog.Returned(rows: [#(_, Cimd), ..], ..)) ->
          Error(InvalidInput("This client kind does not support client secrets"))
        Ok(pog.Returned(rows: [#(client_ref_id, _), ..], ..)) -> {
          let #(raw_secret, secret_prefix, secret_hash) =
            generate_client_secret()

          let insert_sql =
            "INSERT INTO oidc_client_secrets (
              client_ref_id,
              label,
              secret_prefix,
              secret_hash,
              expires_at
            )
            SELECT
              $1,
              $2,
              $3,
              $4,
              CASE
                WHEN $5::bigint IS NULL THEN NULL
                ELSE NOW() + ($5::bigint * INTERVAL '1 second')
              END
            WHERE (
              SELECT COUNT(*)
              FROM oidc_client_secrets
              WHERE client_ref_id = $1
                AND (expires_at IS NULL OR expires_at > NOW())
            ) < $6
            RETURNING
              public_id,
              label,
              secret_prefix,
              expires_at,
              last_used_at,
              created_at"

          let insert_result =
            pog.query(insert_sql)
            |> pog.parameter(pog.int(client_ref_id))
            |> pog.parameter(pog.text(trimmed_label))
            |> pog.parameter(pog.text(secret_prefix))
            |> pog.parameter(pog.bytea(secret_hash))
            |> pog.parameter(pog.nullable(pog.int, ttl_seconds))
            |> pog.parameter(pog.int(max_active_secrets_per_client))
            |> pog.returning(secret_info_decoder_at(0))
            |> pog.execute(db)

          case insert_result {
            Ok(pog.Returned(rows: [info, ..], ..)) ->
              Ok(CreatedSecret(secret: raw_secret, info:))
            Ok(pog.Returned(rows: [], ..)) -> Error(SecretLimitExceeded)
            Error(_) -> Error(InternalError)
          }
        }
      }
    }
  }
}

pub fn revoke_secret(
  db: pog.Connection,
  owner_user_id: Int,
  client_id: String,
  secret_public_id: String,
) -> Result(Bool, pog.QueryError) {
  case is_valid_client_id_format(client_id), uuid.normalize(secret_public_id) {
    False, _ | _, Error(_) -> Ok(False)
    True, Ok(normalized) -> {
      let sql =
        "DELETE FROM oidc_client_secrets s
        USING oidc_clients c
        WHERE s.client_ref_id = c.id
          AND s.public_id = $1::uuid
          AND c.client_id = $2
          AND c.owner_user_id = $3
        RETURNING s.id"

      use returned <- result.map(
        pog.query(sql)
        |> pog.parameter(pog.text(normalized))
        |> pog.parameter(pog.text(client_id))
        |> pog.parameter(pog.int(owner_user_id))
        |> pog.returning(decode.dynamic)
        |> pog.execute(db),
      )

      returned.rows != []
    }
  }
}

pub fn delete_for_owner(
  db: pog.Connection,
  owner_user_id: Int,
  client_id: String,
) -> Result(Option(List(String)), pog.QueryError) {
  case is_valid_client_id_format(client_id) {
    False -> Ok(None)
    True -> {
      let sql =
        "WITH target_client AS (
          DELETE FROM oidc_clients
          WHERE client_id = $1 AND owner_user_id = $2
          RETURNING id
        ),
        revoked_grants AS (
          SELECT g.public_id
          FROM oidc_grants g
          INNER JOIN oidc_consents con ON con.id = g.consent_id
          INNER JOIN target_client tc ON tc.id = con.client_ref_id
          WHERE g.expires_at > NOW()
        )
        SELECT tc.id, rg.public_id
        FROM target_client tc
        LEFT JOIN revoked_grants rg ON TRUE"

      let decoder = {
        use deleted_id <- decode.field(0, decode.int)
        use grant_public_id <- decode.field(1, decode.optional(uuid.decoder()))
        decode.success(#(deleted_id, grant_public_id))
      }

      use returned <- result.map(
        pog.query(sql)
        |> pog.parameter(pog.text(client_id))
        |> pog.parameter(pog.int(owner_user_id))
        |> pog.returning(decoder)
        |> pog.execute(db),
      )

      case returned.rows {
        [] -> None
        rows ->
          rows
          |> list.filter_map(fn(row) {
            case row.1 {
              Some(gid) -> Ok(gid)
              None -> Error(Nil)
            }
          })
          |> Some
      }
    }
  }
}

pub fn authenticate_secret_for_client(
  db: pog.Connection,
  client: Client,
  raw_secret: String,
) -> Result(Client, Error) {
  case client.kind, is_valid_secret_format(raw_secret) {
    PublicApp, _ | Cimd, _ | _, False -> Error(InvalidClientCredentials)
    SubordinateBot, True | ConfidentialApp, True -> {
      let secret_hash = crypto.hash(crypto.Sha256, <<raw_secret:utf8>>)

      let sql =
        "WITH matched AS (
          SELECT id, secret_hash
          FROM oidc_client_secrets
          WHERE client_ref_id = $1
            AND secret_hash = $2
            AND (expires_at IS NULL OR expires_at > NOW())
          LIMIT 1
        ),
        touch AS (
          UPDATE oidc_client_secrets
          SET last_used_at = NOW()
          FROM matched
          WHERE oidc_client_secrets.id = matched.id
            AND (
              oidc_client_secrets.last_used_at IS NULL
              OR oidc_client_secrets.last_used_at < NOW() - INTERVAL '60 seconds'
            )
        )
        SELECT secret_hash FROM matched"

      let decoder = {
        use stored_hash <- decode.field(0, decode.bit_array)
        decode.success(stored_hash)
      }

      let result =
        pog.query(sql)
        |> pog.parameter(pog.int(client.id))
        |> pog.parameter(pog.bytea(secret_hash))
        |> pog.returning(decoder)
        |> pog.execute(db)

      case result {
        Ok(pog.Returned(rows: [stored_hash, ..], ..)) ->
          case crypto.secure_compare(secret_hash, stored_hash) {
            True -> Ok(client)
            False -> Error(InvalidClientCredentials)
          }
        Ok(pog.Returned(rows: [], ..)) -> Error(InvalidClientCredentials)
        Error(_) -> Error(InternalError)
      }
    }
  }
}

pub fn authenticate_secret(
  db: pog.Connection,
  client_id: String,
  raw_secret: String,
) -> Result(Client, Error) {
  case
    is_valid_client_id_format(client_id) && is_valid_secret_format(raw_secret)
  {
    False -> Error(InvalidClientCredentials)
    True ->
      case find_by_client_id(db, client_id) {
        Ok(Some(found)) -> authenticate_secret_for_client(db, found, raw_secret)
        Ok(None) -> Error(InvalidClientCredentials)
        Error(_) -> Error(InternalError)
      }
  }
}

fn is_lowercase_hex(s: String) -> Bool {
  s
  |> string.to_utf_codepoints
  |> list.all(fn(cp) {
    case string.utf_codepoint_to_int(cp) {
      n if n >= 0x30 && n <= 0x39 -> True
      n if n >= 0x61 && n <= 0x66 -> True
      _ -> False
    }
  })
}

fn is_base64url_unpadded(s: String) -> Bool {
  s
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

fn generate_client_id() -> String {
  let hex =
    crypto.strong_random_bytes(16)
    |> bit_array.base16_encode
    |> string.lowercase
  "cli_" <> hex
}

fn generate_client_secret() -> #(String, String, BitArray) {
  let rand =
    crypto.strong_random_bytes(32)
    |> bit_array.base64_url_encode(False)
  let raw_secret = "lote_cs_" <> rand
  let secret_prefix = string.slice(raw_secret, at_index: 0, length: 12)
  let secret_hash = crypto.hash(crypto.Sha256, <<raw_secret:utf8>>)
  #(raw_secret, secret_prefix, secret_hash)
}

fn validate_name(raw: String) -> Result(String, Error) {
  let trimmed = string.trim(raw)
  let len = string.length(trimmed)
  case len {
    0 -> Error(InvalidInput("Client name is required"))
    n if n > max_name_length ->
      Error(InvalidInput("Client name must be at most 100 characters"))
    _ -> Ok(trimmed)
  }
}

fn validate_secret_label(raw: String) -> Result(String, Error) {
  let trimmed = string.trim(raw)
  case string.length(trimmed) > max_secret_label_length {
    True -> Error(InvalidInput("Secret label must be at most 100 characters"))
    False -> Ok(trimmed)
  }
}

fn validate_bot_scopes(scopes: Set(Scope)) -> Result(Nil, Error) {
  case set.is_empty(scopes) {
    True -> Error(InvalidScope("At least one scope is required"))
    False ->
      case
        list.find(set.to_list(scopes), fn(s) { !scope.is_bot_assignable(s) })
      {
        Ok(disallowed) ->
          Error(InvalidScope(
            "Scope is not assignable to subordinate bots: "
            <> scope.to_string(disallowed),
          ))
        Error(_) -> Ok(Nil)
      }
  }
}

fn validate_ttl(ttl_seconds: Option(Int)) -> Result(Nil, Error) {
  case ttl_seconds {
    Some(s) if s <= 0 -> Error(InvalidInput("Secret TTL must be positive"))
    _ -> Ok(Nil)
  }
}

fn validate_redirect_uris(
  raw_uris: List(String),
) -> Result(List(String), Error) {
  let unique_uris = list.unique(raw_uris)
  case unique_uris {
    [] -> Error(InvalidRedirectUri("At least one redirect URI is required"))
    _ ->
      list.try_map(unique_uris, fn(u) {
        validate_redirect_uri(u)
        |> result.map_error(InvalidRedirectUri)
      })
  }
}

fn matches_native_loopback(
  registered_uris: List(String),
  requested_raw: String,
) -> Bool {
  case parse_native_loopback_uri(requested_raw) {
    Error(_) -> False
    Ok(#(req_host, req_uri)) ->
      list.any(registered_uris, fn(reg_raw) {
        case validate_redirect_uri(reg_raw) {
          Error(_) -> False
          Ok(_) ->
            case parse_native_loopback_uri(reg_raw) {
              Error(_) -> False
              Ok(#(reg_host, reg_uri)) ->
                reg_host == req_host
                && reg_uri.path == req_uri.path
                && reg_uri.query == req_uri.query
            }
        }
      })
  }
}

fn parse_native_loopback_uri(raw: String) -> Result(#(String, Uri), Nil) {
  use parsed <- result.try(uri.parse(raw))
  case
    parsed.scheme,
    parsed.fragment,
    parsed.userinfo,
    valid_port(parsed.port),
    parsed.host
  {
    Some("http"), None, None, True, Some(host) -> {
      use ip_host <- result.map(canonical_loopback_ip(host))
      #(ip_host, parsed)
    }
    _, _, _, _, _ -> Error(Nil)
  }
}

fn is_loopback_host(host: String) -> Bool {
  case string.lowercase(host) {
    "127.0.0.1" | "[::1]" | "::1" | "localhost" -> True
    _ -> False
  }
}

fn canonical_loopback_ip(host: String) -> Result(String, Nil) {
  case string.lowercase(host) {
    "127.0.0.1" -> Ok("127.0.0.1")
    "[::1]" | "::1" -> Ok("::1")
    _ -> Error(Nil)
  }
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

fn client_decoder_at(offset: Int) -> decode.Decoder(Client) {
  use id <- decode.field(offset, decode.int)
  use client_id <- decode.field(offset + 1, decode.string)
  use owner_user_id <- decode.field(offset + 2, decode.optional(decode.int))
  use kind <- decode.field(offset + 3, kind_decoder())
  use visibility <- decode.field(offset + 4, visibility_decoder())
  use application_type <- decode.field(offset + 5, application_type_decoder())
  use name <- decode.field(offset + 6, decode.string)
  use redirect_uris <- decode.field(offset + 7, decode.list(decode.string))
  use allowed_scopes <- decode.field(offset + 8, scopes_decoder())
  use created_at <- decode.field(offset + 9, timestamptz_decoder())
  decode.success(Client(
    id:,
    client_id:,
    owner_user_id:,
    kind:,
    visibility:,
    application_type:,
    name:,
    redirect_uris:,
    allowed_scopes:,
    created_at:,
  ))
}

fn secret_info_decoder_at(offset: Int) -> decode.Decoder(SecretInfo) {
  use public_id <- decode.field(offset, uuid.decoder())
  use label <- decode.field(offset + 1, decode.string)
  use secret_prefix <- decode.field(offset + 2, decode.string)
  use expires_at <- decode.field(
    offset + 3,
    decode.optional(timestamptz_decoder()),
  )
  use last_used_at <- decode.field(
    offset + 4,
    decode.optional(timestamptz_decoder()),
  )
  use created_at <- decode.field(offset + 5, timestamptz_decoder())
  decode.success(SecretInfo(
    public_id:,
    label:,
    secret_prefix:,
    expires_at:,
    last_used_at:,
    created_at:,
  ))
}

fn kind_decoder() -> decode.Decoder(Kind) {
  use raw <- decode.then(decode.string)
  case kind_from_string(raw) {
    Ok(kind) -> decode.success(kind)
    Error(_) -> decode.failure(SubordinateBot, "Kind")
  }
}

fn visibility_decoder() -> decode.Decoder(Visibility) {
  use raw <- decode.then(decode.string)
  case visibility_from_string(raw) {
    Ok(visibility) -> decode.success(visibility)
    Error(_) -> decode.failure(Private, "Visibility")
  }
}

fn application_type_decoder() -> decode.Decoder(ApplicationType) {
  use raw <- decode.then(decode.string)
  case application_type_from_string(raw) {
    Ok(app_type) -> decode.success(app_type)
    Error(_) -> decode.failure(Web, "ApplicationType")
  }
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
