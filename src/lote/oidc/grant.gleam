import gleam/dynamic/decode
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/set.{type Set}
import gleam/string
import gleam/time/calendar
import gleam/time/timestamp.{type Timestamp}
import lote/db/uuid
import lote/oidc/client
import lote/oidc/scope.{type Scope}
import pog

const max_user_agent_length = 512

pub type ConsentInfo {
  ConsentInfo(
    id: Int,
    public_id: String,
    user_id: Int,
    client_ref_id: Int,
    client_id: String,
    client_name: String,
    client_kind: client.Kind,
    scopes: Set(Scope),
    created_at: Timestamp,
    updated_at: Timestamp,
  )
}

pub type GrantInfo {
  GrantInfo(
    id: Int,
    public_id: String,
    consent_public_id: String,
    client_id: String,
    client_name: String,
    scopes: Set(Scope),
    audience: String,
    user_agent: String,
    last_used_at: Option(Timestamp),
    expires_at: Timestamp,
    created_at: Timestamp,
  )
}

pub fn upsert_consent(
  db: pog.Connection,
  user_id: Int,
  client_ref_id: Int,
  scopes: Set(Scope),
) -> Result(#(Int, String, Set(Scope)), pog.QueryError) {
  let scope_strings = scope.to_sorted_strings(scopes)

  let sql =
    "INSERT INTO oidc_consents (user_id, client_ref_id, scopes)
    VALUES ($1, $2, $3)
    ON CONFLICT (user_id, client_ref_id) DO UPDATE
    SET
      scopes = ARRAY(
        SELECT DISTINCT unnest(oidc_consents.scopes || EXCLUDED.scopes)
        ORDER BY 1
      ),
      updated_at = NOW()
    RETURNING id, public_id, scopes"

  let decoder = {
    use id <- decode.field(0, decode.int)
    use public_id <- decode.field(1, uuid.decoder())
    use merged_scopes <- decode.field(2, scopes_decoder())
    decode.success(#(id, public_id, merged_scopes))
  }

  use returned <- result.try(
    pog.query(sql)
    |> pog.parameter(pog.int(user_id))
    |> pog.parameter(pog.int(client_ref_id))
    |> pog.parameter(pog.array(pog.text, scope_strings))
    |> pog.returning(decoder)
    |> pog.execute(db),
  )

  case returned.rows {
    [row, ..] -> Ok(row)
    [] -> Error(pog.ConnectionUnavailable)
  }
}

pub fn ensure_consent_row(
  db: pog.Connection,
  user_id: Int,
  client_ref_id: Int,
) -> Result(#(Int, String), pog.QueryError) {
  let sql =
    "INSERT INTO oidc_consents (user_id, client_ref_id, scopes)
    VALUES ($1, $2, '{}')
    ON CONFLICT (user_id, client_ref_id) DO UPDATE
    SET user_id = EXCLUDED.user_id
    RETURNING id, public_id"

  let decoder = {
    use id <- decode.field(0, decode.int)
    use public_id <- decode.field(1, uuid.decoder())
    decode.success(#(id, public_id))
  }

  use returned <- result.try(
    pog.query(sql)
    |> pog.parameter(pog.int(user_id))
    |> pog.parameter(pog.int(client_ref_id))
    |> pog.returning(decoder)
    |> pog.execute(db),
  )

  case returned.rows {
    [row, ..] -> Ok(row)
    [] -> Error(pog.ConnectionUnavailable)
  }
}

pub fn find_consent(
  db: pog.Connection,
  user_id: Int,
  client_ref_id: Int,
) -> Result(Option(#(Int, String, Set(Scope))), pog.QueryError) {
  let sql =
    "SELECT id, public_id, scopes
    FROM oidc_consents
    WHERE user_id = $1 AND client_ref_id = $2
    LIMIT 1"

  let decoder = {
    use id <- decode.field(0, decode.int)
    use public_id <- decode.field(1, uuid.decoder())
    use scopes <- decode.field(2, scopes_decoder())
    decode.success(#(id, public_id, scopes))
  }

  use returned <- result.map(
    pog.query(sql)
    |> pog.parameter(pog.int(user_id))
    |> pog.parameter(pog.int(client_ref_id))
    |> pog.returning(decoder)
    |> pog.execute(db),
  )

  case returned.rows {
    [row, ..] -> Some(row)
    [] -> None
  }
}

pub fn find_consent_for_audience(
  db: pog.Connection,
  user_id: Int,
  client_ref_id: Int,
  audience: String,
  default_issuer: String,
) -> Result(Option(#(Int, String, Set(Scope))), pog.QueryError) {
  case audience == default_issuer {
    True -> find_consent(db, user_id, client_ref_id)
    False -> {
      let sql =
        "SELECT
          con.id,
          con.public_id,
          ARRAY(
            SELECT DISTINCT unnest(g.scopes)
            FROM oidc_grants g
            WHERE g.consent_id = con.id
              AND g.audience = $3
              AND g.expires_at > NOW()
              AND (
                g.last_used_at IS NOT NULL
                OR NOT EXISTS (
                  SELECT 1 FROM oidc_auth_codes ac
                  WHERE ac.grant_id = g.id AND ac.used_at IS NULL
                )
              )
            ORDER BY 1
          )
        FROM oidc_consents con
        WHERE con.user_id = $1 AND con.client_ref_id = $2
        LIMIT 1"

      let decoder = {
        use id <- decode.field(0, decode.int)
        use public_id <- decode.field(1, uuid.decoder())
        use scopes <- decode.field(2, scopes_decoder())
        decode.success(#(id, public_id, scopes))
      }

      use returned <- result.map(
        pog.query(sql)
        |> pog.parameter(pog.int(user_id))
        |> pog.parameter(pog.int(client_ref_id))
        |> pog.parameter(pog.text(audience))
        |> pog.returning(decoder)
        |> pog.execute(db),
      )

      case returned.rows {
        [row, ..] -> Some(row)
        [] -> None
      }
    }
  }
}

pub fn create_grant(
  db: pog.Connection,
  consent_id: Int,
  scopes: Set(Scope),
  audience: String,
  user_agent: String,
  ttl_seconds: Int,
) -> Result(#(Int, String, Timestamp), pog.QueryError) {
  let clean_ua =
    user_agent
    |> string.trim
    |> string.slice(at_index: 0, length: max_user_agent_length)
  let effective_ttl = int.max(ttl_seconds, 1)
  let scope_strings = scope.to_sorted_strings(scopes)

  let sql =
    "INSERT INTO oidc_grants (
      consent_id,
      scopes,
      audience,
      user_agent,
      expires_at
    )
    VALUES ($1, $2, $3, $4, NOW() + ($5::bigint * INTERVAL '1 second'))
    RETURNING id, public_id, expires_at"

  let decoder = {
    use id <- decode.field(0, decode.int)
    use public_id <- decode.field(1, uuid.decoder())
    use expires_at <- decode.field(2, timestamptz_decoder())
    decode.success(#(id, public_id, expires_at))
  }

  use returned <- result.try(
    pog.query(sql)
    |> pog.parameter(pog.int(consent_id))
    |> pog.parameter(pog.array(pog.text, scope_strings))
    |> pog.parameter(pog.text(audience))
    |> pog.parameter(pog.text(clean_ua))
    |> pog.parameter(pog.int(effective_ttl))
    |> pog.returning(decoder)
    |> pog.execute(db),
  )

  case returned.rows {
    [row, ..] -> Ok(row)
    [] -> Error(pog.ConnectionUnavailable)
  }
}

pub fn list_consents_for_user(
  db: pog.Connection,
  user_id: Int,
) -> Result(List(ConsentInfo), pog.QueryError) {
  let sql =
    "SELECT
      con.id,
      con.public_id,
      con.user_id,
      con.client_ref_id,
      c.client_id,
      c.name,
      c.kind,
      con.scopes,
      con.created_at,
      con.updated_at
    FROM oidc_consents con
    INNER JOIN oidc_clients c ON c.id = con.client_ref_id
    WHERE con.user_id = $1
    ORDER BY con.updated_at DESC, con.id DESC"

  let decoder = {
    use id <- decode.field(0, decode.int)
    use public_id <- decode.field(1, uuid.decoder())
    use uid <- decode.field(2, decode.int)
    use client_ref_id <- decode.field(3, decode.int)
    use client_id <- decode.field(4, decode.string)
    use client_name <- decode.field(5, decode.string)
    use client_kind <- decode.field(6, kind_decoder())
    use scopes <- decode.field(7, scopes_decoder())
    use created_at <- decode.field(8, timestamptz_decoder())
    use updated_at <- decode.field(9, timestamptz_decoder())
    decode.success(ConsentInfo(
      id:,
      public_id:,
      user_id: uid,
      client_ref_id:,
      client_id:,
      client_name:,
      client_kind:,
      scopes:,
      created_at:,
      updated_at:,
    ))
  }

  pog.query(sql)
  |> pog.parameter(pog.int(user_id))
  |> pog.returning(decoder)
  |> pog.execute(db)
  |> result.map(fn(returned) { returned.rows })
}

pub fn list_active_grants_for_user(
  db: pog.Connection,
  user_id: Int,
) -> Result(List(GrantInfo), pog.QueryError) {
  let sql =
    "SELECT
      g.id,
      g.public_id,
      con.public_id,
      c.client_id,
      c.name,
      g.scopes,
      g.audience,
      g.user_agent,
      g.last_used_at,
      g.expires_at,
      g.created_at
    FROM oidc_grants g
    INNER JOIN oidc_consents con ON con.id = g.consent_id
    INNER JOIN oidc_clients c ON c.id = con.client_ref_id
    WHERE con.user_id = $1
      AND g.expires_at > NOW()
      AND (
        g.last_used_at IS NOT NULL
        OR NOT EXISTS (
          SELECT 1 FROM oidc_auth_codes ac
          WHERE ac.grant_id = g.id AND ac.used_at IS NULL
        )
      )
    ORDER BY g.created_at DESC, g.id DESC"

  let decoder = {
    use id <- decode.field(0, decode.int)
    use public_id <- decode.field(1, uuid.decoder())
    use consent_public_id <- decode.field(2, uuid.decoder())
    use client_id <- decode.field(3, decode.string)
    use client_name <- decode.field(4, decode.string)
    use scopes <- decode.field(5, scopes_decoder())
    use audience <- decode.field(6, decode.string)
    use user_agent <- decode.field(7, decode.string)
    use last_used_at <- decode.field(8, decode.optional(timestamptz_decoder()))
    use expires_at <- decode.field(9, timestamptz_decoder())
    use created_at <- decode.field(10, timestamptz_decoder())
    decode.success(GrantInfo(
      id:,
      public_id:,
      consent_public_id:,
      client_id:,
      client_name:,
      scopes:,
      audience:,
      user_agent:,
      last_used_at:,
      expires_at:,
      created_at:,
    ))
  }

  pog.query(sql)
  |> pog.parameter(pog.int(user_id))
  |> pog.returning(decoder)
  |> pog.execute(db)
  |> result.map(fn(returned) { returned.rows })
}

pub fn revoke_grant_by_public_id(
  db: pog.Connection,
  public_id: String,
  user_id: Int,
) -> Result(Option(String), pog.QueryError) {
  case uuid.normalize(public_id) {
    Error(_) -> Ok(None)
    Ok(normalized) -> {
      let sql =
        "DELETE FROM oidc_grants
        USING oidc_consents
        WHERE oidc_grants.consent_id = oidc_consents.id
          AND oidc_grants.public_id = $1::uuid
          AND oidc_consents.user_id = $2
        RETURNING oidc_grants.public_id"

      let decoder = {
        use gid <- decode.field(0, uuid.decoder())
        decode.success(gid)
      }

      use returned <- result.map(
        pog.query(sql)
        |> pog.parameter(pog.text(normalized))
        |> pog.parameter(pog.int(user_id))
        |> pog.returning(decoder)
        |> pog.execute(db),
      )

      case returned.rows {
        [gid, ..] -> Some(gid)
        [] -> None
      }
    }
  }
}

pub fn revoke_consent_by_public_id(
  db: pog.Connection,
  public_id: String,
  user_id: Int,
) -> Result(Option(List(String)), pog.QueryError) {
  case uuid.normalize(public_id) {
    Error(_) -> Ok(None)
    Ok(normalized) -> {
      let sql =
        "WITH target_consent AS (
          DELETE FROM oidc_consents
          USING oidc_clients
          WHERE oidc_consents.client_ref_id = oidc_clients.id
            AND oidc_consents.public_id = $1::uuid
            AND oidc_consents.user_id = $2
            AND oidc_clients.kind <> 'subordinate_bot'
          RETURNING oidc_consents.id
        ),
        revoked_grants AS (
          SELECT g.public_id
          FROM oidc_grants g
          INNER JOIN target_consent tc ON tc.id = g.consent_id
          WHERE g.expires_at > NOW()
        )
        SELECT tc.id, rg.public_id
        FROM target_consent tc
        LEFT JOIN revoked_grants rg ON TRUE"

      let decoder = {
        use cid <- decode.field(0, decode.int)
        use grant_public_id <- decode.field(1, decode.optional(uuid.decoder()))
        decode.success(#(cid, grant_public_id))
      }

      use returned <- result.map(
        pog.query(sql)
        |> pog.parameter(pog.text(normalized))
        |> pog.parameter(pog.int(user_id))
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

fn kind_decoder() -> decode.Decoder(client.Kind) {
  use raw <- decode.then(decode.string)
  case client.kind_from_string(raw) {
    Ok(kind) -> decode.success(kind)
    Error(_) -> decode.failure(client.SubordinateBot, "Kind")
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
