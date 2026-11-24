import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/set.{type Set}
import lote/auth.{type Auth}
import lote/auth/user.{type AuthUser}
import lote/oidc/scope.{type Scope}
import lote/rate_limit.{type Limiter}
import lote/realtime/pubsub.{type PubSub}
import pog

pub const default_issuer = "http://localhost:8080"

pub type Oidc {
  Oidc(
    db: pog.Connection,
    issuer: String,
    grant_revocations: Option(PubSub(String)),
    rate_limiter: Limiter,
  )
}

pub type Principal {
  Principal(
    user: AuthUser,
    sub: String,
    client_id: String,
    grant_public_id: String,
    scopes: Set(Scope),
    audience: String,
  )
}

pub fn new(
  db: pog.Connection,
  issuer: String,
  grant_revocations: PubSub(String),
  rate_limiter: Limiter,
) -> Oidc {
  Oidc(db:, issuer:, grant_revocations: Some(grant_revocations), rate_limiter:)
}

pub fn from_auth(auth_ctx: Auth) -> Oidc {
  Oidc(
    db: auth_ctx.db,
    issuer: default_issuer,
    grant_revocations: None,
    rate_limiter: auth_ctx.rate_limiter,
  )
}

pub fn publish_revocation(oidc: Oidc, grant_public_id: String) -> Nil {
  case oidc.grant_revocations {
    Some(subject) -> pubsub.publish(subject, grant_public_id)
    None -> Nil
  }
}

pub fn publish_revocations(oidc: Oidc, grant_public_ids: List(String)) -> Nil {
  case oidc.grant_revocations {
    Some(subject) ->
      list.each(grant_public_ids, fn(id) { pubsub.publish(subject, id) })
    None -> Nil
  }
}

pub fn has_scope(principal: Principal, required: Scope) -> Bool {
  set.contains(principal.scopes, required)
}
