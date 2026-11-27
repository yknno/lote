import gleam/http
import gleam/http/response
import gleam/option.{None, Some}
import lote/auth.{type Auth}
import lote/auth/session
import lote/oidc.{type Oidc}
import lote/oidc/grant
import lote/web/csrf
import lote/web/http_rate_limit
import lote/web/settings/grants_view
import wisp

pub fn handle_request(
  req: wisp.Request,
  segments: List(String),
  auth_ctx: Auth,
  oidc_ctx: Oidc,
) -> wisp.Response {
  case req.method, segments {
    http.Get, [] -> handle_index(req, auth_ctx, oidc_ctx)
    _, [] -> wisp.method_not_allowed([http.Get, http.Head])

    http.Post, ["consents", consent_public_id, "revoke"] ->
      handle_revoke_consent(req, consent_public_id, auth_ctx, oidc_ctx)
    _, ["consents", _, "revoke"] -> wisp.method_not_allowed([http.Post])

    http.Post, [grant_public_id, "revoke"] ->
      handle_revoke_grant(req, grant_public_id, auth_ctx, oidc_ctx)
    _, [_, "revoke"] -> wisp.method_not_allowed([http.Post])

    _, _ -> wisp.not_found()
  }
}

fn handle_index(
  req: wisp.Request,
  auth_ctx: Auth,
  oidc_ctx: Oidc,
) -> wisp.Response {
  case session.current_session(req, auth_ctx.db, auth_ctx.secret_key_base) {
    None -> wisp.redirect(to: "/auth/login")
    Some(active) ->
      case
        grant.list_consents_for_user(oidc_ctx.db, active.user.id),
        grant.list_active_grants_for_user(oidc_ctx.db, active.user.id)
      {
        Ok(consents), Ok(active_grants) -> {
          let #(csrf_token, should_set_cookie) =
            csrf.ensure_token(req, auth_ctx.secret_key_base)

          grants_view.index_page(
            active.user,
            consents,
            active_grants,
            csrf_token,
          )
          |> response.set_header("cache-control", "no-store")
          |> csrf.attach_cookie(
            req,
            csrf_token,
            auth_ctx.secret_key_base,
            should_set_cookie,
          )
        }
        _, _ -> wisp.internal_server_error()
      }
  }
}

fn handle_revoke_consent(
  req: wisp.Request,
  consent_public_id: String,
  auth_ctx: Auth,
  oidc_ctx: Oidc,
) -> wisp.Response {
  use form <- wisp.require_form(req)
  use _csrf <- csrf.require_form_token(
    req,
    form.values,
    auth_ctx.secret_key_base,
  )

  case session.current_session(req, auth_ctx.db, auth_ctx.secret_key_base) {
    None -> wisp.response(401)
    Some(active) -> {
      use <- http_rate_limit.require_user_write(
        auth_ctx.rate_limiter,
        active.user.id,
      )

      case
        grant.revoke_consent_by_public_id(
          oidc_ctx.db,
          consent_public_id,
          active.user.id,
        )
      {
        Ok(Some(revoked_grant_ids)) -> {
          oidc.publish_revocations(oidc_ctx, revoked_grant_ids)
          wisp.redirect(to: "/settings/grants")
        }
        Ok(None) -> wisp.not_found()
        Error(_) -> wisp.internal_server_error()
      }
    }
  }
}

fn handle_revoke_grant(
  req: wisp.Request,
  grant_public_id: String,
  auth_ctx: Auth,
  oidc_ctx: Oidc,
) -> wisp.Response {
  use form <- wisp.require_form(req)
  use _csrf <- csrf.require_form_token(
    req,
    form.values,
    auth_ctx.secret_key_base,
  )

  case session.current_session(req, auth_ctx.db, auth_ctx.secret_key_base) {
    None -> wisp.response(401)
    Some(active) -> {
      use <- http_rate_limit.require_user_write(
        auth_ctx.rate_limiter,
        active.user.id,
      )

      case
        grant.revoke_grant_by_public_id(
          oidc_ctx.db,
          grant_public_id,
          active.user.id,
        )
      {
        Ok(Some(gid)) -> {
          oidc.publish_revocations(oidc_ctx, [gid])
          wisp.redirect(to: "/settings/grants")
        }
        Ok(None) -> wisp.not_found()
        Error(_) -> wisp.internal_server_error()
      }
    }
  }
}
