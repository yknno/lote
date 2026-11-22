import gleam/http
import gleam/list
import gleam/option.{None, Some}
import lote/auth.{type Auth}
import lote/auth/session
import lote/realtime/pubsub
import lote/web/csrf
import lote/web/sessions/view
import wisp

pub fn handle_request(
  req: wisp.Request,
  segments: List(String),
  auth_ctx: Auth,
) -> wisp.Response {
  case req.method, segments {
    http.Get, [] -> handle_index(req, auth_ctx)
    _, [] -> wisp.method_not_allowed([http.Get, http.Head])

    http.Post, ["revoke-others"] -> handle_revoke_others(req, auth_ctx)
    _, ["revoke-others"] -> wisp.method_not_allowed([http.Post])

    http.Post, [public_id, "revoke"] ->
      handle_revoke_one(req, public_id, auth_ctx)
    _, [_, "revoke"] -> wisp.method_not_allowed([http.Post])

    _, _ -> wisp.not_found()
  }
}

fn handle_index(req: wisp.Request, auth_ctx: Auth) -> wisp.Response {
  case session.current_session(req, auth_ctx.db, auth_ctx.secret_key_base) {
    None -> wisp.redirect(to: "/auth/login")
    Some(active) ->
      case
        session.list_active_for_user(auth_ctx.db, active.user.id, active.id)
      {
        Ok(sessions) -> {
          let #(csrf_token, should_set_cookie) =
            csrf.ensure_token(req, auth_ctx.secret_key_base)
          view.index_page(active.user, sessions, csrf_token)
          |> csrf.attach_cookie(
            req,
            csrf_token,
            auth_ctx.secret_key_base,
            should_set_cookie,
          )
        }
        Error(_) -> wisp.internal_server_error()
      }
  }
}

fn handle_revoke_one(
  req: wisp.Request,
  public_id: String,
  auth_ctx: Auth,
) -> wisp.Response {
  use form <- wisp.require_form(req)
  use _token <- csrf.require_form_token(
    req,
    form.values,
    auth_ctx.secret_key_base,
  )

  case session.current_session(req, auth_ctx.db, auth_ctx.secret_key_base) {
    None -> wisp.response(401)
    Some(active) ->
      case session.revoke_by_public_id(auth_ctx.db, public_id, active.user.id) {
        Ok(Some(revoked_id)) -> {
          pubsub.publish(auth_ctx.session_revocations, revoked_id)
          case revoked_id == active.id {
            True ->
              wisp.redirect(to: "/")
              |> session.clear_cookie(req, auth_ctx.secret_key_base)
              |> csrf.rotate_cookie(req, auth_ctx.secret_key_base)
            False -> wisp.redirect(to: "/sessions")
          }
        }
        Ok(None) -> wisp.not_found()
        Error(_) -> wisp.internal_server_error()
      }
  }
}

fn handle_revoke_others(req: wisp.Request, auth_ctx: Auth) -> wisp.Response {
  use form <- wisp.require_form(req)
  use _token <- csrf.require_form_token(
    req,
    form.values,
    auth_ctx.secret_key_base,
  )

  case session.current_session(req, auth_ctx.db, auth_ctx.secret_key_base) {
    None -> wisp.response(401)
    Some(active) ->
      case session.revoke_others(auth_ctx.db, active.user.id, active.id) {
        Ok(revoked_ids) -> {
          list.each(revoked_ids, pubsub.publish(auth_ctx.session_revocations, _))
          wisp.redirect(to: "/sessions")
        }
        Error(_) -> wisp.internal_server_error()
      }
  }
}
