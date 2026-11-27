import gleam/http
import gleam/http/response
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import lote/auth.{type Auth}
import lote/auth/session
import lote/auth/user.{type AuthUser}
import lote/oidc.{type Oidc}
import lote/oidc/client
import lote/oidc/scope
import lote/web/csrf
import lote/web/http_rate_limit
import lote/web/settings/clients_view.{type RevealedSecret, RevealedSecret}
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

    http.Post, ["bots"] -> handle_create_bot(req, auth_ctx, oidc_ctx)
    _, ["bots"] -> wisp.method_not_allowed([http.Post])

    http.Post, ["apps"] -> handle_create_app(req, auth_ctx, oidc_ctx)
    _, ["apps"] -> wisp.method_not_allowed([http.Post])

    http.Post, [client_id, "secrets"] ->
      handle_create_secret(req, client_id, auth_ctx, oidc_ctx)
    _, [_, "secrets"] -> wisp.method_not_allowed([http.Post])

    http.Post, [client_id, "secrets", secret_public_id, "revoke"] ->
      handle_revoke_secret(req, client_id, secret_public_id, auth_ctx, oidc_ctx)
    _, [_, "secrets", _, "revoke"] -> wisp.method_not_allowed([http.Post])

    http.Post, [client_id, "delete"] ->
      handle_delete_client(req, client_id, auth_ctx, oidc_ctx)
    _, [_, "delete"] -> wisp.method_not_allowed([http.Post])

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
      render_clients_page(req, auth_ctx, oidc_ctx, active.user, None, None, 200)
  }
}

fn handle_create_bot(
  req: wisp.Request,
  auth_ctx: Auth,
  oidc_ctx: Oidc,
) -> wisp.Response {
  use form <- wisp.require_form(req)
  use _csrf_token <- csrf.require_form_token(
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

      let name = list.key_find(form.values, "name") |> result.unwrap("")
      let secret_label =
        list.key_find(form.values, "secret_label") |> result.unwrap("")
      let raw_scopes =
        list.filter_map(form.values, fn(pair) {
          case pair.0 == "scopes" {
            True -> Ok(pair.1)
            False -> Error(Nil)
          }
        })

      case scope.parse_list(raw_scopes) {
        Error(bad_scope) ->
          render_clients_page(
            req,
            auth_ctx,
            oidc_ctx,
            active.user,
            None,
            Some("Invalid scope: " <> bad_scope),
            422,
          )

        Ok(scopes) ->
          case
            client.create_subordinate_bot(
              oidc_ctx.db,
              active.user.id,
              name,
              scopes,
              secret_label,
              None,
            )
          {
            Ok(created_bot) -> {
              let revealed =
                RevealedSecret(
                  heading: "Subordinate bot created",
                  client_name: Some(created_bot.client.name),
                  client_id: created_bot.client.client_id,
                  secret_label: created_bot.secret.info.label,
                  raw_secret: created_bot.secret.secret,
                )
              render_clients_page(
                req,
                auth_ctx,
                oidc_ctx,
                active.user,
                Some(revealed),
                None,
                200,
              )
            }

            Error(client.InvalidInput(msg))
            | Error(client.InvalidScope(msg))
            | Error(client.InvalidRedirectUri(msg)) ->
              render_clients_page(
                req,
                auth_ctx,
                oidc_ctx,
                active.user,
                None,
                Some(msg),
                422,
              )

            Error(_) -> wisp.internal_server_error()
          }
      }
    }
  }
}

fn handle_create_app(
  req: wisp.Request,
  auth_ctx: Auth,
  oidc_ctx: Oidc,
) -> wisp.Response {
  use form <- wisp.require_form(req)
  use _csrf_token <- csrf.require_form_token(
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

      let name = list.key_find(form.values, "name") |> result.unwrap("")
      let confidential_res = case
        list.key_find(form.values, "client_type") |> result.unwrap("")
      {
        "confidential" -> Ok(True)
        "public" -> Ok(False)
        _ -> Error("Invalid client type")
      }
      let visibility_res =
        list.key_find(form.values, "visibility")
        |> result.unwrap("")
        |> client.visibility_from_string
        |> result.replace_error("Invalid visibility")
      let app_type_res =
        list.key_find(form.values, "application_type")
        |> result.unwrap("")
        |> client.application_type_from_string
        |> result.replace_error("Invalid application type")
      let redirect_uris = parse_redirect_uris_field(form.values)
      let raw_scopes =
        list.filter_map(form.values, fn(pair) {
          case pair.0 == "scopes" {
            True -> Ok(pair.1)
            False -> Error(Nil)
          }
        })
      let scopes_res =
        scope.parse_list(raw_scopes)
        |> result.map_error(fn(bad_scope) { "Invalid scope: " <> bad_scope })

      let parsed = {
        use confidential <- result.try(confidential_res)
        use visibility <- result.try(visibility_res)
        use application_type <- result.try(app_type_res)
        use scopes <- result.map(scopes_res)
        #(confidential, visibility, application_type, scopes)
      }

      case parsed {
        Error(err_msg) ->
          render_clients_page(
            req,
            auth_ctx,
            oidc_ctx,
            active.user,
            None,
            Some(err_msg),
            422,
          )

        Ok(#(confidential, visibility, application_type, scopes)) ->
          case
            client.create_app(
              oidc_ctx.db,
              active.user.id,
              name,
              confidential,
              visibility,
              application_type,
              redirect_uris,
              scopes,
            )
          {
            Ok(#(created_client, Some(secret))) -> {
              let revealed =
                RevealedSecret(
                  heading: "Confidential OAuth app created",
                  client_name: Some(created_client.name),
                  client_id: created_client.client_id,
                  secret_label: secret.info.label,
                  raw_secret: secret.secret,
                )
              render_clients_page(
                req,
                auth_ctx,
                oidc_ctx,
                active.user,
                Some(revealed),
                None,
                200,
              )
            }

            Ok(#(_created_client, None)) ->
              wisp.redirect(to: "/settings/clients")

            Error(client.InvalidInput(msg))
            | Error(client.InvalidScope(msg))
            | Error(client.InvalidRedirectUri(msg)) ->
              render_clients_page(
                req,
                auth_ctx,
                oidc_ctx,
                active.user,
                None,
                Some(msg),
                422,
              )

            Error(_) -> wisp.internal_server_error()
          }
      }
    }
  }
}

fn parse_redirect_uris_field(values: List(#(String, String))) -> List(String) {
  values
  |> list.filter_map(fn(pair) {
    case pair.0 == "redirect_uris" {
      True -> Ok(pair.1)
      False -> Error(Nil)
    }
  })
  |> list.flat_map(fn(raw) { string.split(raw, "\n") })
  |> list.map(string.trim)
  |> list.filter(fn(uri) { uri != "" })
}

fn handle_create_secret(
  req: wisp.Request,
  client_id: String,
  auth_ctx: Auth,
  oidc_ctx: Oidc,
) -> wisp.Response {
  use form <- wisp.require_form(req)
  use _csrf_token <- csrf.require_form_token(
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

      let label = list.key_find(form.values, "label") |> result.unwrap("")
      case
        client.create_secret(
          oidc_ctx.db,
          active.user.id,
          client_id,
          label,
          None,
        )
      {
        Ok(created_secret) -> {
          let revealed =
            RevealedSecret(
              heading: "New client secret generated",
              client_name: None,
              client_id:,
              secret_label: created_secret.info.label,
              raw_secret: created_secret.secret,
            )
          render_clients_page(
            req,
            auth_ctx,
            oidc_ctx,
            active.user,
            Some(revealed),
            None,
            200,
          )
        }

        Error(client.SecretLimitExceeded) ->
          render_clients_page(
            req,
            auth_ctx,
            oidc_ctx,
            active.user,
            None,
            Some(
              "Maximum active secrets per client (5) reached. Revoke an unused secret first.",
            ),
            422,
          )

        Error(client.InvalidInput(msg)) ->
          render_clients_page(
            req,
            auth_ctx,
            oidc_ctx,
            active.user,
            None,
            Some(msg),
            422,
          )

        Error(client.NotFound) -> wisp.not_found()
        Error(_) -> wisp.internal_server_error()
      }
    }
  }
}

fn handle_revoke_secret(
  req: wisp.Request,
  client_id: String,
  secret_public_id: String,
  auth_ctx: Auth,
  oidc_ctx: Oidc,
) -> wisp.Response {
  use form <- wisp.require_form(req)
  use _csrf_token <- csrf.require_form_token(
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
        client.revoke_secret_returning_grants(
          oidc_ctx.db,
          active.user.id,
          client_id,
          secret_public_id,
        )
      {
        Ok(Some(revoked_grant_ids)) -> {
          oidc.publish_revocations(oidc_ctx, revoked_grant_ids)
          wisp.redirect(to: "/settings/clients")
        }
        Ok(None) -> wisp.not_found()
        Error(_) -> wisp.internal_server_error()
      }
    }
  }
}

fn handle_delete_client(
  req: wisp.Request,
  client_id: String,
  auth_ctx: Auth,
  oidc_ctx: Oidc,
) -> wisp.Response {
  use form <- wisp.require_form(req)
  use _csrf_token <- csrf.require_form_token(
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

      case client.delete_for_owner(oidc_ctx.db, active.user.id, client_id) {
        Ok(Some(revoked_grant_ids)) -> {
          oidc.publish_revocations(oidc_ctx, revoked_grant_ids)
          wisp.redirect(to: "/settings/clients")
        }
        Ok(None) -> wisp.not_found()
        Error(_) -> wisp.internal_server_error()
      }
    }
  }
}

fn render_clients_page(
  req: wisp.Request,
  auth_ctx: Auth,
  oidc_ctx: Oidc,
  current_user: AuthUser,
  revealed: Option(RevealedSecret),
  error: Option(String),
  status: Int,
) -> wisp.Response {
  case client.list_for_owner(oidc_ctx.db, current_user.id) {
    Ok(clients) -> {
      let #(csrf_token, should_set_cookie) =
        csrf.ensure_token(req, auth_ctx.secret_key_base)

      clients_view.index_page(
        current_user,
        clients,
        revealed,
        error,
        csrf_token,
        status,
      )
      |> response.set_header("cache-control", "no-store")
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
