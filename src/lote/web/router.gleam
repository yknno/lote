import gleam/http
import gleam/http/request
import gleam/http/response
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import lote/auth.{type Auth}
import lote/auth/session
import lote/db/post_repo
import lote/oidc.{type Oidc}
import lote/realtime/pubsub.{type PubSub}
import lote/web/api/posts_handler
import lote/web/auth/handler as auth_handler
import lote/web/components/timeline
import lote/web/csrf
import lote/web/http_rate_limit
import lote/web/oidc/handler as oidc_handler
import lote/web/post/view as post_view
import lote/web/sessions/handler as sessions_handler
import lote/web/settings/clients_handler
import lustre/attribute
import lustre/element
import lustre/element/html
import lustre/server_component
import wisp.{type Request, type Response}

const default_cache_control = "no-store"

const static_cache_control = "public, no-cache"

pub fn handle_request(
  req: Request,
  auth_ctx: Auth,
  post_pubsub: PubSub(timeline.PostEvent),
) -> Response {
  handle_request_with_ip(req, auth_ctx, post_pubsub, "127.0.0.1")
}

pub fn handle_request_with_ip(
  req: Request,
  auth_ctx: Auth,
  post_pubsub: PubSub(timeline.PostEvent),
  client_ip: String,
) -> Response {
  handle_request_with_oidc(
    req,
    auth_ctx,
    oidc.from_auth(auth_ctx),
    post_pubsub,
    client_ip,
  )
}

pub fn handle_request_with_oidc(
  req: Request,
  auth_ctx: Auth,
  oidc_ctx: Oidc,
  post_pubsub: PubSub(timeline.PostEvent),
  client_ip: String,
) -> Response {
  use req <- middleware(req)

  case req.method, wisp.path_segments(req) {
    _, [] -> {
      let #(csrf_token, should_set_cookie) =
        csrf.ensure_token(req, auth_ctx.secret_key_base)
      wisp.html_response(index_html(), 200)
      |> csrf.attach_cookie(
        req,
        csrf_token,
        auth_ctx.secret_key_base,
        should_set_cookie,
      )
    }
    http.Get, ["posts", id] ->
      case post_repo.find_by_id(auth_ctx.db, id) {
        Ok(Some(post)) -> {
          let current_user =
            session.current_user(req, auth_ctx.db, auth_ctx.secret_key_base)
          case current_user {
            Some(u) if u.id == post.user_id -> {
              let #(csrf_token, should_set_cookie) =
                csrf.ensure_token(req, auth_ctx.secret_key_base)
              post_view.show_page(post, Some(csrf_token))
              |> csrf.attach_cookie(
                req,
                csrf_token,
                auth_ctx.secret_key_base,
                should_set_cookie,
              )
            }
            _ -> post_view.show_page(post, None)
          }
        }
        Ok(None) -> wisp.not_found()
        Error(_) -> wisp.internal_server_error()
      }
    _, ["posts", _] -> wisp.method_not_allowed([http.Get, http.Head])
    http.Post, ["posts", id, "delete"] -> {
      use form <- wisp.require_form(req)
      use _token <- csrf.require_form_token(
        req,
        form.values,
        auth_ctx.secret_key_base,
      )
      case session.current_user(req, auth_ctx.db, auth_ctx.secret_key_base) {
        None -> wisp.response(401)
        Some(auth_user) -> {
          use <- http_rate_limit.require_user_write(
            auth_ctx.rate_limiter,
            auth_user.id,
          )
          case post_repo.delete(auth_ctx.db, id, auth_user.id) {
            Ok(True) -> {
              pubsub.publish(
                post_pubsub,
                timeline.Deleted(string.lowercase(id)),
              )
              wisp.redirect(to: "/")
            }
            Ok(False) -> wisp.not_found()
            Error(_) -> wisp.internal_server_error()
          }
        }
      }
    }
    _, ["posts", _, "delete"] -> wisp.method_not_allowed([http.Post])
    _, ["sessions", ..rest] ->
      sessions_handler.handle_request(req, rest, auth_ctx)
    _, ["settings", "clients", ..rest] ->
      clients_handler.handle_request(req, rest, auth_ctx, oidc_ctx)
    _, ["auth", ..rest] ->
      auth_handler.handle_request(req, rest, auth_ctx, client_ip)
    _, ["oidc", ..rest] ->
      oidc_handler.handle_request(req, rest, oidc_ctx, client_ip)
    _, ["api", "v1", "posts", ..rest] ->
      posts_handler.handle_request(req, rest, oidc_ctx, post_pubsub, client_ip)
    _, ["api", ..] -> posts_handler.json_error(404, "not_found")
    _, ["health"] -> wisp.response(200) |> wisp.string_body("ok")
    _, _ -> wisp.not_found()
  }
}

fn index_html() -> String {
  html.html([attribute.lang("ja"), attribute.class("bg-white")], [
    html.head([], [
      html.meta([attribute.charset("utf-8")]),
      html.meta([
        attribute.name("viewport"),
        attribute.content("width=device-width, initial-scale=1"),
      ]),
      html.title([], "lote"),
      html.link([
        attribute.rel("stylesheet"),
        attribute.href("/static/app.css"),
      ]),
      server_component.script(),
      html.script(
        [attribute.type_("module"), attribute.src("/static/lote-time.js")],
        "",
      ),
      html.script(
        [attribute.type_("module"), attribute.src("/static/lote-sentinel.js")],
        "",
      ),
      html.script(
        [attribute.type_("module"), attribute.src("/static/lote-composer.js")],
        "",
      ),
    ]),
    html.body([attribute.class("min-h-screen bg-white text-neutral-950")], [
      server_component.element([server_component.route("/ws")], []),
    ]),
  ])
  |> element.to_document_string
}

fn middleware(
  req: Request,
  handle_request: fn(Request) -> Response,
) -> Response {
  let req = wisp.method_override(req)
  use <- wisp.log_request(req)
  {
    use <- wisp.rescue_crashes
    use req <- wisp.handle_head(req)
    use req <- apply_origin_or_strip_cookies(req)

    let static_dir = case wisp.priv_directory("lote") {
      Ok(priv) -> priv <> "/static"
      Error(_) -> "priv/static"
    }
    serve_static_with_cache(req, static_dir, fn() {
      handle_request(req)
      |> ensure_cache_control(default_cache_control)
    })
  }
  |> ensure_cache_control(default_cache_control)
}

fn apply_origin_or_strip_cookies(
  req: Request,
  next: fn(Request) -> Response,
) -> Response {
  case is_cookieless_route(wisp.path_segments(req)) {
    True -> {
      let headers =
        list.filter(req.headers, fn(h) { string.lowercase(h.0) != "cookie" })
      next(request.Request(..req, headers:))
    }
    False -> wisp.csrf_known_header_protection(req, next)
  }
}

fn is_cookieless_route(segments: List(String)) -> Bool {
  case segments {
    ["oidc", "token"]
    | ["oidc", "revoke"]
    | ["oidc", "introspect"]
    | ["api", ..] -> True
    _ -> False
  }
}

fn serve_static_with_cache(
  req: Request,
  static_dir: String,
  next: fn() -> Response,
) -> Response {
  let resp = wisp.serve_static(req, under: "/static", from: static_dir, next:)
  case resp.status {
    200 | 206 | 304 -> ensure_cache_control(resp, static_cache_control)
    _ -> resp
  }
}

fn ensure_cache_control(resp: Response, value: String) -> Response {
  case response.get_header(resp, "cache-control") {
    Ok(_) -> resp
    Error(_) -> response.set_header(resp, "cache-control", value)
  }
}
