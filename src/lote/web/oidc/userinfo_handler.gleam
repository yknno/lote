import gleam/bit_array
import gleam/http
import gleam/http/request
import gleam/http/response
import gleam/json
import gleam/list
import gleam/string
import gleam/uri
import lote/oidc.{type Oidc}
import lote/oidc/scope
import lote/web/oidc/bearer
import lote/web/oidc/discovery_handler
import wisp

const max_form_bytes = 16_384

pub fn handle_request(req: wisp.Request, oidc_ctx: Oidc) -> wisp.Response {
  let is_head = request.get_header(req, "x-original-method") == Ok("HEAD")
  let resp = case req.method, is_head {
    _, True -> wisp.method_not_allowed([http.Get, http.Post])
    http.Get, False | http.Post, False -> handle_userinfo(req, oidc_ctx)
    _, False -> wisp.method_not_allowed([http.Get, http.Post])
  }

  with_no_store_headers(resp)
}

fn handle_userinfo(req: wisp.Request, oidc_ctx: Oidc) -> wisp.Response {
  case has_query_access_token(req) {
    True -> invalid_request_response(oidc_ctx.issuer)
    False -> {
      use principal <- bearer.authorize(
        req,
        oidc_ctx,
        scope.OpenId,
        bearer.Read,
      )
      case validate_post_body_without_access_token(req) {
        Error(Nil) -> invalid_request_response(oidc_ctx.issuer)
        Ok(Nil) -> {
          let claims = case oidc.has_scope(principal, scope.Profile) {
            True -> [
              #("sub", json.string(principal.sub)),
              #("name", json.string(principal.user.name)),
            ]
            False -> [#("sub", json.string(principal.sub))]
          }

          json.object(claims)
          |> json.to_string
          |> wisp.json_response(200)
        }
      }
    }
  }
}

fn has_query_access_token(req: wisp.Request) -> Bool {
  case list.key_find(wisp.get_query(req), "access_token") {
    Ok(_) -> True
    Error(_) -> False
  }
}

fn validate_post_body_without_access_token(
  req: wisp.Request,
) -> Result(Nil, Nil) {
  case req.method, has_form_urlencoded_content_type(req) {
    http.Post, True -> {
      let req = wisp.set_max_body_size(req, max_form_bytes)
      case wisp.read_body_bits(req) {
        Error(_) -> Error(Nil)
        Ok(bits) ->
          case bit_array.to_string(bits) {
            Error(_) -> Error(Nil)
            Ok(body_str) ->
              case uri.parse_query(body_str) {
                Error(_) -> Error(Nil)
                Ok(values) ->
                  case list.key_find(values, "access_token") {
                    Ok(_) -> Error(Nil)
                    Error(_) -> Ok(Nil)
                  }
              }
          }
      }
    }
    _, _ -> Ok(Nil)
  }
}

fn has_form_urlencoded_content_type(req: wisp.Request) -> Bool {
  case request.get_header(req, "content-type") {
    Error(_) -> False
    Ok(raw) -> {
      let media_type = case string.split_once(raw, ";") {
        Ok(#(base, _)) -> base
        Error(_) -> raw
      }
      string.lowercase(string.trim(media_type))
      == "application/x-www-form-urlencoded"
    }
  }
}

fn invalid_request_response(issuer: String) -> wisp.Response {
  let meta_url = discovery_handler.resource_metadata_url(issuer)
  json.object([#("error", json.string("invalid_request"))])
  |> json.to_string
  |> wisp.json_response(400)
  |> response.set_header(
    "www-authenticate",
    "Bearer realm=\"lote\", error=\"invalid_request\", resource_metadata=\""
      <> meta_url
      <> "\"",
  )
}

fn with_no_store_headers(resp: wisp.Response) -> wisp.Response {
  resp
  |> response.set_header("cache-control", "no-store")
  |> response.set_header("pragma", "no-cache")
}
