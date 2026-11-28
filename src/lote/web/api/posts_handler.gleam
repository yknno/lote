import gleam/bit_array
import gleam/dynamic/decode
import gleam/http
import gleam/http/request
import gleam/http/response
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import gleam/time/calendar
import gleam/time/timestamp.{type Timestamp}
import lote/db/post_repo.{type PostRow}
import lote/db/uuid
import lote/oidc.{type Oidc}
import lote/oidc/scope
import lote/realtime/pubsub.{type PubSub}
import lote/web/components/timeline
import lote/web/oidc/bearer
import wisp

const default_limit = 20

const max_limit = 50

pub fn handle_request(
  req: wisp.Request,
  segments: List(String),
  oidc_ctx: Oidc,
  post_pubsub: PubSub(timeline.PostEvent),
) -> wisp.Response {
  case req.method, segments {
    http.Get, [] -> handle_list(req, oidc_ctx)
    http.Post, [] -> handle_create(req, oidc_ctx, post_pubsub)
    _, [] -> json_method_not_allowed([http.Get, http.Head, http.Post])

    http.Get, [id] -> handle_show(req, id, oidc_ctx)
    http.Delete, [id] -> handle_delete(req, id, oidc_ctx, post_pubsub)
    _, [_] -> json_method_not_allowed([http.Get, http.Head, http.Delete])

    _, _ -> json_error(404, "not_found")
  }
}

fn handle_list(req: wisp.Request, oidc_ctx: Oidc) -> wisp.Response {
  use _principal <- bearer.authorize(
    req,
    oidc_ctx,
    scope.PostsRead,
    bearer.Read,
  )

  case parse_list_query(wisp.get_query(req)) {
    Error(_) -> json_error(400, "invalid_request")
    Ok(#(limit, before, after)) -> {
      let query_res = case before, after {
        Some(before_id), None ->
          post_repo.list_before(oidc_ctx.db, before_id, limit)
        None, Some(after_id) ->
          post_repo.list_after(oidc_ctx.db, after_id, limit)
        None, None -> post_repo.list_recent(oidc_ctx.db, limit)
        Some(_), Some(_) -> Ok([])
      }

      case query_res {
        Ok(rows) ->
          json.object([#("posts", json.array(rows, encode_post_row))])
          |> json.to_string
          |> wisp.json_response(200)
        Error(_) -> json_error(500, "internal_error")
      }
    }
  }
}

fn handle_show(req: wisp.Request, id: String, oidc_ctx: Oidc) -> wisp.Response {
  use _principal <- bearer.authorize(
    req,
    oidc_ctx,
    scope.PostsRead,
    bearer.Read,
  )

  case post_repo.find_by_id(oidc_ctx.db, id) {
    Ok(Some(row)) ->
      json.object([#("post", encode_post_row(row))])
      |> json.to_string
      |> wisp.json_response(200)
    Ok(None) -> json_error(404, "not_found")
    Error(_) -> json_error(500, "internal_error")
  }
}

fn handle_create(
  req: wisp.Request,
  oidc_ctx: Oidc,
  post_pubsub: PubSub(timeline.PostEvent),
) -> wisp.Response {
  use principal <- bearer.authorize(
    req,
    oidc_ctx,
    scope.PostsWrite,
    bearer.PostCreate,
  )

  let body_decoder = {
    use raw_body <- decode.field("body", decode.string)
    decode.success(raw_body)
  }

  use raw_body <- require_json_body(req, body_decoder)

  case post_repo.create(oidc_ctx.db, principal.user.id, raw_body) {
    Ok(created) -> {
      pubsub.publish(
        post_pubsub,
        timeline.Created(timeline.Post(
          id: created.id,
          user_id: principal.user.id,
          author_name: principal.user.name,
          body: created.body,
          created_at: created.created_at,
        )),
      )

      json.object([
        #(
          "post",
          encode_post_fields(
            created.id,
            principal.user.name,
            created.body,
            created.created_at,
          ),
        ),
      ])
      |> json.to_string
      |> wisp.json_response(201)
      |> response.set_header("location", "/posts/" <> created.id)
    }

    Error(post_repo.InvalidBody(_)) -> json_error(422, "invalid_body")
    Error(post_repo.QueryError(_)) -> json_error(500, "internal_error")
  }
}

fn handle_delete(
  req: wisp.Request,
  id: String,
  oidc_ctx: Oidc,
  post_pubsub: PubSub(timeline.PostEvent),
) -> wisp.Response {
  use principal <- bearer.authorize(
    req,
    oidc_ctx,
    scope.PostsDelete,
    bearer.Write,
  )

  case post_repo.delete(oidc_ctx.db, id, principal.user.id) {
    Ok(True) -> {
      pubsub.publish(post_pubsub, timeline.Deleted(string.lowercase(id)))
      wisp.no_content()
    }
    Ok(False) -> json_error(404, "not_found")
    Error(_) -> json_error(500, "internal_error")
  }
}

fn parse_list_query(
  query: List(#(String, String)),
) -> Result(#(Int, Option(String), Option(String)), Nil) {
  use raw_limit <- result.try(single_optional_param(query, "limit"))
  use raw_before <- result.try(single_optional_param(query, "before"))
  use raw_after <- result.try(single_optional_param(query, "after"))

  use limit <- result.try(case raw_limit {
    None -> Ok(default_limit)
    Some(val) ->
      case int.parse(val) {
        Ok(n) if n >= 1 && n <= max_limit -> Ok(n)
        _ -> Error(Nil)
      }
  })

  use before <- result.try(case raw_before {
    None -> Ok(None)
    Some(val) -> uuid.normalize(val) |> result.map(Some)
  })

  use after <- result.try(case raw_after {
    None -> Ok(None)
    Some(val) -> uuid.normalize(val) |> result.map(Some)
  })

  case before, after {
    Some(_), Some(_) -> Error(Nil)
    _, _ -> Ok(#(limit, before, after))
  }
}

fn single_optional_param(
  query: List(#(String, String)),
  key: String,
) -> Result(Option(String), Nil) {
  case list.key_filter(query, key) {
    [] -> Ok(None)
    [val] -> Ok(Some(val))
    _ -> Error(Nil)
  }
}

const max_json_payload_bytes = 65_536

fn require_json_body(
  req: wisp.Request,
  decoder: decode.Decoder(a),
  next: fn(a) -> wisp.Response,
) -> wisp.Response {
  case has_json_content_type(req) {
    False -> json_error(400, "invalid_request")
    True -> {
      let req = wisp.set_max_body_size(req, max_json_payload_bytes)
      case wisp.read_body_bits(req) {
        Error(_) -> json_error(413, "payload_too_large")
        Ok(bits) ->
          case bit_array.byte_size(bits) > max_json_payload_bytes {
            True -> json_error(413, "payload_too_large")
            False ->
              case bit_array.to_string(bits) {
                Error(_) -> json_error(400, "invalid_request")
                Ok(text) ->
                  case json.parse(text, decoder) {
                    Ok(parsed) -> next(parsed)
                    Error(_) -> json_error(400, "invalid_request")
                  }
              }
          }
      }
    }
  }
}

fn has_json_content_type(req: wisp.Request) -> Bool {
  case request.get_header(req, "content-type") {
    Error(_) -> False
    Ok(raw) -> {
      let media_type = case string.split_once(raw, ";") {
        Ok(#(base, _)) -> base
        Error(_) -> raw
      }
      string.lowercase(string.trim(media_type)) == "application/json"
    }
  }
}

fn encode_post_row(row: PostRow) -> json.Json {
  encode_post_fields(row.id, row.author_name, row.body, row.created_at)
}

fn encode_post_fields(
  id: String,
  author_name: String,
  body: String,
  created_at: Timestamp,
) -> json.Json {
  json.object([
    #("id", json.string(id)),
    #("author_name", json.string(author_name)),
    #("body", json.string(body)),
    #(
      "created_at",
      json.string(timestamp.to_rfc3339(created_at, calendar.utc_offset)),
    ),
  ])
}

fn json_method_not_allowed(methods: List(http.Method)) -> wisp.Response {
  let allowed =
    methods
    |> list.map(http.method_to_string)
    |> list.sort(string.compare)
    |> string.join(", ")
    |> string.uppercase

  json_error(405, "method_not_allowed")
  |> response.set_header("allow", allowed)
}

pub fn json_error(status: Int, code: String) -> wisp.Response {
  json.object([#("error", json.string(code))])
  |> json.to_string
  |> wisp.json_response(status)
}
