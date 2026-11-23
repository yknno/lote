import gleam/bytes_tree
import gleam/erlang/process.{type Subject}
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/otp/static_supervisor as supervisor
import gleam/result
import lote/auth.{type Auth, Auth, Password}
import lote/auth/session
import lote/auth/session_cleanup
import lote/config
import lote/db/pool
import lote/realtime/pubsub.{type PubSub}
import lote/web/components/timeline
import lote/web/csrf
import lote/web/origin
import lote/web/router
import lustre
import lustre/server_component
import mist.{type Connection, type ResponseData}
import pog
import wisp
import wisp/wisp_mist

pub fn main() -> Nil {
  wisp.configure_logger()

  let cfg = config.load()
  let db_pool_name = process.new_name("lote_db")
  let db_config = pool.config(db_pool_name, cfg.database_url)
  let db = pog.named_connection(db_pool_name)

  let methods =
    list.filter_map(cfg.auth_adapters, fn(name) {
      case name {
        "password" -> Ok(Password)
        other -> {
          wisp.log_warning(
            "Unknown AUTH_ADAPTERS entry \"" <> other <> "\", ignoring",
          )
          Error(Nil)
        }
      }
    })

  let session_revocations_name = process.new_name("lote_session_revocations")
  let session_revocations = process.named_subject(session_revocations_name)
  let auth_ctx =
    Auth(
      db:,
      secret_key_base: cfg.secret_key_base,
      methods:,
      session_revocations:,
    )

  let post_pubsub_name = process.new_name("lote_post_pubsub")
  let post_pubsub = process.named_subject(post_pubsub_name)

  let http_server =
    handler(db, post_pubsub, auth_ctx)
    |> mist.new
    |> mist.bind("0.0.0.0")
    |> mist.port(cfg.port)
    |> mist.supervised

  let assert Ok(_) =
    supervisor.new(supervisor.OneForOne)
    |> supervisor.add(pool.supervised(db_config))
    |> supervisor.add(pubsub.supervised(
      session_revocations_name,
      session_revocations_adapter(cfg.pubsub_adapter, db, cfg.database_url),
    ))
    |> supervisor.add(pubsub.supervised(
      post_pubsub_name,
      post_pubsub_adapter(cfg.pubsub_adapter, db, cfg.database_url),
    ))
    |> supervisor.add(session_cleanup.supervised(
      db,
      session_revocations,
      session_cleanup.default_interval_ms,
      session_cleanup.default_batch_limit,
    ))
    |> supervisor.add(http_server)
    |> supervisor.start

  process.sleep_forever()
}

pub const session_revocations_channel = "lote_session_revocations"

pub const post_events_channel = "lote_post_events"

pub fn session_revocations_adapter(
  adapter_kind: config.PubSubAdapter,
  db: pog.Connection,
  database_url: String,
) -> pubsub.Adapter(String) {
  case adapter_kind {
    config.MemoryPubSub -> pubsub.Memory
    config.PostgresPubSub ->
      pubsub.Postgres(
        db:,
        database_url:,
        channel: session_revocations_channel,
        encode: fn(id) { id },
        decode: fn(raw) {
          case raw {
            "" -> Error(Nil)
            id -> Ok(id)
          }
        },
      )
  }
}

pub fn post_pubsub_adapter(
  adapter_kind: config.PubSubAdapter,
  db: pog.Connection,
  database_url: String,
) -> pubsub.Adapter(timeline.PostEvent) {
  case adapter_kind {
    config.MemoryPubSub -> pubsub.Memory
    config.PostgresPubSub ->
      pubsub.Postgres(
        db:,
        database_url:,
        channel: post_events_channel,
        encode: timeline.encode_post_event,
        decode: timeline.decode_post_event(db, _),
      )
  }
}

pub fn start_session_revocations_pubsub(
  adapter_kind: config.PubSubAdapter,
  db: pog.Connection,
  database_url: String,
) {
  session_revocations_adapter(adapter_kind, db, database_url)
  |> pubsub.start_with_adapter
}

pub fn start_post_pubsub(
  adapter_kind: config.PubSubAdapter,
  db: pog.Connection,
  database_url: String,
) {
  post_pubsub_adapter(adapter_kind, db, database_url)
  |> pubsub.start_with_adapter
}

pub fn handler(
  db: pog.Connection,
  post_pubsub: PubSub(timeline.PostEvent),
  auth_ctx: Auth,
) -> fn(Request(Connection)) -> Response(ResponseData) {
  let http_handler =
    wisp_mist.handler(
      router.handle_request(_, auth_ctx, post_pubsub),
      auth_ctx.secret_key_base,
    )

  fn(req: Request(Connection)) -> Response(ResponseData) {
    case request.path_segments(req) {
      ["ws"] -> serve_timeline_ws(req, db, post_pubsub, auth_ctx)
      _ -> http_handler(req)
    }
  }
}

pub type WsMsg {
  ComponentMessage(server_component.ClientMessage(timeline.Msg))
  SessionRevoked(String)
}

pub type WsState {
  WsState(
    component: lustre.Runtime(timeline.Msg),
    self: Subject(server_component.ClientMessage(timeline.Msg)),
    session_id: Option(String),
  )
}

fn serve_timeline_ws(
  req: Request(Connection),
  db: pog.Connection,
  post_pubsub: PubSub(timeline.PostEvent),
  auth_ctx: Auth,
) -> Response(ResponseData) {
  case origin.verify_same_origin(req) {
    False ->
      response.new(403)
      |> response.set_header("cache-control", "no-store")
      |> response.set_body(mist.Bytes(bytes_tree.from_string("Forbidden")))

    True ->
      mist.websocket(
        request: req,
        on_init: fn(_conn) { ws_init(req, db, post_pubsub, auth_ctx) },
        handler: fn(state: WsState, msg, conn) {
          ws_handle_message(state, msg, fn(payload) {
            let _ = mist.send_text_frame(conn, payload)
            Nil
          })
        },
        on_close: ws_close,
      )
  }
}

pub fn ws_init(
  req: Request(body),
  db: pog.Connection,
  post_pubsub: PubSub(timeline.PostEvent),
  auth_ctx: Auth,
) -> #(WsState, Option(process.Selector(WsMsg))) {
  let revocation_sub = process.new_subject()
  let candidate_session_id = session.session_id(req, auth_ctx.secret_key_base)
  case candidate_session_id {
    Some(_) -> pubsub.subscribe(auth_ctx.session_revocations, revocation_sub)
    None -> Nil
  }

  let active_session =
    session.current_session(req, auth_ctx.db, auth_ctx.secret_key_base)
  let #(current_user, session_id, has_revocation_sub) = case active_session {
    Some(active) -> #(Some(active.user), Some(active.id), True)
    None -> {
      case candidate_session_id {
        Some(_) ->
          pubsub.unsubscribe(auth_ctx.session_revocations, revocation_sub)
        None -> Nil
      }
      #(None, None, False)
    }
  }

  let csrf_token =
    csrf.read_token(req, auth_ctx.secret_key_base)
    |> result.unwrap("")
  let flags =
    timeline.Flags(db:, pubsub: post_pubsub, user: current_user, csrf_token:)
  let assert Ok(component) =
    lustre.start_server_component(timeline.app(), flags)
  let self = process.new_subject()
  let selector =
    process.new_selector()
    |> process.select_map(self, ComponentMessage)
  let selector = case has_revocation_sub {
    True ->
      selector
      |> process.select_map(revocation_sub, SessionRevoked)
    False -> selector
  }

  server_component.register_subject(self)
  |> lustre.send(to: component)

  #(WsState(component:, self:, session_id:), Some(selector))
}

pub fn ws_handle_message(
  state: WsState,
  msg: mist.WebsocketMessage(WsMsg),
  send_text: fn(String) -> Nil,
) -> mist.Next(WsState, WsMsg) {
  case msg {
    mist.Text(text) -> {
      case json.parse(text, server_component.runtime_message_decoder()) {
        Ok(runtime_msg) -> lustre.send(state.component, runtime_msg)
        Error(_) -> Nil
      }
      mist.continue(state)
    }

    mist.Custom(ComponentMessage(client_msg)) -> {
      let payload =
        client_msg
        |> server_component.client_message_to_json
        |> json.to_string
      send_text(payload)
      mist.continue(state)
    }

    mist.Custom(SessionRevoked(revoked_id)) ->
      case state.session_id {
        Some(sid) if sid == revoked_id -> mist.stop()
        _ -> mist.continue(state)
      }

    mist.Binary(_) -> mist.continue(state)
    mist.Closed | mist.Shutdown -> mist.stop()
  }
}

pub fn ws_close(state: WsState) -> Nil {
  lustre.send(state.component, server_component.deregister_subject(state.self))
  lustre.send(state.component, lustre.shutdown())
}
