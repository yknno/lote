import gleam/erlang/process.{type Subject}
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import lote/auth.{type Auth, Auth, Password}
import lote/auth/session
import lote/config
import lote/db/pool
import lote/realtime/pubsub.{type PubSub}
import lote/web/components/timeline
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
  let db = pool.start(cfg.database_url)

  let methods =
    list.filter_map(cfg.auth_adapters, fn(name) {
      case name {
        "password" -> Ok(Password)
        _ -> Error(Nil)
      }
    })

  let assert Ok(session_revocations) = pubsub.start()
  let auth_ctx =
    Auth(
      db:,
      secret_key_base: cfg.secret_key_base,
      methods:,
      session_revocations:,
    )

  let assert Ok(post_pubsub) = pubsub.start()
  let http_handler =
    wisp_mist.handler(router.handle_request(_, auth_ctx), cfg.secret_key_base)

  let assert Ok(_) =
    fn(req: Request(Connection)) -> Response(ResponseData) {
      case request.path_segments(req) {
        ["ws"] -> serve_timeline_ws(req, db, post_pubsub, auth_ctx)
        _ -> http_handler(req)
      }
    }
    |> mist.new
    |> mist.bind("0.0.0.0")
    |> mist.port(cfg.port)
    |> mist.start

  process.sleep_forever()
}

type WsMsg {
  ComponentMessage(server_component.ClientMessage(timeline.Msg))
  SessionRevoked(String)
}

type WsState {
  WsState(
    component: lustre.Runtime(timeline.Msg),
    self: Subject(server_component.ClientMessage(timeline.Msg)),
    session_id: Option(String),
  )
}

fn serve_timeline_ws(
  req: Request(Connection),
  db: pog.Connection,
  post_pubsub: PubSub(timeline.Post),
  auth_ctx: Auth,
) -> Response(ResponseData) {
  mist.websocket(
    request: req,
    on_init: fn(_conn) {
      let revocation_sub = process.new_subject()
      let candidate_session_id =
        session.session_id(req, auth_ctx.secret_key_base)
      case candidate_session_id {
        Some(_) ->
          pubsub.subscribe(auth_ctx.session_revocations, revocation_sub)
        None -> Nil
      }

      let active_session =
        session.current_session(req, auth_ctx.db, auth_ctx.secret_key_base)
      let #(current_user, session_id, has_revocation_sub) = case
        active_session
      {
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

      let flags = timeline.Flags(db:, pubsub: post_pubsub, user: current_user)
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
    },
    handler: fn(state: WsState, msg, conn) {
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
          let _ = mist.send_text_frame(conn, payload)
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
    },
    on_close: fn(state: WsState) {
      lustre.send(
        state.component,
        server_component.deregister_subject(state.self),
      )
      lustre.send(state.component, lustre.shutdown())
    },
  )
}
