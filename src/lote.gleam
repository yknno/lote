import gleam/erlang/process.{type Subject}
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/json
import gleam/option.{Some}
import lote/config
import lote/web/components/counter
import lote/web/router
import lustre
import lustre/server_component
import mist.{type Connection, type ResponseData}
import wisp
import wisp/wisp_mist

pub fn main() -> Nil {
  wisp.configure_logger()

  let cfg = config.load()
  let http_handler = wisp_mist.handler(router.handle_request, cfg.secret_key_base)

  let assert Ok(_) =
    fn(req: Request(Connection)) -> Response(ResponseData) {
      case request.path_segments(req) {
        ["ws"] -> serve_counter_ws(req)
        _ -> http_handler(req)
      }
    }
    |> mist.new
    |> mist.bind("0.0.0.0")
    |> mist.port(cfg.port)
    |> mist.start

  process.sleep_forever()
}

type WsState {
  WsState(
    component: lustre.Runtime(counter.Msg),
    self: Subject(server_component.ClientMessage(counter.Msg)),
  )
}

fn serve_counter_ws(req: Request(Connection)) -> Response(ResponseData) {
  mist.websocket(
    request: req,
    on_init: fn(_conn) {
      let assert Ok(component) = lustre.start_server_component(counter.app(), Nil)
      let self = process.new_subject()
      let selector = process.new_selector() |> process.select(self)

      server_component.register_subject(self)
      |> lustre.send(to: component)

      #(WsState(component:, self:), Some(selector))
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

        mist.Custom(client_msg) -> {
          let payload =
            client_msg
            |> server_component.client_message_to_json
            |> json.to_string
          let _ = mist.send_text_frame(conn, payload)
          mist.continue(state)
        }

        mist.Binary(_) -> mist.continue(state)
        mist.Closed | mist.Shutdown -> mist.stop()
      }
    },
    on_close: fn(state: WsState) {
      lustre.send(state.component, server_component.deregister_subject(state.self))
      lustre.send(state.component, lustre.shutdown())
    },
  )
}
