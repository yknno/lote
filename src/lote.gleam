import gleam/erlang/process
import lote/config
import lote/web/router
import mist
import wisp
import wisp/wisp_mist

pub fn main() -> Nil {
  wisp.configure_logger()

  let cfg = config.load()

  let assert Ok(_) =
    router.handle_request
    |> wisp_mist.handler(cfg.secret_key_base)
    |> mist.new
    |> mist.bind("0.0.0.0")
    |> mist.port(cfg.port)
    |> mist.start

  process.sleep_forever()
}
