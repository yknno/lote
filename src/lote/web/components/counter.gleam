import gleam/int
import lustre
import lustre/element.{type Element}
import lustre/element/html
import lustre/event

pub type Model =
  Int

pub type Msg {
  Increment
}

pub fn app() -> lustre.App(Nil, Model, Msg) {
  lustre.simple(init:, update:, view:)
}

fn init(_flags: Nil) -> Model {
  0
}

fn update(model: Model, msg: Msg) -> Model {
  case msg {
    Increment -> model + 1
  }
}

fn view(model: Model) -> Element(Msg) {
  html.div([], [
    html.p([], [html.text("Count: " <> int.to_string(model))]),
    html.button([event.on_click(Increment)], [html.text("+1")]),
  ])
}
