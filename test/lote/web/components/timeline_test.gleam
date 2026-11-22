import gleam/dynamic/decode
import gleam/erlang/process
import gleam/json
import gleam/list
import gleam/option.{Some}
import lote/auth/user
import lote/realtime/pubsub
import lote/test_helper
import lote/web/components/timeline
import lustre
import lustre/server_component

type ReplaceFormChange {
  ReplaceFormChange(kind: Int, tag: String, key: String)
}

fn patch_replace_form_decoder() -> decode.Decoder(List(ReplaceFormChange)) {
  use <- decode.recursive

  let change_decoder = {
    use kind <- decode.field("kind", decode.int)
    case kind {
      5 -> {
        use tag <- decode.subfield(["with", "tag"], decode.string)
        use key <- decode.subfield(["with", "key"], decode.string)
        decode.success([ReplaceFormChange(kind:, tag:, key:)])
      }
      _ -> decode.success([])
    }
  }

  use changes <- decode.optional_field(
    "changes",
    [],
    decode.list(change_decoder),
  )
  use children <- decode.optional_field(
    "children",
    [],
    decode.list(patch_replace_form_decoder()),
  )
  decode.success(list.flatten([list.flatten(changes), ..children]))
}

fn collect_replace_form_changes(
  patch_json: String,
) -> Result(List(ReplaceFormChange), json.DecodeError) {
  let msg_decoder = {
    use patch <- decode.field("patch", patch_replace_form_decoder())
    decode.success(patch)
  }

  json.parse(patch_json, msg_decoder)
}

pub fn submitting_post_replaces_form_element_to_reset_input_test() {
  use tx <- test_helper.with_db

  let assert Ok(author) = user.create(tx, "TimelineUser")
  let assert Ok(post_pubsub) = pubsub.start()
  let pubsub_sub = process.new_subject()
  pubsub.subscribe(post_pubsub, pubsub_sub)

  let flags =
    timeline.Flags(
      db: tx,
      pubsub: post_pubsub,
      user: Some(author),
      csrf_token: "test-csrf-token",
    )
  let assert Ok(component) =
    lustre.start_server_component(timeline.app(), flags)

  let client = process.new_subject()
  server_component.register_subject(client)
  |> lustre.send(to: component)

  // Initial mount message
  let assert Ok(_mount) = process.receive(client, 500)

  // Submitting a post should emit a VDOM Replace patch for the <form>
  // with an incremented key so the browser resets the uncontrolled textarea.
  lustre.dispatch(timeline.UserSubmittedForm([#("body", "hello world")]))
  |> lustre.send(to: component)

  let assert Ok(reconcile_msg) = process.receive(client, 500)
  let payload =
    reconcile_msg
    |> server_component.client_message_to_json
    |> json.to_string

  assert collect_replace_form_changes(payload)
    == Ok([ReplaceFormChange(kind: 5, tag: "form", key: "post-form-1")])

  // Wait for the save_and_publish effect to complete before transaction rollback
  let assert Ok(created) = process.receive(pubsub_sub, 500)
  assert created.body == "hello world"
  assert created.author_name == "TimelineUser"

  lustre.send(component, lustre.shutdown())
}

pub fn submitting_blank_post_does_not_replace_form_test() {
  use tx <- test_helper.with_db

  let assert Ok(author) = user.create(tx, "TimelineUser")
  let assert Ok(post_pubsub) = pubsub.start()

  let flags =
    timeline.Flags(
      db: tx,
      pubsub: post_pubsub,
      user: Some(author),
      csrf_token: "test-csrf-token",
    )
  let assert Ok(component) =
    lustre.start_server_component(timeline.app(), flags)

  let client = process.new_subject()
  server_component.register_subject(client)
  |> lustre.send(to: component)

  let assert Ok(_mount) = process.receive(client, 500)

  lustre.dispatch(timeline.UserSubmittedForm([#("body", "   ")]))
  |> lustre.send(to: component)

  let assert Ok(reconcile_msg) = process.receive(client, 500)
  let payload =
    reconcile_msg
    |> server_component.client_message_to_json
    |> json.to_string

  assert collect_replace_form_changes(payload) == Ok([])

  lustre.send(component, lustre.shutdown())
}

pub fn shutting_down_timeline_component_removes_pubsub_subscriber_test() {
  use tx <- test_helper.with_db

  let assert Ok(author) = user.create(tx, "TimelineUser")
  let assert Ok(post_pubsub) = pubsub.start()

  let flags =
    timeline.Flags(
      db: tx,
      pubsub: post_pubsub,
      user: Some(author),
      csrf_token: "test-csrf-token",
    )
  let assert Ok(component) =
    lustre.start_server_component(timeline.app(), flags)

  let client = process.new_subject()
  server_component.register_subject(client)
  |> lustre.send(to: component)
  let assert Ok(_mount) = process.receive(client, 500)

  assert pubsub.subscriber_count(post_pubsub) == 1

  let mon = process.monitor(server_component.pid(component))
  lustre.send(component, lustre.shutdown())
  let down_selector =
    process.new_selector()
    |> process.select_specific_monitor(mon, fn(down) { down })
  let assert Ok(_) = process.selector_receive(down_selector, 500)

  assert test_helper.wait_until(100, 5, fn() {
    pubsub.subscriber_count(post_pubsub) == 0
  })
}
