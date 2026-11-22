import gleam/dynamic/decode
import gleam/erlang/process
import gleam/json
import gleam/list
import gleam/option.{Some}
import gleam/string
import gleam/time/calendar
import gleam/time/timestamp
import lote/auth/user
import lote/db/post_repo
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

fn shutdown_and_wait(component: lustre.Runtime(timeline.Msg)) -> Nil {
  let mon = process.monitor(server_component.pid(component))
  lustre.send(component, lustre.shutdown())
  let down_selector =
    process.new_selector()
    |> process.select_specific_monitor(mon, fn(down) { down })
  let assert Ok(_) = process.selector_receive(down_selector, 500)
  Nil
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

  shutdown_and_wait(component)
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

  shutdown_and_wait(component)
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

  shutdown_and_wait(component)

  assert test_helper.wait_until(100, 5, fn() {
    pubsub.subscriber_count(post_pubsub) == 0
  })
}

pub fn unauthenticated_user_cannot_submit_post_test() {
  use tx <- test_helper.with_db

  let assert Ok(post_pubsub) = pubsub.start()
  let pubsub_sub = process.new_subject()
  pubsub.subscribe(post_pubsub, pubsub_sub)

  let flags =
    timeline.Flags(
      db: tx,
      pubsub: post_pubsub,
      user: option.None,
      csrf_token: "anon-csrf-token",
    )
  let assert Ok(component) =
    lustre.start_server_component(timeline.app(), flags)

  let client = process.new_subject()
  server_component.register_subject(client)
  |> lustre.send(to: component)
  let assert Ok(_mount) = process.receive(client, 500)

  lustre.dispatch(
    timeline.UserSubmittedForm([#("body", "unauthorized attempt")]),
  )
  |> lustre.send(to: component)

  let assert Ok(_reconcile) = process.receive(client, 500)
  assert process.receive(pubsub_sub, 50) == Error(Nil)
  assert post_repo.list_recent(tx, 10) == Ok([])

  shutdown_and_wait(component)
}

fn receive_json(
  client: process.Subject(server_component.ClientMessage(timeline.Msg)),
) -> String {
  let assert Ok(msg) = process.receive(client, 500)
  msg
  |> server_component.client_message_to_json
  |> json.to_string
}

pub fn incoming_post_shows_pending_banner_until_refreshed_test() {
  use tx <- test_helper.with_db

  let assert Ok(alice) = user.create(tx, "Alice")
  let assert Ok(bob) = user.create(tx, "Bob")
  let assert Ok(post_pubsub) = pubsub.start()

  let flags =
    timeline.Flags(
      db: tx,
      pubsub: post_pubsub,
      user: Some(alice),
      csrf_token: "test-csrf-token",
    )
  let assert Ok(component) =
    lustre.start_server_component(timeline.app(), flags)

  let client = process.new_subject()
  server_component.register_subject(client)
  |> lustre.send(to: component)
  let _mount = receive_json(client)

  // Bob publishes two posts while Alice has auto-refresh off
  let assert Ok(row1) = post_repo.create(tx, bob.id, "bob first post")
  pubsub.publish(
    post_pubsub,
    timeline.Post(
      id: row1.id,
      author_name: bob.name,
      body: row1.body,
      created_at: row1.created_at,
    ),
  )
  let patch1 = receive_json(client)
  assert string.contains(patch1, "Show 1 new post")
  assert !string.contains(patch1, "bob first post")

  let assert Ok(row2) = post_repo.create(tx, bob.id, "bob second post")
  pubsub.publish(
    post_pubsub,
    timeline.Post(
      id: row2.id,
      author_name: bob.name,
      body: row2.body,
      created_at: row2.created_at,
    ),
  )
  let patch2 = receive_json(client)
  assert string.contains(patch2, "Show 2 new posts")
  assert !string.contains(patch2, "bob second post")

  // Clicking refresh reloads both posts from DB and clears pending banner
  lustre.dispatch(timeline.UserClickedRefresh)
  |> lustre.send(to: component)
  let refresh_patch = receive_json(client)
  assert string.contains(refresh_patch, "bob first post")
  assert string.contains(refresh_patch, "bob second post")
  assert !string.contains(refresh_patch, "Show 2 new posts")

  shutdown_and_wait(component)
}

pub fn submitting_own_post_refreshes_pending_posts_without_echo_banner_test() {
  use tx <- test_helper.with_db

  let assert Ok(alice) = user.create(tx, "Alice")
  let assert Ok(bob) = user.create(tx, "Bob")
  let assert Ok(post_pubsub) = pubsub.start()

  let flags =
    timeline.Flags(
      db: tx,
      pubsub: post_pubsub,
      user: Some(alice),
      csrf_token: "test-csrf-token",
    )
  let assert Ok(component) =
    lustre.start_server_component(timeline.app(), flags)

  let client = process.new_subject()
  server_component.register_subject(client)
  |> lustre.send(to: component)
  let _mount = receive_json(client)

  // Bob posts first, queued as pending for Alice
  let assert Ok(bob_row) = post_repo.create(tx, bob.id, "bob pending post")
  pubsub.publish(
    post_pubsub,
    timeline.Post(
      id: bob_row.id,
      author_name: bob.name,
      body: bob_row.body,
      created_at: bob_row.created_at,
    ),
  )
  let pending_patch = receive_json(client)
  assert string.contains(pending_patch, "Show 1 new post")

  // Alice submits her own post: should reset form, reload DB (showing Bob's + Alice's posts),
  // and ignore the echoed PostCreated for her own post without showing a new pending banner.
  lustre.dispatch(timeline.UserSubmittedForm([#("body", "alice own post")]))
  |> lustre.send(to: component)

  let _form_replace_patch = receive_json(client)
  let reloaded_patch = receive_json(client)
  assert string.contains(reloaded_patch, "alice own post")
  assert string.contains(reloaded_patch, "bob pending post")

  // Echoed PostCreated(alice_post) produces an empty no-op patch (no pending banner)
  let echo_patch = receive_json(client)
  assert !string.contains(echo_patch, "Show 1 new post")

  shutdown_and_wait(component)
}

pub fn toggling_auto_refresh_flushes_pending_and_streams_new_posts_test() {
  use tx <- test_helper.with_db

  let assert Ok(alice) = user.create(tx, "Alice")
  let assert Ok(bob) = user.create(tx, "Bob")
  let assert Ok(post_pubsub) = pubsub.start()

  let flags =
    timeline.Flags(
      db: tx,
      pubsub: post_pubsub,
      user: Some(alice),
      csrf_token: "test-csrf-token",
    )
  let assert Ok(component) =
    lustre.start_server_component(timeline.app(), flags)

  let client = process.new_subject()
  server_component.register_subject(client)
  |> lustre.send(to: component)
  let _mount = receive_json(client)

  // Bob posts while auto-refresh is OFF -> buffered
  let assert Ok(row1) = post_repo.create(tx, bob.id, "pending before live")
  pubsub.publish(
    post_pubsub,
    timeline.Post(
      id: row1.id,
      author_name: bob.name,
      body: row1.body,
      created_at: row1.created_at,
    ),
  )
  let pending_patch = receive_json(client)
  assert string.contains(pending_patch, "Show 1 new post")

  // Toggle Live ON -> immediately reloads pending post from DB
  lustre.dispatch(timeline.UserToggledAutoRefresh)
  |> lustre.send(to: component)
  let live_on_patch = receive_json(client)
  assert string.contains(live_on_patch, "pending before live")

  // New post while Live is ON -> streamed immediately into feed
  let assert Ok(row2) = post_repo.create(tx, bob.id, "streamed live post")
  pubsub.publish(
    post_pubsub,
    timeline.Post(
      id: row2.id,
      author_name: bob.name,
      body: row2.body,
      created_at: row2.created_at,
    ),
  )
  let live_patch = receive_json(client)
  assert string.contains(live_patch, "streamed live post")
  assert !string.contains(live_patch, "Show 1 new post")

  // Toggle Live back OFF -> subsequent posts are buffered again
  lustre.dispatch(timeline.UserToggledAutoRefresh)
  |> lustre.send(to: component)
  let _live_off_patch = receive_json(client)

  let assert Ok(row3) = post_repo.create(tx, bob.id, "buffered after live off")
  pubsub.publish(
    post_pubsub,
    timeline.Post(
      id: row3.id,
      author_name: bob.name,
      body: row3.body,
      created_at: row3.created_at,
    ),
  )
  let buffered_again_patch = receive_json(client)
  assert string.contains(buffered_again_patch, "Show 1 new post")
  assert !string.contains(buffered_again_patch, "buffered after live off")

  shutdown_and_wait(component)
}

pub fn post_renders_lote_time_with_rfc3339_datetime_test() {
  use tx <- test_helper.with_db

  let assert Ok(author) = user.create(tx, "TimeUser")
  let assert Ok(created) = post_repo.create(tx, author.id, "timestamped post")
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

  let payload = receive_json(client)

  let expected_iso =
    timestamp.to_rfc3339(created.created_at, calendar.utc_offset)
  assert string.contains(payload, "\"/posts/" <> created.id <> "\"")
  assert string.contains(payload, "\"tag\":\"lote-time\"")
  assert string.contains(payload, expected_iso)
  assert string.contains(payload, " UTC")

  shutdown_and_wait(component)
}
