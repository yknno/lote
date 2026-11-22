import gleam/dynamic
import gleam/erlang/process
import gleam/int
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import gleam/time/calendar
import gleam/time/timestamp
import lote/auth/user
import lote/db/post_repo
import lote/realtime/pubsub
import lote/test_helper
import lote/web/components/timeline
import lustre
import lustre/effect.{type Effect}
import lustre/element
import lustre/server_component

fn render_html(model: timeline.Model) -> String {
  model
  |> timeline.view
  |> element.to_string
}

fn extract_tag_keys(html: String, tag: String) -> List(String) {
  let prefix = "<" <> tag <> " data-lustre-key=\""
  case string.split(html, prefix) {
    [] | [_] -> []
    [_, ..rest] ->
      list.filter_map(rest, fn(chunk) {
        case string.split_once(chunk, "\"") {
          Ok(#(key, _)) -> Ok(key)
          Error(_) -> Error(Nil)
        }
      })
  }
}

fn run_effect(eff: Effect(msg)) -> List(msg) {
  let subject = process.new_subject()
  effect.perform(
    eff,
    fn(msg) { process.send(subject, msg) },
    fn(_, _) { Nil },
    fn(_) { Nil },
    fn() { dynamic.nil() },
    fn(_, _) { Nil },
    fn(_, _) { Nil },
    fn(_) { Nil },
  )
  drain_subject(subject, [])
}

fn drain_subject(subject: process.Subject(msg), acc: List(msg)) -> List(msg) {
  case process.receive(subject, 0) {
    Ok(msg) -> drain_subject(subject, [msg, ..acc])
    Error(_) -> list.reverse(acc)
  }
}

fn step(model: timeline.Model, msg: timeline.Msg) -> timeline.Model {
  let #(next_model, eff) = timeline.update(model, msg)
  list.fold(run_effect(eff), next_model, step)
}

fn to_timeline_post(
  row: post_repo.CreatedPost,
  author: user.AuthUser,
) -> timeline.Post {
  timeline.Post(
    id: row.id,
    user_id: author.id,
    author_name: author.name,
    body: row.body,
    created_at: row.created_at,
  )
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

pub fn submitting_post_increments_form_key_and_publishes_post_test() {
  use tx <- test_helper.with_db

  let assert Ok(author) = user.create(tx, "TimelineUser")
  let assert Ok(post_pubsub) = pubsub.start()
  let pubsub_sub = process.new_subject()
  pubsub.subscribe(post_pubsub, pubsub_sub)

  let #(model0, _init_eff) =
    timeline.init(timeline.Flags(
      db: tx,
      pubsub: post_pubsub,
      user: Some(author),
      csrf_token: "test-csrf-token",
    ))

  assert model0.form_key == 0
  assert extract_tag_keys(render_html(model0), "form") == ["post-form-0"]

  // Submitting a valid post increments form_key (so the keyed <form> is
  // reconstructed and the uncontrolled <textarea> is cleared), saves to DB,
  // reloads recent posts, and broadcasts Created(post) via PubSub.
  let model1 =
    step(model0, timeline.UserSubmittedForm([#("body", "hello world")]))

  assert model1.form_key == 1
  assert extract_tag_keys(render_html(model1), "form") == ["post-form-1"]
  assert list.map(model1.posts, fn(p) { #(p.author_name, p.body) })
    == [#("TimelineUser", "hello world")]

  let assert Ok(timeline.Created(created)) = process.receive(pubsub_sub, 100)
  assert created.user_id == author.id
  assert created.body == "hello world"
  assert created.author_name == "TimelineUser"
}

pub fn submitting_blank_post_keeps_form_key_and_does_not_save_test() {
  use tx <- test_helper.with_db

  let assert Ok(author) = user.create(tx, "TimelineUser")
  let assert Ok(post_pubsub) = pubsub.start()
  let pubsub_sub = process.new_subject()
  pubsub.subscribe(post_pubsub, pubsub_sub)

  let #(model0, _init_eff) =
    timeline.init(timeline.Flags(
      db: tx,
      pubsub: post_pubsub,
      user: Some(author),
      csrf_token: "test-csrf-token",
    ))

  let model1 = step(model0, timeline.UserSubmittedForm([#("body", "   ")]))

  assert model1.form_key == 0
  assert extract_tag_keys(render_html(model1), "form") == ["post-form-0"]
  assert model1.posts == []
  assert process.receive(pubsub_sub, 20) == Error(Nil)
  assert post_repo.list_recent(tx, 10) == Ok([])
}

pub fn unauthenticated_user_cannot_submit_post_test() {
  use tx <- test_helper.with_db

  let assert Ok(post_pubsub) = pubsub.start()
  let pubsub_sub = process.new_subject()
  pubsub.subscribe(post_pubsub, pubsub_sub)

  let #(model0, _init_eff) =
    timeline.init(timeline.Flags(
      db: tx,
      pubsub: post_pubsub,
      user: None,
      csrf_token: "anon-csrf-token",
    ))

  assert extract_tag_keys(render_html(model0), "form") == []
  assert string.contains(render_html(model0), "Sign in to publish posts.")

  let model1 =
    step(
      model0,
      timeline.UserSubmittedForm([#("body", "unauthorized attempt")]),
    )

  assert model1 == model0
  assert process.receive(pubsub_sub, 20) == Error(Nil)
  assert post_repo.list_recent(tx, 10) == Ok([])
}

pub fn incoming_post_shows_pending_banner_until_refreshed_test() {
  use tx <- test_helper.with_db

  let assert Ok(alice) = user.create(tx, "Alice")
  let assert Ok(bob) = user.create(tx, "Bob")
  let assert Ok(post_pubsub) = pubsub.start()

  let #(model0, _init_eff) =
    timeline.init(timeline.Flags(
      db: tx,
      pubsub: post_pubsub,
      user: Some(alice),
      csrf_token: "test-csrf-token",
    ))

  // Bob publishes two posts while Alice has auto-refresh off
  let assert Ok(row1) = post_repo.create(tx, bob.id, "bob first post")
  let model1 = step(model0, timeline.PostCreated(to_timeline_post(row1, bob)))
  assert model1.pending_count == 1
  assert model1.posts == []
  let html1 = render_html(model1)
  assert string.contains(html1, "Show 1 new post")
  assert !string.contains(html1, "bob first post")

  let assert Ok(row2) = post_repo.create(tx, bob.id, "bob second post")
  let model2 = step(model1, timeline.PostCreated(to_timeline_post(row2, bob)))
  assert model2.pending_count == 2
  assert model2.posts == []
  let html2 = render_html(model2)
  assert string.contains(html2, "Show 2 new posts")
  assert !string.contains(html2, "bob second post")

  // Clicking refresh reloads both posts from DB and clears pending banner
  let model3 = step(model2, timeline.UserClickedRefresh)
  assert model3.pending_count == 0
  assert list.map(model3.posts, fn(p) { p.body })
    == ["bob second post", "bob first post"]
  let html3 = render_html(model3)
  assert string.contains(html3, "bob first post")
  assert string.contains(html3, "bob second post")
  assert !string.contains(html3, "Show 2 new posts")
}

pub fn submitting_own_post_refreshes_pending_posts_without_echo_banner_test() {
  use tx <- test_helper.with_db

  let assert Ok(alice) = user.create(tx, "Alice")
  let assert Ok(bob) = user.create(tx, "Bob")
  let assert Ok(post_pubsub) = pubsub.start()
  let pubsub_sub = process.new_subject()
  pubsub.subscribe(post_pubsub, pubsub_sub)

  let #(model0, _init_eff) =
    timeline.init(timeline.Flags(
      db: tx,
      pubsub: post_pubsub,
      user: Some(alice),
      csrf_token: "test-csrf-token",
    ))

  // Bob posts first, queued as pending for Alice
  let assert Ok(bob_row) = post_repo.create(tx, bob.id, "bob pending post")
  let model1 =
    step(model0, timeline.PostCreated(to_timeline_post(bob_row, bob)))
  assert model1.pending_count == 1
  assert string.contains(render_html(model1), "Show 1 new post")

  // Alice submits her own post: increments form_key, reloads DB (showing Alice's + Bob's posts),
  // and clears pending_count.
  let model2 =
    step(model1, timeline.UserSubmittedForm([#("body", "alice own post")]))
  assert model2.pending_count == 0
  assert list.map(model2.posts, fn(p) { p.body })
    == ["alice own post", "bob pending post"]

  // When the echoed PostCreated for Alice's own post arrives from PubSub,
  // it is ignored because its ID is not newer than the head of model.posts.
  let assert Ok(timeline.Created(alice_post)) = process.receive(pubsub_sub, 100)
  let model3 = step(model2, timeline.PostCreated(alice_post))
  assert model3.pending_count == 0
  assert model3.posts == model2.posts
  assert !string.contains(render_html(model3), "Show 1 new post")
}

pub fn toggling_auto_refresh_flushes_pending_and_streams_new_posts_test() {
  use tx <- test_helper.with_db

  let assert Ok(alice) = user.create(tx, "Alice")
  let assert Ok(bob) = user.create(tx, "Bob")
  let assert Ok(post_pubsub) = pubsub.start()

  let #(model0, _init_eff) =
    timeline.init(timeline.Flags(
      db: tx,
      pubsub: post_pubsub,
      user: Some(alice),
      csrf_token: "test-csrf-token",
    ))

  // Bob posts while auto-refresh is OFF -> buffered
  let assert Ok(row1) = post_repo.create(tx, bob.id, "pending before live")
  let model1 = step(model0, timeline.PostCreated(to_timeline_post(row1, bob)))
  assert model1.pending_count == 1
  assert !model1.auto_refresh

  // Toggle Live ON -> immediately reloads pending post from DB
  let model2 = step(model1, timeline.UserToggledAutoRefresh)
  assert model2.auto_refresh
  assert model2.pending_count == 0
  assert list.map(model2.posts, fn(p) { p.body }) == ["pending before live"]
  assert string.contains(render_html(model2), "aria-pressed=\"true\"")

  // New post while Live is ON -> streamed immediately into feed
  let assert Ok(row2) = post_repo.create(tx, bob.id, "streamed live post")
  let model3 = step(model2, timeline.PostCreated(to_timeline_post(row2, bob)))
  assert model3.pending_count == 0
  assert list.map(model3.posts, fn(p) { p.body })
    == ["streamed live post", "pending before live"]

  // Toggle Live back OFF -> subsequent posts are buffered again
  let model4 = step(model3, timeline.UserToggledAutoRefresh)
  assert !model4.auto_refresh
  assert string.contains(render_html(model4), "aria-pressed=\"false\"")

  let assert Ok(row3) = post_repo.create(tx, bob.id, "buffered after live off")
  let model5 = step(model4, timeline.PostCreated(to_timeline_post(row3, bob)))
  assert model5.pending_count == 1
  assert list.map(model5.posts, fn(p) { p.body })
    == ["streamed live post", "pending before live"]
  let html5 = render_html(model5)
  assert string.contains(html5, "Show 1 new post")
  assert !string.contains(html5, "buffered after live off")
}

pub fn post_renders_lote_time_with_rfc3339_datetime_and_permalink_test() {
  use tx <- test_helper.with_db

  let assert Ok(author) = user.create(tx, "TimeUser")
  let assert Ok(created) = post_repo.create(tx, author.id, "timestamped post")
  let assert Ok(post_pubsub) = pubsub.start()

  let #(model, _init_eff) =
    timeline.init(timeline.Flags(
      db: tx,
      pubsub: post_pubsub,
      user: Some(author),
      csrf_token: "test-csrf-token",
    ))

  let html = render_html(model)
  let expected_iso =
    timestamp.to_rfc3339(created.created_at, calendar.utc_offset)

  assert string.contains(html, "href=\"/posts/" <> created.id <> "\"")
  assert string.contains(html, "<lote-time")
  assert string.contains(html, "datetime=\"" <> expected_iso <> "\"")
  assert string.contains(html, " UTC</time></lote-time>")
}

pub fn owner_can_delete_post_with_confirmation_and_broadcasts_deletion_test() {
  use tx <- test_helper.with_db

  let assert Ok(alice) = user.create(tx, "Alice")
  let assert Ok(bob) = user.create(tx, "Bob")
  let assert Ok(post) = post_repo.create(tx, alice.id, "alice deletable post")
  let assert Ok(post_pubsub) = pubsub.start()
  let pubsub_sub = process.new_subject()
  pubsub.subscribe(post_pubsub, pubsub_sub)

  let #(alice_model0, _) =
    timeline.init(timeline.Flags(
      db: tx,
      pubsub: post_pubsub,
      user: Some(alice),
      csrf_token: "alice-csrf",
    ))
  let alice_html0 = render_html(alice_model0)
  assert string.contains(alice_html0, "alice deletable post")
  assert string.contains(alice_html0, ">Delete</button>")

  let #(bob_model0, _) =
    timeline.init(timeline.Flags(
      db: tx,
      pubsub: post_pubsub,
      user: Some(bob),
      csrf_token: "bob-csrf",
    ))
  let bob_html0 = render_html(bob_model0)
  assert string.contains(bob_html0, "alice deletable post")
  assert !string.contains(bob_html0, ">Delete</button>")

  // Step 1: request delete -> shows Confirm / Cancel
  let alice_model1 = step(alice_model0, timeline.UserRequestedDelete(post.id))
  assert alice_model1.confirming_delete == Some(post.id)
  let alice_html1 = render_html(alice_model1)
  assert string.contains(alice_html1, ">Confirm</button>")
  assert string.contains(alice_html1, ">Cancel</button>")

  // Cancel -> returns to Delete without deleting from DB
  let alice_model2 = step(alice_model1, timeline.UserCanceledDelete)
  assert alice_model2.confirming_delete == None
  assert string.contains(render_html(alice_model2), ">Delete</button>")
  let assert Ok(Some(_)) = post_repo.find_by_id(tx, post.id)

  // Confirm delete -> removes from DB, broadcasts Deleted(post.id), and updates models on PostDeleted
  let alice_model3 =
    alice_model2
    |> step(timeline.UserRequestedDelete(post.id))
    |> step(timeline.UserConfirmedDelete(post.id))
  assert alice_model3.confirming_delete == None
  assert process.receive(pubsub_sub, 100) == Ok(timeline.Deleted(post.id))
  assert post_repo.find_by_id(tx, post.id) == Ok(None)

  let alice_model4 = step(alice_model3, timeline.PostDeleted(post.id))
  let bob_model1 = step(bob_model0, timeline.PostDeleted(post.id))
  assert alice_model4.posts == []
  assert bob_model1.posts == []
  assert string.contains(render_html(alice_model4), "No posts yet.")
  assert string.contains(render_html(bob_model1), "No posts yet.")
}

pub fn non_owner_cannot_delete_another_users_post_test() {
  use tx <- test_helper.with_db

  let assert Ok(alice) = user.create(tx, "Alice")
  let assert Ok(bob) = user.create(tx, "Bob")
  let assert Ok(post) = post_repo.create(tx, alice.id, "alice protected post")
  let assert Ok(post_pubsub) = pubsub.start()
  let pubsub_sub = process.new_subject()
  pubsub.subscribe(post_pubsub, pubsub_sub)

  let #(bob_model0, _) =
    timeline.init(timeline.Flags(
      db: tx,
      pubsub: post_pubsub,
      user: Some(bob),
      csrf_token: "bob-csrf",
    ))

  // Even if Bob directly dispatches delete messages, the post is untouched
  let bob_model1 = step(bob_model0, timeline.UserRequestedDelete(post.id))
  assert bob_model1.confirming_delete == None
  assert !string.contains(render_html(bob_model1), ">Confirm</button>")

  let _bob_model2 = step(bob_model1, timeline.UserConfirmedDelete(post.id))
  assert process.receive(pubsub_sub, 20) == Error(Nil)
  let assert Ok(Some(found)) = post_repo.find_by_id(tx, post.id)
  assert found.id == post.id
}

pub fn timeline_loads_initial_page_and_appends_older_posts_on_load_more_test() {
  use tx <- test_helper.with_db

  let assert Ok(alice) = user.create(tx, "Alice")
  let total = timeline.page_size + 5
  let created =
    int.range(from: 1, to: total + 1, with: [], run: fn(acc, n) {
      let body = "paginated-post-" <> string.pad_start(int.to_string(n), 2, "0")
      let assert Ok(row) = post_repo.create(tx, alice.id, body)
      [row, ..acc]
    })
    |> list.reverse

  // Oldest post shown on page 1 is index (total - page_size) = 5 (0-based), i.e. paginated-post-06
  let assert Ok(page1_oldest) =
    created
    |> list.drop(5)
    |> list.first

  let assert Ok(post_pubsub) = pubsub.start()
  let #(model0, _) =
    timeline.init(timeline.Flags(
      db: tx,
      pubsub: post_pubsub,
      user: Some(alice),
      csrf_token: "test-csrf-token",
    ))

  assert list.length(model0.posts) == timeline.page_size
  assert model0.has_more
  assert !model0.loading_more

  let html0 = render_html(model0)
  assert string.contains(html0, "paginated-post-25")
  assert string.contains(html0, "paginated-post-06")
  assert !string.contains(html0, "paginated-post-05")
  assert string.contains(html0, int.to_string(timeline.page_size) <> "+ posts")
  assert string.contains(html0, "<lote-sentinel")
  assert string.contains(html0, "cursor=\"" <> page1_oldest.id <> "\"")
  assert string.contains(html0, "Load older posts")

  // Intermediate loading state before effect completion renders Loading...
  let #(loading_model, load_eff) =
    timeline.update(model0, timeline.UserRequestedLoadMore)
  assert loading_model.loading_more
  assert string.contains(render_html(loading_model), "Loading...")

  // Running the load effect dispatches OlderPostsLoaded and appends the remaining 5 posts
  let model1 = list.fold(run_effect(load_eff), loading_model, step)
  assert !model1.loading_more
  assert !model1.has_more
  assert list.length(model1.posts) == total

  let html1 = render_html(model1)
  assert string.contains(html1, "paginated-post-05")
  assert string.contains(html1, "paginated-post-01")
  assert string.contains(html1, int.to_string(total) <> " posts")
  assert !string.contains(html1, "Load older posts")
  assert !string.contains(html1, "<lote-sentinel")
}

pub fn timeline_without_older_posts_omits_sentinel_test() {
  use tx <- test_helper.with_db

  let assert Ok(alice) = user.create(tx, "Alice")
  let assert Ok(_) = post_repo.create(tx, alice.id, "only post 1")
  let assert Ok(_) = post_repo.create(tx, alice.id, "only post 2")

  let assert Ok(post_pubsub) = pubsub.start()
  let #(model, _) =
    timeline.init(timeline.Flags(
      db: tx,
      pubsub: post_pubsub,
      user: Some(alice),
      csrf_token: "test-csrf-token",
    ))

  assert !model.has_more
  let html = render_html(model)
  assert string.contains(html, "2 posts")
  assert !string.contains(html, "<lote-sentinel")
  assert !string.contains(html, "Load older posts")
}

pub fn feed_assigns_stable_post_id_keys_across_prepend_delete_and_pagination_test() {
  use tx <- test_helper.with_db

  let assert Ok(alice) = user.create(tx, "Alice")
  let total = timeline.page_size + 2
  let created =
    int.range(from: 1, to: total + 1, with: [], run: fn(acc, n) {
      let body = "keyed-post-" <> string.pad_start(int.to_string(n), 2, "0")
      let assert Ok(row) = post_repo.create(tx, alice.id, body)
      [row, ..acc]
    })
    |> list.reverse

  // created is in ascending creation order (#01 .. #22); display order is descending (#22 .. #01)
  let all_ids_desc =
    created
    |> list.reverse
    |> list.map(fn(r) { r.id })
  let page1_ids = list.take(all_ids_desc, timeline.page_size)

  let assert Ok(post_pubsub) = pubsub.start()
  let #(model0, _) =
    timeline.init(timeline.Flags(
      db: tx,
      pubsub: post_pubsub,
      user: Some(alice),
      csrf_token: "test-csrf-token",
    ))

  // 1. Initial feed renders <li data-lustre-key="{post.id}"> for the first page in descending ID order
  assert extract_tag_keys(render_html(model0), "li") == page1_ids

  // 2. Loading older posts appends the remaining 2 older post IDs to the tail while keeping existing keys
  let model1 = step(model0, timeline.UserRequestedLoadMore)
  assert extract_tag_keys(render_html(model1), "li") == all_ids_desc

  // 3. Enabling Live auto-refresh and prepending a new post places its key at index 0
  let model2 = step(model1, timeline.UserToggledAutoRefresh)
  let assert Ok(fresh) = post_repo.create(tx, alice.id, "new-post-top")
  let model3 =
    step(model2, timeline.PostCreated(to_timeline_post(fresh, alice)))
  assert extract_tag_keys(render_html(model3), "li")
    == [fresh.id, ..all_ids_desc]

  // 4. Deleting a post removes only that post's key while preserving confirmation state on another post
  let assert [_, second_id, third_id, ..] = all_ids_desc
  let assert Ok(True) = post_repo.delete(tx, second_id, alice.id)
  let model4 =
    model3
    |> step(timeline.UserRequestedDelete(third_id))
    |> step(timeline.PostDeleted(second_id))
  assert model4.confirming_delete == Some(third_id)
  assert extract_tag_keys(render_html(model4), "li")
    == list.filter([fresh.id, ..all_ids_desc], fn(id) { id != second_id })
  assert string.contains(render_html(model4), ">Confirm</button>")

  // 5. Clicking Refresh reloads the latest page_size posts from DB with their stable keys
  let model5 = step(model4, timeline.UserClickedRefresh)
  let expected_refreshed_keys =
    [fresh.id, ..all_ids_desc]
    |> list.filter(fn(id) { id != second_id })
    |> list.take(timeline.page_size)
  assert extract_tag_keys(render_html(model5), "li") == expected_refreshed_keys
}

pub fn server_component_runtime_delivers_pubsub_events_and_cleans_up_on_shutdown_test() {
  use tx <- test_helper.with_db

  let assert Ok(author) = user.create(tx, "RuntimeUser")
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

  // Publishing a PostEvent to post_pubsub is routed into the server component
  // via server_component.select and triggers a client update message.
  let assert Ok(row) = post_repo.create(tx, author.id, "runtime pubsub post")
  pubsub.publish(post_pubsub, timeline.Created(to_timeline_post(row, author)))
  let assert Ok(_patch) = process.receive(client, 500)

  shutdown_and_wait(component)

  assert test_helper.wait_until(100, 5, fn() {
    pubsub.subscriber_count(post_pubsub) == 0
  })
}
