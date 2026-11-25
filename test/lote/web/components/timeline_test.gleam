import gleam/dynamic
import gleam/erlang/process
import gleam/int
import gleam/list
import gleam/option.{None, Some}
import gleam/set
import gleam/string
import gleam/time/calendar
import gleam/time/timestamp
import lote/auth/user
import lote/db/post_repo
import lote/rate_limit
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
      rate_limiter: rate_limit.disabled(),
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
      rate_limiter: rate_limit.disabled(),
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
      rate_limiter: rate_limit.disabled(),
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
      rate_limiter: rate_limit.disabled(),
      user: Some(alice),
      csrf_token: "test-csrf-token",
    ))

  // Bob publishes two posts while Alice has auto-refresh off
  let assert Ok(row1) = post_repo.create(tx, bob.id, "bob first post")
  let model1 = step(model0, timeline.PostCreated(to_timeline_post(row1, bob)))
  assert set.size(model1.pending_ids) == 1
  assert model1.posts == []
  let html1 = render_html(model1)
  assert string.contains(html1, "Show 1 new post")
  assert !string.contains(html1, "bob first post")

  let assert Ok(row2) = post_repo.create(tx, bob.id, "bob second post")
  let model2 = step(model1, timeline.PostCreated(to_timeline_post(row2, bob)))
  assert set.size(model2.pending_ids) == 2
  assert model2.posts == []
  let html2 = render_html(model2)
  assert string.contains(html2, "Show 2 new posts")
  assert !string.contains(html2, "bob second post")

  // Clicking refresh loads both posts asynchronously via effect and clears pending banner
  let #(loading_model, refresh_eff) =
    timeline.update(model2, timeline.UserClickedRefresh)
  assert loading_model.loading_newer
  assert loading_model.posts == []
  assert string.contains(render_html(loading_model), "Loading new posts...")

  let model3 = list.fold(run_effect(refresh_eff), loading_model, step)
  assert !model3.loading_newer
  assert set.size(model3.pending_ids) == 0
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
      rate_limiter: rate_limit.disabled(),
      user: Some(alice),
      csrf_token: "test-csrf-token",
    ))

  // Bob posts first, queued as pending for Alice
  let assert Ok(bob_row) = post_repo.create(tx, bob.id, "bob pending post")
  let model1 =
    step(model0, timeline.PostCreated(to_timeline_post(bob_row, bob)))
  assert set.size(model1.pending_ids) == 1
  assert string.contains(render_html(model1), "Show 1 new post")

  // Alice submits her own post: increments form_key on save success, includes Bob's pending post,
  // and clears pending_ids.
  let model2 =
    step(model1, timeline.UserSubmittedForm([#("body", "alice own post")]))
  assert set.size(model2.pending_ids) == 0
  assert list.map(model2.posts, fn(p) { p.body })
    == ["alice own post", "bob pending post"]

  // When the echoed PostCreated for Alice's own post arrives from PubSub,
  // it is ignored because its ID is not newer than the head of model.posts.
  let assert Ok(timeline.Created(alice_post)) = process.receive(pubsub_sub, 100)
  let model3 = step(model2, timeline.PostCreated(alice_post))
  assert set.size(model3.pending_ids) == 0
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
      rate_limiter: rate_limit.disabled(),
      user: Some(alice),
      csrf_token: "test-csrf-token",
    ))

  // Bob posts while auto-refresh is OFF -> buffered
  let assert Ok(row1) = post_repo.create(tx, bob.id, "pending before live")
  let model1 = step(model0, timeline.PostCreated(to_timeline_post(row1, bob)))
  assert set.size(model1.pending_ids) == 1
  assert !model1.auto_refresh

  // Toggle Live ON -> flushes pending post asynchronously via effect
  let #(toggling_model, toggle_eff) =
    timeline.update(model1, timeline.UserToggledAutoRefresh)
  assert toggling_model.auto_refresh
  assert toggling_model.loading_newer
  assert toggling_model.posts == []

  let model2 = list.fold(run_effect(toggle_eff), toggling_model, step)
  assert model2.auto_refresh
  assert !model2.loading_newer
  assert set.size(model2.pending_ids) == 0
  assert list.map(model2.posts, fn(p) { p.body }) == ["pending before live"]
  assert string.contains(render_html(model2), "aria-pressed=\"true\"")

  // New post while Live is ON -> streamed immediately into feed
  let assert Ok(row2) = post_repo.create(tx, bob.id, "streamed live post")
  let model3 = step(model2, timeline.PostCreated(to_timeline_post(row2, bob)))
  assert set.size(model3.pending_ids) == 0
  assert list.map(model3.posts, fn(p) { p.body })
    == ["streamed live post", "pending before live"]

  // Toggle Live back OFF -> subsequent posts are buffered again
  let model4 = step(model3, timeline.UserToggledAutoRefresh)
  assert !model4.auto_refresh
  assert string.contains(render_html(model4), "aria-pressed=\"false\"")

  let assert Ok(row3) = post_repo.create(tx, bob.id, "buffered after live off")
  let model5 = step(model4, timeline.PostCreated(to_timeline_post(row3, bob)))
  assert set.size(model5.pending_ids) == 1
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
      rate_limiter: rate_limit.disabled(),
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
      rate_limiter: rate_limit.disabled(),
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
      rate_limiter: rate_limit.disabled(),
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
      rate_limiter: rate_limit.disabled(),
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
      rate_limiter: rate_limit.disabled(),
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
      rate_limiter: rate_limit.disabled(),
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
      rate_limiter: rate_limit.disabled(),
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

  // 5. Clicking Refresh fetches only newer posts via list_after without truncating older loaded posts
  let assert Ok(newer_row) = post_repo.create(tx, alice.id, "refreshed-top")
  let model5 = step(model4, timeline.UserClickedRefresh)
  let expected_refreshed_keys =
    [newer_row.id, fresh.id, ..all_ids_desc]
    |> list.filter(fn(id) { id != second_id })
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
      rate_limiter: rate_limit.disabled(),
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

pub fn submitting_over_limit_post_shows_error_without_resetting_form_and_clears_on_valid_submit_test() {
  use tx <- test_helper.with_db

  let assert Ok(author) = user.create(tx, "LimitUser")
  let assert Ok(post_pubsub) = pubsub.start()
  let pubsub_sub = process.new_subject()
  pubsub.subscribe(post_pubsub, pubsub_sub)

  let #(model0, _init_eff) =
    timeline.init(timeline.Flags(
      db: tx,
      pubsub: post_pubsub,
      rate_limiter: rate_limit.disabled(),
      user: Some(author),
      csrf_token: "test-csrf-token",
    ))

  let initial_html = render_html(model0)
  assert string.contains(initial_html, "<lote-composer")
  assert string.contains(
    initial_html,
    "max=\"" <> int.to_string(post_repo.max_body_length) <> "\"",
  )
  assert string.contains(initial_html, "data-char-counter")
  assert string.contains(
    initial_html,
    "0 / " <> int.to_string(post_repo.max_body_length),
  )
  assert !string.contains(initial_html, "role=\"alert\"")

  // Over-limit submission sets form_error, keeps form_key intact, and does not save or publish
  let over_301 = string.repeat("a", post_repo.max_body_length + 1)
  let model1 = step(model0, timeline.UserSubmittedForm([#("body", over_301)]))

  assert model1.form_key == 0
  assert model1.posts == []
  assert process.receive(pubsub_sub, 20) == Error(Nil)
  assert post_repo.list_recent(tx, 10) == Ok([])
  let err_html = render_html(model1)
  assert string.contains(err_html, "role=\"alert\"")
  assert string.contains(err_html, "301 / 300")

  // Valid 300-grapheme submission succeeds, resets form_key, and clears form_error
  let exact_300 = string.repeat("あ", post_repo.max_body_length - 1) <> "👨‍👩‍👧‍👦"
  let model2 = step(model1, timeline.UserSubmittedForm([#("body", exact_300)]))

  assert model2.form_key == 1
  assert model2.form_error == None
  assert !string.contains(render_html(model2), "role=\"alert\"")
  assert list.map(model2.posts, fn(p) { p.body }) == [exact_300]
  let assert Ok(timeline.Created(created)) = process.receive(pubsub_sub, 100)
  assert created.body == exact_300
}

pub fn incremental_refresh_and_own_submit_preserve_loaded_older_posts_test() {
  use tx <- test_helper.with_db

  let assert Ok(alice) = user.create(tx, "Alice")
  let assert Ok(bob) = user.create(tx, "Bob")
  let total = timeline.page_size + 3
  let _ =
    int.range(from: 1, to: total + 1, with: Nil, run: fn(_, n) {
      let assert Ok(_) =
        post_repo.create(tx, bob.id, "older-" <> int.to_string(n))
      Nil
    })

  let assert Ok(post_pubsub) = pubsub.start()
  let #(model0, _) =
    timeline.init(timeline.Flags(
      db: tx,
      pubsub: post_pubsub,
      rate_limiter: rate_limit.disabled(),
      user: Some(alice),
      csrf_token: "test-csrf-token",
    ))

  // Load older posts so we have page_size + 3 (23) posts in memory
  let model1 = step(model0, timeline.UserRequestedLoadMore)
  assert list.length(model1.posts) == total

  // Bob posts a new message while Alice has auto-refresh OFF
  let assert Ok(bob_new) = post_repo.create(tx, bob.id, "bob newer post")
  let model2 =
    step(model1, timeline.PostCreated(to_timeline_post(bob_new, bob)))
  assert set.size(model2.pending_ids) == 1

  // Clicking Show 1 new post prepends bob_new while keeping all 23 older posts (24 total)
  let model3 = step(model2, timeline.UserClickedRefresh)
  assert set.size(model3.pending_ids) == 0
  assert list.length(model3.posts) == total + 1
  let assert [head3, ..] = model3.posts
  assert head3.body == "bob newer post"

  // Submitting Alice's own post also prepends without rewinding to 20 (25 total)
  let model4 =
    step(model3, timeline.UserSubmittedForm([#("body", "alice newer post")]))
  assert list.length(model4.posts) == total + 2
  let assert [head4, second4, ..] = model4.posts
  assert head4.body == "alice newer post"
  assert second4.body == "bob newer post"
}

pub fn pending_ids_deduplicate_and_remove_deleted_pending_posts_test() {
  use tx <- test_helper.with_db

  let assert Ok(alice) = user.create(tx, "Alice")
  let assert Ok(bob) = user.create(tx, "Bob")
  let assert Ok(post_pubsub) = pubsub.start()

  let #(model0, _) =
    timeline.init(timeline.Flags(
      db: tx,
      pubsub: post_pubsub,
      rate_limiter: rate_limit.disabled(),
      user: Some(alice),
      csrf_token: "test-csrf-token",
    ))

  let assert Ok(row1) = post_repo.create(tx, bob.id, "pending 1")
  let assert Ok(row2) = post_repo.create(tx, bob.id, "pending 2")
  let post1 = to_timeline_post(row1, bob)
  let post2 = to_timeline_post(row2, bob)

  // Duplicate PostCreated for the same ID does not double-count
  let model1 =
    model0
    |> step(timeline.PostCreated(post1))
    |> step(timeline.PostCreated(post1))
    |> step(timeline.PostCreated(post2))
  assert set.size(model1.pending_ids) == 2
  assert string.contains(render_html(model1), "Show 2 new posts")

  // Deleting a pending post immediately decrements the banner count
  let model2 = step(model1, timeline.PostDeleted(post1.id))
  assert set.size(model2.pending_ids) == 1
  assert string.contains(render_html(model2), "Show 1 new post")

  // Deleting the last pending post removes the banner completely
  let model3 = step(model2, timeline.PostDeleted(post2.id))
  assert set.size(model3.pending_ids) == 0
  assert !string.contains(render_html(model3), "Show ")
}

pub fn save_and_delete_failures_display_error_without_clearing_form_test() {
  use tx <- test_helper.with_db

  let assert Ok(post_pubsub) = pubsub.start()
  // Use a non-existent user ID so post_repo.create hits a FK QueryError
  let ghost_user = user.AuthUser(id: -999_999, name: "Ghost")

  let #(model0, _) =
    timeline.init(timeline.Flags(
      db: tx,
      pubsub: post_pubsub,
      rate_limiter: rate_limit.disabled(),
      user: Some(ghost_user),
      csrf_token: "test-csrf-token",
    ))

  // Save failure preserves form_key (does not clear the user's draft) and renders alert
  let model1 =
    step(model0, timeline.UserSubmittedForm([#("body", "draft preserved")]))
  assert model1.form_key == 0
  let assert Some(form_err) = model1.form_error
  assert string.contains(form_err, "Failed to publish post")
  assert string.contains(render_html(model1), "role=\"alert\"")
  assert string.contains(render_html(model1), "Failed to publish post")

  // Delete failure renders timeline error alert with Dismiss button
  let model2 =
    step(
      model1,
      timeline.PostDeleteFailed("Failed to delete post. Please try again."),
    )
  assert model2.timeline_error
    == Some("Failed to delete post. Please try again.")
  let html2 = render_html(model2)
  assert string.contains(html2, "Failed to delete post. Please try again.")
  assert string.contains(html2, ">Dismiss</button>")

  let model3 = step(model2, timeline.UserDismissedError)
  assert model3.timeline_error == None
  assert !string.contains(
    render_html(model3),
    "Failed to delete post. Please try again.",
  )
}

pub fn submitting_state_disables_button_and_blocks_duplicate_submit_test() {
  use tx <- test_helper.with_db

  let assert Ok(alice) = user.create(tx, "DoubleClickAlice")
  let assert Ok(post_pubsub) = pubsub.start()

  let #(model0, _) =
    timeline.init(timeline.Flags(
      db: tx,
      pubsub: post_pubsub,
      rate_limiter: rate_limit.disabled(),
      user: Some(alice),
      csrf_token: "test-csrf-token",
    ))

  // First submit enters submitting state and disables the Post button before DB save finishes
  let #(submitting_model, save_eff) =
    timeline.update(
      model0,
      timeline.UserSubmittedForm([#("body", "only save once")]),
    )
  assert submitting_model.submitting
  assert submitting_model.form_key == 0
  let submitting_html = render_html(submitting_model)
  assert string.contains(submitting_html, " submitting>")
  assert string.contains(submitting_html, "disabled")
  assert string.contains(submitting_html, ">Posting...</button>")

  // A rapid second submit while submitting == True is ignored with no effect
  let #(dup_model, dup_eff) =
    timeline.update(
      submitting_model,
      timeline.UserSubmittedForm([#("body", "only save once")]),
    )
  assert dup_model == submitting_model
  assert run_effect(dup_eff) == []

  // Completing the first save effect persists exactly 1 post, clears submitting, and resets form_key
  let model_done = list.fold(run_effect(save_eff), submitting_model, step)
  assert !model_done.submitting
  assert model_done.form_key == 1
  assert list.map(model_done.posts, fn(p) { p.body }) == ["only save once"]
  let assert Ok(db_rows) = post_repo.list_recent(tx, 10)
  assert list.length(db_rows) == 1
  assert string.contains(render_html(model_done), ">Post</button>")

  // PostSaveFailed also clears submitting so the user can retry without losing their draft
  let #(failed_model, _) =
    timeline.update(submitting_model, timeline.PostSaveFailed("DB error"))
  assert !failed_model.submitting
  assert failed_model.form_key == 0
  assert failed_model.form_error == Some("DB error")
}

pub fn submitting_posts_past_rate_limit_shows_error_and_preserves_draft_test() {
  use tx <- test_helper.with_db

  let assert Ok(alice) = user.create(tx, "BurstAlice")
  let assert Ok(bob) = user.create(tx, "BurstBob")
  let assert Ok(post_pubsub) = pubsub.start()
  let assert Ok(rate_limiter) =
    rate_limit.start_memory("timeline_rl_secret_key_base")

  let #(alice0, _) =
    timeline.init(timeline.Flags(
      db: tx,
      pubsub: post_pubsub,
      rate_limiter:,
      user: Some(alice),
      csrf_token: "alice-csrf",
    ))

  // Alice can publish up to burst (5) posts in rapid succession
  let alice_after_burst =
    int.range(
      from: 1,
      to: timeline.post_create_policy.burst + 1,
      with: alice0,
      run: fn(m, n) {
        step(
          m,
          timeline.UserSubmittedForm([#("body", "burst-" <> int.to_string(n))]),
        )
      },
    )
  assert alice_after_burst.form_key == timeline.post_create_policy.burst
  assert list.length(alice_after_burst.posts)
    == timeline.post_create_policy.burst
  assert alice_after_burst.form_error == None

  // 6th rapid post from Alice is rate-limited: preserves form_key (draft), clears submitting, shows error
  let alice_limited =
    step(
      alice_after_burst,
      timeline.UserSubmittedForm([#("body", "too fast post")]),
    )
  assert !alice_limited.submitting
  assert alice_limited.form_key == timeline.post_create_policy.burst
  assert list.length(alice_limited.posts) == timeline.post_create_policy.burst
  let assert Some(err_msg) = alice_limited.form_error
  assert string.contains(err_msg, "posting too fast")
  assert string.contains(render_html(alice_limited), "role=\"alert\"")

  // Bob has his own independent user_id quota and can still post
  let #(bob0, _) =
    timeline.init(timeline.Flags(
      db: tx,
      pubsub: post_pubsub,
      rate_limiter:,
      user: Some(bob),
      csrf_token: "bob-csrf",
    ))
  let bob1 = step(bob0, timeline.UserSubmittedForm([#("body", "bob ok post")]))
  assert bob1.form_key == 1
  assert bob1.form_error == None

  rate_limit.stop_memory(rate_limiter)
}

pub fn timeline_ws_read_and_delete_actions_enforce_rate_limits_test() {
  use tx <- test_helper.with_db

  let assert Ok(alice) = user.create(tx, "WsRateAlice")
  let assert Ok(bob) = user.create(tx, "WsRateBob")
  let assert Ok(post_pubsub) = pubsub.start()
  let assert Ok(rate_limiter) =
    rate_limit.start_memory("timeline_ws_read_delete_rl_secret")

  // Seed 25 posts by Alice so `has_more` is True (`page_size == 20`)
  let created_posts =
    int.range(from: 1, to: 26, with: [], run: fn(acc, n) {
      let assert Ok(row) =
        post_repo.create(tx, alice.id, "ws-rl-post-" <> int.to_string(n))
      [row, ..acc]
    })
  let assert [newest_post, ..] = created_posts

  let #(alice0, _) =
    timeline.init(timeline.Flags(
      db: tx,
      pubsub: post_pubsub,
      rate_limiter:,
      user: Some(alice),
      csrf_token: "alice-csrf",
    ))
  assert alice0.has_more

  // 1. Authenticated WS read quota (`ws:read:user:<id>`, burst 20) throttles Refresh & LoadMore
  let alice_exhausted_reads =
    int.range(
      from: 1,
      to: timeline.ws_read_policy.burst + 1,
      with: alice0,
      run: fn(m, _) { step(m, timeline.UserClickedRefresh) },
    )
  assert alice_exhausted_reads.timeline_error == None

  // 21st read via Refresh is throttled without querying DB
  let alice_refresh_limited =
    step(alice_exhausted_reads, timeline.UserClickedRefresh)
  assert !alice_refresh_limited.loading_newer
  let assert Some(read_err) = alice_refresh_limited.timeline_error
  assert string.contains(read_err, "Too many requests")

  // LoadMore shares the same `ws:read:user:<alice>` bucket and is also throttled!
  let alice_load_more_limited =
    step(
      step(alice_refresh_limited, timeline.UserDismissedError),
      timeline.UserRequestedLoadMore,
    )
  assert !alice_load_more_limited.loading_more
  assert list.length(alice_load_more_limited.posts) == timeline.page_size
  let assert Some(load_more_err) = alice_load_more_limited.timeline_error
  assert string.contains(load_more_err, "Too many requests")

  // Bob's authenticated WS read quota is independent and loads older posts cleanly
  let #(bob0, _) =
    timeline.init(timeline.Flags(
      db: tx,
      pubsub: post_pubsub,
      rate_limiter:,
      user: Some(bob),
      csrf_token: "bob-csrf",
    ))
  let bob_loaded_more = step(bob0, timeline.UserRequestedLoadMore)
  assert bob_loaded_more.timeline_error == None
  assert list.length(bob_loaded_more.posts) == 25

  // 2. Anonymous WS connections from the same IP (/32 IPv4 or /64 IPv6) share `ws:read:ip:<bucket>`!
  let #(anon_a, _) =
    timeline.init_with_ip(
      timeline.Flags(
        db: tx,
        pubsub: post_pubsub,
        rate_limiter:,
        user: None,
        csrf_token: "anon-a",
      ),
      "2001:db8:abcd:42::1",
    )
  let #(anon_b, _) =
    timeline.init_with_ip(
      timeline.Flags(
        db: tx,
        pubsub: post_pubsub,
        rate_limiter:,
        user: None,
        csrf_token: "anon-b",
      ),
      "2001:db8:abcd:42:ffff::99",
    )
  let #(anon_other_net, _) =
    timeline.init_with_ip(
      timeline.Flags(
        db: tx,
        pubsub: post_pubsub,
        rate_limiter:,
        user: None,
        csrf_token: "anon-c",
      ),
      "2001:db8:abcd:43::1",
    )

  let _ =
    int.range(
      from: 1,
      to: timeline.ws_read_policy.burst + 1,
      with: anon_a,
      run: fn(m, _) { step(m, timeline.UserClickedRefresh) },
    )
  // Separate anonymous connection in the same IPv6 /64 is throttled!
  let anon_b_limited = step(anon_b, timeline.UserRequestedLoadMore)
  assert list.length(anon_b_limited.posts) == timeline.page_size
  let assert Some(anon_err) = anon_b_limited.timeline_error
  assert string.contains(anon_err, "Too many requests")

  // Anonymous connection in a different /64 is unaffected
  let anon_other_ok = step(anon_other_net, timeline.UserRequestedLoadMore)
  assert anon_other_ok.timeline_error == None
  assert list.length(anon_other_ok.posts) == 25

  // 3. WS `UserConfirmedDelete` enforces `http:write:user:<id>` (burst 10)!
  let _ =
    int.range(
      from: 1,
      to: timeline.delete_write_policy.burst + 1,
      with: Nil,
      run: fn(_, _) {
        let _ =
          rate_limit.check(
            rate_limiter,
            "http:write:user:" <> int.to_string(alice.id),
            timeline.delete_write_policy,
          )
        Nil
      },
    )

  let alice_delete_blocked =
    alice0
    |> step(timeline.UserRequestedDelete(newest_post.id))
    |> step(timeline.UserConfirmedDelete(newest_post.id))

  let assert Some(del_err) = alice_delete_blocked.timeline_error
  assert string.contains(del_err, "Too many requests")
  // Post was NOT deleted in PostgreSQL while write-throttled!
  let assert Ok(Some(_)) = post_repo.find_by_id(tx, newest_post.id)

  rate_limit.stop_memory(rate_limiter)
}
