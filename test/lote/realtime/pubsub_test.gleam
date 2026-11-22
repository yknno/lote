import gleam/erlang/process
import gleam/time/timestamp
import lote
import lote/config
import lote/realtime/pubsub
import lote/test_helper
import lote/web/components/timeline
import pog

pub fn publish_broadcasts_to_all_subscribers_test() {
  let assert Ok(bus) = pubsub.start()
  let sub1 = process.new_subject()
  let sub2 = process.new_subject()

  pubsub.subscribe(bus, sub1)
  pubsub.subscribe(bus, sub2)
  assert pubsub.subscriber_count(bus) == 2

  pubsub.publish(bus, "hello")

  assert process.receive(sub1, 100) == Ok("hello")
  assert process.receive(sub2, 100) == Ok("hello")
}

pub fn unsubscribe_stops_delivery_test() {
  let assert Ok(bus) = pubsub.start()
  let sub1 = process.new_subject()
  let sub2 = process.new_subject()

  pubsub.subscribe(bus, sub1)
  pubsub.subscribe(bus, sub2)
  pubsub.unsubscribe(bus, sub1)
  assert pubsub.subscriber_count(bus) == 1

  pubsub.publish(bus, "world")

  assert process.receive(sub1, 50) == Error(Nil)
  assert process.receive(sub2, 100) == Ok("world")
}

pub fn dead_subscriber_process_is_automatically_removed_test() {
  let assert Ok(bus) = pubsub.start()
  let ready = process.new_subject()

  let worker_pid =
    process.spawn_unlinked(fn() {
      let sub = process.new_subject()
      let stop = process.new_subject()
      pubsub.subscribe(bus, sub)
      process.send(ready, stop)
      let _ = process.receive(stop, 1000)
      Nil
    })

  let assert Ok(stop) = process.receive(ready, 500)
  assert pubsub.subscriber_count(bus) == 1

  let mon = process.monitor(worker_pid)
  process.send(stop, Nil)
  let down_selector =
    process.new_selector()
    |> process.select_specific_monitor(mon, fn(down) { down })
  let assert Ok(_) = process.selector_receive(down_selector, 500)

  assert test_helper.wait_until(100, 5, fn() {
    pubsub.subscriber_count(bus) == 0
  })
}

pub fn duplicate_subscribe_is_idempotent_test() {
  let assert Ok(bus) = pubsub.start()
  let sub = process.new_subject()

  pubsub.subscribe(bus, sub)
  pubsub.subscribe(bus, sub)
  assert pubsub.subscriber_count(bus) == 1

  pubsub.publish(bus, "once")

  assert process.receive(sub, 100) == Ok("once")
  assert process.receive(sub, 50) == Error(Nil)
}

pub fn parse_pubsub_adapter_selects_memory_or_postgres_test() {
  assert config.parse_pubsub_adapter("") == config.MemoryPubSub
  assert config.parse_pubsub_adapter("memory") == config.MemoryPubSub
  assert config.parse_pubsub_adapter("unknown") == config.MemoryPubSub
  assert config.parse_pubsub_adapter("postgres") == config.PostgresPubSub
  assert config.parse_pubsub_adapter("  PostgreSQL ") == config.PostgresPubSub
}

pub fn post_event_codec_roundtrips_created_and_deleted_events_test() {
  let post =
    timeline.Post(
      id: "019352a0-1234-7000-8000-000000000001",
      user_id: 42,
      author_name: "Alice",
      body: "Hello PubSub JSON!",
      created_at: timestamp.from_unix_seconds_and_nanoseconds(
        1_732_250_000,
        123_456_789,
      ),
    )

  let created_event = timeline.Created(post)
  let encoded_created = timeline.encode_post_event(created_event)
  assert timeline.decode_post_event(encoded_created) == Ok(created_event)

  let deleted_event = timeline.Deleted(post.id)
  let encoded_deleted = timeline.encode_post_event(deleted_event)
  assert timeline.decode_post_event(encoded_deleted) == Ok(deleted_event)

  assert timeline.decode_post_event("{invalid json") == Error(Nil)
  assert timeline.decode_post_event("{\"type\":\"unknown\"}") == Error(Nil)
}

pub fn postgres_adapter_publishes_via_pg_notify_and_decodes_incoming_payloads_test() {
  let cfg = config.load()
  let pool_name = process.new_name("lote_pubsub_test_db")
  let assert Ok(db_config) = pog.url_config(pool_name, cfg.database_url)
  let db_config =
    db_config
    |> pog.pool_size(1)
    |> pog.connection_parameter("timezone", "UTC")
  let assert Ok(started_pool) = pog.start(db_config)
  let db = started_pool.data

  let assert Ok(post_bus) = lote.start_post_pubsub(config.PostgresPubSub, db)
  let post_sub = process.new_subject()
  pubsub.subscribe(post_bus, post_sub)

  let sample_post =
    timeline.Post(
      id: "019352a0-5678-7000-8000-000000000002",
      user_id: 7,
      author_name: "Bob",
      body: "Postgres adapter post",
      created_at: timestamp.from_unix_seconds(1_732_250_100),
    )

  // 1. publish delivers locally AND executes SELECT pg_notify($1, $2) on Postgres
  pubsub.publish(post_bus, timeline.Created(sample_post))
  assert process.receive(post_sub, 200) == Ok(timeline.Created(sample_post))

  // 2. receive_payload decodes an external payload (e.g. from a notification bridge)
  //    and fans it out to local subscribers; malformed payloads are ignored.
  let remote_deleted = timeline.Deleted(sample_post.id)
  pubsub.receive_payload(post_bus, timeline.encode_post_event(remote_deleted))
  assert process.receive(post_sub, 100) == Ok(remote_deleted)

  pubsub.receive_payload(post_bus, "invalid-json-payload")
  assert process.receive(post_sub, 30) == Error(Nil)

  // 3. broadcast_local fans out directly to local subscribers without re-triggering pg_notify
  pubsub.broadcast_local(post_bus, remote_deleted)
  assert process.receive(post_sub, 100) == Ok(remote_deleted)

  // 4. session_revocations Postgres adapter also round-trips and ignores empty payloads
  let assert Ok(revocation_bus) =
    lote.start_session_revocations_pubsub(config.PostgresPubSub, db)
  let revocation_sub = process.new_subject()
  pubsub.subscribe(revocation_bus, revocation_sub)

  pubsub.publish(revocation_bus, "session-abc")
  assert process.receive(revocation_sub, 200) == Ok("session-abc")

  pubsub.receive_payload(revocation_bus, "session-from-other-node")
  assert process.receive(revocation_sub, 100) == Ok("session-from-other-node")

  pubsub.receive_payload(revocation_bus, "")
  assert process.receive(revocation_sub, 30) == Error(Nil)

  // Ensure actors have finished their synchronous pg_notify call before stopping pool
  assert pubsub.subscriber_count(post_bus) == 1
  assert pubsub.subscriber_count(revocation_bus) == 1
  process.send_exit(started_pool.pid)
}
