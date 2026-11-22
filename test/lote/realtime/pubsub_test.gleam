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

pub fn postgres_adapter_delivers_events_across_multiple_pubsub_instances_via_listen_notify_test() {
  let cfg = config.load()
  let pool_name = process.new_name("lote_pubsub_test_db")
  let assert Ok(db_config) = pog.url_config(pool_name, cfg.database_url)
  let db_config =
    db_config
    |> pog.pool_size(2)
    |> pog.connection_parameter("timezone", "UTC")
  let assert Ok(started_pool) = pog.start(db_config)
  let db = started_pool.data

  // Start two independent Postgres-backed PubSub instances simulating two Cloud Run containers
  let assert Ok(node_a_post_bus) =
    lote.start_post_pubsub(config.PostgresPubSub, db, cfg.database_url)
  let assert Ok(node_b_post_bus) =
    lote.start_post_pubsub(config.PostgresPubSub, db, cfg.database_url)

  let sub_a = process.new_subject()
  let sub_b = process.new_subject()
  pubsub.subscribe(node_a_post_bus, sub_a)
  pubsub.subscribe(node_b_post_bus, sub_b)
  assert pubsub.subscriber_count(node_a_post_bus) == 1
  assert pubsub.subscriber_count(node_b_post_bus) == 1

  let sample_post =
    timeline.Post(
      id: "019352a0-5678-7000-8000-000000000002",
      user_id: 7,
      author_name: "Bob",
      body: "Multi-node LISTEN/NOTIFY post",
      created_at: timestamp.from_unix_seconds_and_nanoseconds(
        1_732_250_100,
        42_000,
      ),
    )

  // 1. Publishing on Node A sends pg_notify; both Node A and Node B receive it via PostgreSQL LISTEN!
  pubsub.publish(node_a_post_bus, timeline.Created(sample_post))
  assert process.receive(sub_a, 500) == Ok(timeline.Created(sample_post))
  assert process.receive(sub_b, 500) == Ok(timeline.Created(sample_post))
  // Ensure no duplicate delivery on Node A
  assert process.receive(sub_a, 30) == Error(Nil)

  // 2. Publishing Deleted on Node B is received by Node A via PostgreSQL LISTEN
  let deleted_event = timeline.Deleted(sample_post.id)
  pubsub.publish(node_b_post_bus, deleted_event)
  assert process.receive(sub_a, 500) == Ok(deleted_event)
  assert process.receive(sub_b, 500) == Ok(deleted_event)

  // 3. Two independent session_revocations PubSub instances also sync across nodes via LISTEN/NOTIFY
  let assert Ok(node_a_revocation_bus) =
    lote.start_session_revocations_pubsub(
      config.PostgresPubSub,
      db,
      cfg.database_url,
    )
  let assert Ok(node_b_revocation_bus) =
    lote.start_session_revocations_pubsub(
      config.PostgresPubSub,
      db,
      cfg.database_url,
    )
  let rev_sub_a = process.new_subject()
  let rev_sub_b = process.new_subject()
  pubsub.subscribe(node_a_revocation_bus, rev_sub_a)
  pubsub.subscribe(node_b_revocation_bus, rev_sub_b)
  assert pubsub.subscriber_count(node_a_revocation_bus) == 1
  assert pubsub.subscriber_count(node_b_revocation_bus) == 1

  pubsub.publish(node_a_revocation_bus, "revoked-session-xyz")
  assert process.receive(rev_sub_a, 500) == Ok("revoked-session-xyz")
  assert process.receive(rev_sub_b, 500) == Ok("revoked-session-xyz")

  // 4. Malformed payload on channel is safely ignored without crashing the listener
  let assert Ok(Nil) =
    pubsub.pg_notify(db, lote.post_events_channel, "invalid-json-payload")
  assert process.receive(sub_a, 50) == Error(Nil)
  assert process.receive(sub_b, 50) == Error(Nil)

  process.send_exit(started_pool.pid)
}
