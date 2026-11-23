import gleam/bit_array
import gleam/dynamic/decode
import gleam/erlang/process
import gleam/list
import gleam/otp/static_supervisor as supervisor
import gleam/string
import gleam/time/duration
import gleam/time/timestamp
import lote
import lote/auth/user
import lote/config
import lote/db/post_repo
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

pub fn parse_pubsub_adapter_selects_memory_or_postgres_and_rejects_typo_test() {
  assert config.parse_pubsub_adapter("") == Ok(config.MemoryPubSub)
  assert config.parse_pubsub_adapter("  ") == Ok(config.MemoryPubSub)
  assert config.parse_pubsub_adapter("memory") == Ok(config.MemoryPubSub)
  assert config.parse_pubsub_adapter("MEMORY") == Ok(config.MemoryPubSub)
  assert config.parse_pubsub_adapter("postgres") == Ok(config.PostgresPubSub)
  assert config.parse_pubsub_adapter("  PostgreSQL ")
    == Ok(config.PostgresPubSub)
  assert config.parse_pubsub_adapter("postgers") == Error("postgers")
  assert config.parse_pubsub_adapter(" unknown ") == Error("unknown")
}

pub fn post_event_codec_uses_compact_id_only_payloads_test() {
  // Even with a large body (e.g. multibyte emoji sequences), the NOTIFY payload
  // carries only the event type and post ID, staying far below 8000 bytes.
  let huge_body = string.repeat("👨‍👩‍👧‍👦", 300)
  assert bit_array.byte_size(<<huge_body:utf8>>) > 7000

  let post =
    timeline.Post(
      id: "019352a0-1234-7000-8000-000000000001",
      user_id: 42,
      author_name: "Alice",
      body: huge_body,
      created_at: timestamp.from_unix_seconds_and_nanoseconds(
        1_732_250_000,
        123_456_789,
      ),
    )

  let encoded_created = timeline.encode_post_event(timeline.Created(post))
  assert bit_array.byte_size(<<encoded_created:utf8>>) < 100
  assert timeline.decode_post_notification(encoded_created)
    == Ok(timeline.PostCreatedNotification(post.id))

  let encoded_deleted = timeline.encode_post_event(timeline.Deleted(post.id))
  assert bit_array.byte_size(<<encoded_deleted:utf8>>) < 100
  assert timeline.decode_post_notification(encoded_deleted)
    == Ok(timeline.PostDeletedNotification(post.id))

  assert timeline.decode_post_notification("{invalid json") == Error(Nil)
  assert timeline.decode_post_notification("{\"type\":\"unknown\"}")
    == Error(Nil)
}

fn wait_until_listening(
  db: pog.Connection,
  channel: String,
  probe: String,
  check: fn() -> Bool,
) -> Bool {
  test_helper.wait_until(40, 50, fn() {
    let _ = pubsub.pg_notify(db, channel, probe)
    check()
  })
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

  // Insert a real user & post so ID-only Postgres notifications resolve via DB
  let assert Ok(author) = user.create(db, "PubSubBob")
  let assert Ok(created_row) =
    post_repo.create(db, author.id, "Multi-node LISTEN/NOTIFY post")

  let sample_post =
    timeline.Post(
      id: created_row.id,
      user_id: author.id,
      author_name: author.name,
      body: created_row.body,
      created_at: created_row.created_at,
    )

  // Start two independent Postgres-backed PubSub instances simulating two containers
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

  // Wait for async LISTEN connections on both nodes to become active in pg_stat_activity
  let pid_decoder = {
    use pid <- decode.field(0, decode.int)
    decode.success(pid)
  }
  assert test_helper.wait_until(40, 25, fn() {
    case
      pog.query(
        "SELECT pid FROM pg_stat_activity WHERE pid <> pg_backend_pid() AND query ILIKE $1",
      )
      |> pog.parameter(pog.text("%" <> lote.post_events_channel <> "%"))
      |> pog.returning(pid_decoder)
      |> pog.execute(db)
    {
      Ok(r) -> list.length(r.rows) >= 2
      Error(_) -> False
    }
  })

  // 1. Publishing on Node A sends compact ID-only pg_notify; both nodes resolve and receive it
  pubsub.publish(node_a_post_bus, timeline.Created(sample_post))
  assert process.receive(sub_a, 1000) == Ok(timeline.Created(sample_post))
  assert process.receive(sub_b, 1000) == Ok(timeline.Created(sample_post))
  // Ensure no duplicate delivery on Node A
  assert process.receive(sub_a, 30) == Error(Nil)

  // 2. Publishing Deleted on Node B is received by Node A via PostgreSQL LISTEN
  let deleted_event = timeline.Deleted(sample_post.id)
  pubsub.publish(node_b_post_bus, deleted_event)
  assert process.receive(sub_a, 1000) == Ok(deleted_event)
  assert process.receive(sub_b, 1000) == Ok(deleted_event)

  // 3. Two independent session_revocations PubSub instances also sync across nodes
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

  assert test_helper.wait_until(40, 25, fn() {
    case
      pog.query(
        "SELECT pid FROM pg_stat_activity WHERE pid <> pg_backend_pid() AND query ILIKE $1",
      )
      |> pog.parameter(pog.text("%" <> lote.session_revocations_channel <> "%"))
      |> pog.returning(pid_decoder)
      |> pog.execute(db)
    {
      Ok(r) -> list.length(r.rows) >= 2
      Error(_) -> False
    }
  })

  pubsub.publish(node_a_revocation_bus, "revoked-session-xyz")
  assert process.receive(rev_sub_a, 1000) == Ok("revoked-session-xyz")
  assert process.receive(rev_sub_b, 1000) == Ok("revoked-session-xyz")

  // 4. Malformed payload on channel is safely ignored without crashing the listener
  let assert Ok(Nil) =
    pubsub.pg_notify(db, lote.post_events_channel, "invalid-json-payload")
  assert process.receive(sub_a, 50) == Error(Nil)
  assert process.receive(sub_b, 50) == Error(Nil)

  // Clean up test rows so subsequent tests see an empty posts table
  let assert Ok(True) = post_repo.delete(db, created_row.id, author.id)
  let assert Ok(_) =
    pog.query("DELETE FROM users WHERE id = $1")
    |> pog.parameter(pog.int(author.id))
    |> pog.returning(decode.dynamic)
    |> pog.execute(db)

  pubsub.stop(node_a_post_bus)
  pubsub.stop(node_b_post_bus)
  pubsub.stop(node_a_revocation_bus)
  pubsub.stop(node_b_revocation_bus)
  process.send_exit(started_pool.pid)
}

pub fn postgres_publish_is_non_blocking_and_oversized_payload_falls_back_locally_test() {
  let cfg = config.load()
  let pool_name = process.new_name("lote_pubsub_async_test_db")
  let assert Ok(db_config) = pog.url_config(pool_name, cfg.database_url)
  let db_config =
    db_config
    |> pog.pool_size(2)
    |> pog.connection_parameter("timezone", "UTC")
  let assert Ok(started_pool) = pog.start(db_config)
  let db = started_pool.data

  let channel = "lote_test_async_and_limit"
  let adapter =
    pubsub.Postgres(
      db:,
      database_url: cfg.database_url,
      channel:,
      encode: fn(msg) {
        case msg {
          "slow" -> {
            process.sleep(250)
            "slow"
          }
          other -> other
        }
      },
      decode: fn(raw) { Ok(raw) },
    )

  let assert Ok(bus) = pubsub.start_with_adapter(adapter)
  let sub = process.new_subject()
  pubsub.subscribe(bus, sub)
  assert pubsub.subscriber_count(bus) == 1

  assert wait_until_listening(db, channel, "warmup", fn() {
    process.receive(sub, 50) == Ok("warmup")
  })

  // Trigger a slow publish and verify the PubSub actor itself remains responsive immediately
  let started_at = timestamp.system_time()
  pubsub.publish(bus, "slow")
  assert pubsub.subscriber_count(bus) == 1
  let elapsed_ms =
    timestamp.difference(started_at, timestamp.system_time())
    |> duration.to_milliseconds
  assert elapsed_ms < 150

  // The slow publish still completes and arrives via LISTEN/NOTIFY
  assert process.receive(sub, 1000) == Ok("slow")

  // A payload exceeding PostgreSQL's 8000-byte limit falls back cleanly to local delivery
  let oversized = string.repeat("a", pubsub.max_notify_payload_bytes + 100)
  pubsub.publish(bus, oversized)
  assert process.receive(sub, 500) == Ok(oversized)

  // Normal events continue flowing via Postgres after an oversized payload
  pubsub.publish(bus, "after-oversized")
  assert process.receive(sub, 1000) == Ok("after-oversized")

  pubsub.stop(bus)
  process.send_exit(started_pool.pid)
}

pub fn postgres_listener_reconnects_after_backend_termination_preserving_subscribers_test() {
  let cfg = config.load()
  let pool_name = process.new_name("lote_pubsub_reconnect_test_db")
  let assert Ok(db_config) = pog.url_config(pool_name, cfg.database_url)
  let db_config =
    db_config
    |> pog.pool_size(2)
    |> pog.connection_parameter("timezone", "UTC")
  let assert Ok(started_pool) = pog.start(db_config)
  let db = started_pool.data

  let channel = "lote_test_reconnect_channel"
  let adapter =
    pubsub.Postgres(
      db:,
      database_url: cfg.database_url,
      channel:,
      encode: fn(msg) { msg },
      decode: fn(raw) { Ok(raw) },
    )

  let assert Ok(bus) = pubsub.start_with_adapter(adapter)
  let sub = process.new_subject()
  pubsub.subscribe(bus, sub)
  assert pubsub.subscriber_count(bus) == 1

  assert wait_until_listening(db, channel, "before-drop", fn() {
    process.receive(sub, 50) == Ok("before-drop")
  })

  // Simulate DB restart / admin disconnect by terminating the LISTEN backend connection
  let pid_decoder = {
    use pid <- decode.field(0, decode.int)
    decode.success(pid)
  }
  let assert Ok(returned) =
    pog.query(
      "SELECT pid FROM pg_stat_activity WHERE pid <> pg_backend_pid() AND query ILIKE $1",
    )
    |> pog.parameter(pog.text("%" <> channel <> "%"))
    |> pog.returning(pid_decoder)
    |> pog.execute(db)
  assert list.length(returned.rows) >= 1

  list.each(returned.rows, fn(backend_pid) {
    let assert Ok(_) =
      pog.query("SELECT pg_terminate_backend($1)")
      |> pog.parameter(pog.int(backend_pid))
      |> pog.returning(decode.dynamic)
      |> pog.execute(db)
    Nil
  })

  // Wait for automatic reconnect and verify the existing subscriber receives new events
  // without re-subscribing and without crashing the PubSub actor
  assert wait_until_listening(db, channel, "after-reconnect", fn() {
    case process.receive(sub, 80) {
      Ok("after-reconnect") -> True
      _ -> False
    }
  })
  assert pubsub.subscriber_count(bus) == 1

  pubsub.stop(bus)
  process.send_exit(started_pool.pid)
}

pub fn postgres_pubsub_rejects_invalid_channel_identifier_and_starts_without_blocking_when_db_down_test() {
  let cfg = config.load()
  let pool_name = process.new_name("lote_pubsub_nonblocking_init_db")
  let assert Ok(db_config) = pog.url_config(pool_name, cfg.database_url)
  let db = pog.named_connection(pool_name)
  let _ = db_config

  // 1. Invalid SQL identifier channel name is rejected immediately at startup
  let bad_channel_adapter =
    pubsub.Postgres(
      db:,
      database_url: cfg.database_url,
      channel: "invalid-channel; DROP TABLE posts;--",
      encode: fn(s) { s },
      decode: fn(s) { Ok(s) },
    )
  let assert Error(_) = pubsub.start_with_adapter(bad_channel_adapter)

  // 2. Unreachable DB host/port does NOT block actor initialisation for 4s
  let worker_pids_subject = process.new_subject()
  let started_at = timestamp.system_time()
  let unreachable_adapter =
    pubsub.Postgres(
      db:,
      database_url: "postgres://postgres:postgres@127.0.0.1:59999/lote",
      channel: "lote_unreachable_test",
      encode: fn(s) {
        process.send(worker_pids_subject, process.self())
        s
      },
      decode: fn(s) {
        process.send(worker_pids_subject, process.self())
        Ok(s)
      },
    )
  let assert Ok(bus) = pubsub.start_with_adapter(unreachable_adapter)
  let elapsed_ms =
    timestamp.difference(started_at, timestamp.system_time())
    |> duration.to_milliseconds
  assert elapsed_ms < 200
  assert pubsub.subscriber_count(bus) == 0

  // Capture publisher and decoder worker PIDs and verify pubsub.stop terminates both
  pubsub.publish(bus, "probe-pub")
  let assert Ok(publisher_pid) = process.receive(worker_pids_subject, 200)
  pubsub.receive_payload(bus, "probe-dec")
  let assert Ok(decoder_pid) = process.receive(worker_pids_subject, 200)
  assert process.is_alive(publisher_pid)
  assert process.is_alive(decoder_pid)

  pubsub.stop(bus)
  assert test_helper.wait_until(50, 10, fn() {
    !process.is_alive(publisher_pid) && !process.is_alive(decoder_pid)
  })
}

pub fn supervised_named_pubsub_restarts_automatically_after_crash_test() {
  let name = process.new_name("lote_supervised_pubsub_test")
  let bus = process.named_subject(name)

  let assert Ok(sup) =
    supervisor.new(supervisor.OneForOne)
    |> supervisor.add(pubsub.supervised(name, pubsub.Memory))
    |> supervisor.start

  let assert Ok(original_pid) = process.named(name)
  let sub1 = process.new_subject()
  pubsub.subscribe(bus, sub1)

  // Also register a subscriber owned by a short-lived process that exits right as PubSub crashes
  let ephemeral_ready = process.new_subject()
  let ephemeral_pid =
    process.spawn_unlinked(fn() {
      let ephemeral_sub = process.new_subject()
      pubsub.subscribe(bus, ephemeral_sub)
      process.send(ephemeral_ready, Nil)
      process.sleep_forever()
    })
  let assert Ok(Nil) = process.receive(ephemeral_ready, 200)
  assert pubsub.subscriber_count(bus) == 2

  // Kill the ephemeral subscriber and force-kill the PubSub actor;
  // the supervisor must restart PubSub under the same name, restore living
  // subscribers (sub1) without re-subscribing, and prune dead ones.
  process.kill(ephemeral_pid)
  process.kill(original_pid)

  assert test_helper.wait_until(100, 10, fn() {
    case process.named(name) {
      Ok(new_pid) -> new_pid != original_pid && process.is_alive(new_pid)
      Error(_) -> False
    }
  })

  // Existing subscriber sub1 is automatically restored and receives events without re-subscribing
  assert pubsub.subscriber_count(bus) == 1
  pubsub.publish(bus, "recovered-for-existing-sub")
  assert process.receive(sub1, 200) == Ok("recovered-for-existing-sub")

  // New subscribers also work alongside restored subscribers
  let sub2 = process.new_subject()
  pubsub.subscribe(bus, sub2)
  assert pubsub.subscriber_count(bus) == 2
  pubsub.publish(bus, "recovered-for-both")
  assert process.receive(sub1, 200) == Ok("recovered-for-both")
  assert process.receive(sub2, 200) == Ok("recovered-for-both")

  // Unsubscribing sub1 removes it from ETS so a second crash does not resurrect it
  pubsub.unsubscribe(bus, sub1)
  assert pubsub.subscriber_count(bus) == 1
  let assert Ok(second_pid) = process.named(name)
  process.kill(second_pid)
  assert test_helper.wait_until(100, 10, fn() {
    case process.named(name) {
      Ok(third_pid) -> third_pid != second_pid && process.is_alive(third_pid)
      Error(_) -> False
    }
  })
  assert pubsub.subscriber_count(bus) == 1
  pubsub.publish(bus, "after-second-restart")
  assert process.receive(sub2, 200) == Ok("after-second-restart")
  assert process.receive(sub1, 30) == Error(Nil)

  process.send_exit(sup.pid)

  // Calling publish/subscribe/unsubscribe while a named PubSub is unregistered
  // (e.g. during the brief window between crash and supervisor restart) must not panic,
  // and a subscriber registered during that window is restored once the actor starts.
  let gap_name = process.new_name("lote_unregistered_gap_pubsub_test")
  let gap_bus = process.named_subject(gap_name)
  let gap_sub = process.new_subject()
  pubsub.publish(gap_bus, "dropped-during-restart")
  pubsub.subscribe(gap_bus, gap_sub)

  let assert Ok(started_gap) = pubsub.start_named(gap_name, pubsub.Memory)
  assert pubsub.subscriber_count(gap_bus) == 1
  pubsub.publish(gap_bus, "delivered-after-start")
  assert process.receive(gap_sub, 200) == Ok("delivered-after-start")
  pubsub.stop(started_gap.data)
}
