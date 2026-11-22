import gleam/erlang/process
import lote/realtime/pubsub

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

  // Allow the pubsub actor to process the monitor DOWN message before counting.
  process.sleep(10)
  assert pubsub.subscriber_count(bus) == 0
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
