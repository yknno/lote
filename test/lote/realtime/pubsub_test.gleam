import gleam/erlang/process
import lote/realtime/pubsub

pub fn publish_broadcasts_to_all_subscribers_test() {
  let assert Ok(bus) = pubsub.start()
  let sub1 = process.new_subject()
  let sub2 = process.new_subject()

  pubsub.subscribe(bus, sub1)
  pubsub.subscribe(bus, sub2)
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
  pubsub.publish(bus, "world")

  assert process.receive(sub1, 50) == Error(Nil)
  assert process.receive(sub2, 100) == Ok("world")
}
