import pog

pub type Method {
  Password
}

pub type Auth {
  Auth(db: pog.Connection, secret_key_base: String, methods: List(Method))
}
