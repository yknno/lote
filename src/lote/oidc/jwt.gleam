import gleam/bit_array
import gleam/crypto
import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string

pub const id_token_ttl_seconds = 3600

pub opaque type SigningKey {
  SigningKey(
    kid: String,
    priv_scalar: BitArray,
    x: BitArray,
    y: BitArray,
    x_b64: String,
    y_b64: String,
  )
}

pub opaque type VerifyKey {
  VerifyKey(kid: String, x: BitArray, y: BitArray, x_b64: String, y_b64: String)
}

pub opaque type Keyring {
  Keyring(active: SigningKey, verify_keys: List(VerifyKey))
}

pub type IdTokenClaims {
  IdTokenClaims(
    iss: String,
    sub: String,
    aud: String,
    iat: Int,
    exp: Int,
    nonce: Option(String),
    at_hash: Option(String),
    name: Option(String),
  )
}

pub type JwtError {
  InvalidPem(String)
  InvalidFormat
  UnsupportedAlgorithm
  UnknownKey
  InvalidSignature
  InvalidClaims(String)
  ExpiredToken
}

type DecodedHeader {
  DecodedHeader(alg: String, kid: Option(String), typ: Option(String))
}

pub fn generate_signing_key() -> SigningKey {
  let #(priv_scalar, x, y) = ffi_generate_p256_key()
  signing_key_from_parts(priv_scalar, x, y)
}

pub fn default_keyring() -> Keyring {
  let #(priv_scalar, x, y) = ffi_default_ephemeral_p256_key()
  let active = signing_key_from_parts(priv_scalar, x, y)
  new_keyring(active, [])
}

pub fn parse_signing_key_pem(pem: String) -> Result(SigningKey, JwtError) {
  case ffi_parse_signing_key_pem(pem) {
    Ok(#(priv_scalar, x, y)) -> Ok(signing_key_from_parts(priv_scalar, x, y))
    Error(reason) -> Error(InvalidPem(reason))
  }
}

pub fn parse_verify_keys_pem(pem: String) -> Result(List(VerifyKey), JwtError) {
  case ffi_parse_verify_keys_pem(pem) {
    Ok(points) ->
      Ok(list.map(points, fn(xy) { verify_key_from_parts(xy.0, xy.1) }))
    Error(reason) -> Error(InvalidPem(reason))
  }
}

pub fn signing_key_to_verify_key(key: SigningKey) -> VerifyKey {
  VerifyKey(
    kid: key.kid,
    x: key.x,
    y: key.y,
    x_b64: key.x_b64,
    y_b64: key.y_b64,
  )
}

pub fn active_kid(keyring: Keyring) -> String {
  keyring.active.kid
}

pub fn new_keyring(
  active: SigningKey,
  additional_verify_keys: List(VerifyKey),
) -> Keyring {
  let active_verify = signing_key_to_verify_key(active)
  let verify_keys =
    dedup_verify_keys([active_verify, ..additional_verify_keys], [])
  Keyring(active:, verify_keys:)
}

pub fn load_keyring_from_pem(
  signing_pem: Option(String),
  verify_pem: Option(String),
) -> Result(#(Keyring, Bool), JwtError) {
  use #(active, is_ephemeral) <- result.try(case signing_pem {
    None -> Ok(#(generate_signing_key(), True))
    Some(pem) -> {
      use key <- result.try(parse_signing_key_pem(pem))
      Ok(#(key, False))
    }
  })

  use extra_verify <- result.try(case verify_pem {
    None -> Ok([])
    Some(vpem) -> parse_verify_keys_pem(vpem)
  })

  Ok(#(new_keyring(active, extra_verify), is_ephemeral))
}

pub fn jwks_json(keyring: Keyring) -> String {
  json.object([
    #(
      "keys",
      json.array(keyring.verify_keys, fn(key) {
        json.object([
          #("kty", json.string("EC")),
          #("crv", json.string("P-256")),
          #("use", json.string("sig")),
          #("alg", json.string("ES256")),
          #("kid", json.string(key.kid)),
          #("x", json.string(key.x_b64)),
          #("y", json.string(key.y_b64)),
        ])
      }),
    ),
  ])
  |> json.to_string
}

pub fn compute_at_hash(access_token: String) -> String {
  let digest = crypto.hash(crypto.Sha256, <<access_token:utf8>>)
  case digest {
    <<left128:bytes-size(16), _:bytes>> ->
      bit_array.base64_url_encode(left128, False)
    _ -> ""
  }
}

pub fn now_unix_seconds() -> Int {
  ffi_unix_now_seconds()
}

pub fn sign_id_token(keyring: Keyring, claims: IdTokenClaims) -> String {
  let header_json =
    json.object([
      #("alg", json.string("ES256")),
      #("kid", json.string(keyring.active.kid)),
      #("typ", json.string("JWT")),
    ])
    |> json.to_string

  let payload_fields =
    [
      #("iss", json.string(claims.iss)),
      #("sub", json.string(claims.sub)),
      #("aud", json.string(claims.aud)),
      #("exp", json.int(claims.exp)),
      #("iat", json.int(claims.iat)),
    ]
    |> append_optional_string("nonce", claims.nonce)
    |> append_optional_string("at_hash", claims.at_hash)
    |> append_optional_string("name", claims.name)

  let payload_json =
    json.object(payload_fields)
    |> json.to_string

  let header_b64 = bit_array.base64_url_encode(<<header_json:utf8>>, False)
  let payload_b64 = bit_array.base64_url_encode(<<payload_json:utf8>>, False)
  let signing_input = header_b64 <> "." <> payload_b64
  let raw_sig =
    ffi_sign_es256(<<signing_input:utf8>>, keyring.active.priv_scalar)
  let sig_b64 = bit_array.base64_url_encode(raw_sig, False)

  signing_input <> "." <> sig_b64
}

pub fn verify_id_token(
  keyring: Keyring,
  raw_jwt: String,
  expected_issuer: String,
  expected_client_id: String,
  now_unix: Int,
) -> Result(IdTokenClaims, JwtError) {
  use #(header_b64, payload_b64, sig_b64) <- result.try(split_jws_parts(raw_jwt))
  use header_bytes <- result.try(strict_base64_url_decode(header_b64))
  use payload_bytes <- result.try(strict_base64_url_decode(payload_b64))
  use maybe_sig_bytes <- result.try(case sig_b64 {
    "" -> Ok(None)
    _ -> {
      use decoded <- result.try(strict_base64_url_decode(sig_b64))
      Ok(Some(decoded))
    }
  })

  use DecodedHeader(alg:, kid:, typ:) <- result.try(decode_header(header_bytes))

  use _ <- result.try(case alg {
    "ES256" -> Ok(Nil)
    _ -> Error(UnsupportedAlgorithm)
  })

  use _ <- result.try(case typ {
    None -> Ok(Nil)
    Some(t) ->
      case string.uppercase(t) == "JWT" {
        True -> Ok(Nil)
        False -> Error(InvalidFormat)
      }
  })

  use sig_bytes <- result.try(case maybe_sig_bytes {
    Some(bytes) -> Ok(bytes)
    None -> Error(InvalidFormat)
  })

  use verify_key <- result.try(case kid {
    None | Some("") -> Error(UnknownKey)
    Some(key_id) ->
      case list.find(keyring.verify_keys, fn(k) { k.kid == key_id }) {
        Ok(found) -> Ok(found)
        Error(_) -> Error(UnknownKey)
      }
  })

  let signing_input = <<header_b64:utf8, ".":utf8, payload_b64:utf8>>
  use _ <- result.try(
    case
      bit_array.byte_size(sig_bytes) == 64
      && ffi_verify_es256(signing_input, sig_bytes, verify_key.x, verify_key.y)
    {
      True -> Ok(Nil)
      False -> Error(InvalidSignature)
    },
  )

  use claims <- result.try(decode_claims(payload_bytes))
  validate_claims(claims, expected_issuer, expected_client_id, now_unix)
}

pub fn export_key_pems_for_test(key: SigningKey) -> #(String, String, String) {
  ffi_export_private_key_pem(key.priv_scalar, key.x, key.y)
}

fn signing_key_from_parts(
  priv_scalar: BitArray,
  x: BitArray,
  y: BitArray,
) -> SigningKey {
  let x_b64 = bit_array.base64_url_encode(x, False)
  let y_b64 = bit_array.base64_url_encode(y, False)
  let kid = compute_jwk_thumbprint(x_b64, y_b64)
  SigningKey(kid:, priv_scalar:, x:, y:, x_b64:, y_b64:)
}

fn verify_key_from_parts(x: BitArray, y: BitArray) -> VerifyKey {
  let x_b64 = bit_array.base64_url_encode(x, False)
  let y_b64 = bit_array.base64_url_encode(y, False)
  let kid = compute_jwk_thumbprint(x_b64, y_b64)
  VerifyKey(kid:, x:, y:, x_b64:, y_b64:)
}

fn compute_jwk_thumbprint(x_b64: String, y_b64: String) -> String {
  let canonical =
    "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\""
    <> x_b64
    <> "\",\"y\":\""
    <> y_b64
    <> "\"}"
  crypto.hash(crypto.Sha256, <<canonical:utf8>>)
  |> bit_array.base64_url_encode(False)
}

fn dedup_verify_keys(
  remaining: List(VerifyKey),
  acc_rev: List(VerifyKey),
) -> List(VerifyKey) {
  case remaining {
    [] -> list.reverse(acc_rev)
    [head, ..tail] ->
      case list.any(acc_rev, fn(existing) { existing.kid == head.kid }) {
        True -> dedup_verify_keys(tail, acc_rev)
        False -> dedup_verify_keys(tail, [head, ..acc_rev])
      }
  }
}

fn append_optional_string(
  fields: List(#(String, json.Json)),
  key: String,
  value: Option(String),
) -> List(#(String, json.Json)) {
  case value {
    Some(v) if v != "" -> list.append(fields, [#(key, json.string(v))])
    _ -> fields
  }
}

fn split_jws_parts(
  raw_jwt: String,
) -> Result(#(String, String, String), JwtError) {
  case string.split(raw_jwt, ".") {
    [header_b64, payload_b64, sig_b64]
      if header_b64 != "" && payload_b64 != ""
    -> Ok(#(header_b64, payload_b64, sig_b64))
    _ -> Error(InvalidFormat)
  }
}

fn strict_base64_url_decode(encoded: String) -> Result(BitArray, JwtError) {
  case encoded != "" {
    False -> Error(InvalidFormat)
    True ->
      case bit_array.base64_url_decode(encoded) {
        Error(_) -> Error(InvalidFormat)
        Ok(decoded) ->
          case bit_array.base64_url_encode(decoded, False) == encoded {
            True -> Ok(decoded)
            False -> Error(InvalidFormat)
          }
      }
  }
}

fn decode_header(header_bytes: BitArray) -> Result(DecodedHeader, JwtError) {
  case bit_array.to_string(header_bytes) {
    Error(_) -> Error(InvalidFormat)
    Ok(header_str) -> {
      use _ <- result.try(case ffi_validate_jws_header_json(header_bytes) {
        Ok(_) -> Ok(Nil)
        Error(_) -> Error(InvalidFormat)
      })
      let decoder = {
        use alg <- decode.field("alg", decode.string)
        use kid <- decode.optional_field(
          "kid",
          None,
          decode.map(decode.string, Some),
        )
        use typ <- decode.optional_field(
          "typ",
          None,
          decode.map(decode.string, Some),
        )
        decode.success(DecodedHeader(alg:, kid:, typ:))
      }
      case json.parse(header_str, decoder) {
        Ok(parsed) -> Ok(parsed)
        Error(_) -> Error(InvalidFormat)
      }
    }
  }
}

fn decode_claims(payload_bytes: BitArray) -> Result(IdTokenClaims, JwtError) {
  case bit_array.to_string(payload_bytes) {
    Error(_) -> Error(InvalidClaims("Invalid UTF-8 in ID token payload"))
    Ok(payload_str) -> {
      use _ <- result.try(case ffi_validate_jwt_claims_json(payload_bytes) {
        Ok(_) -> Ok(Nil)
        Error(reason) -> Error(InvalidClaims(reason))
      })
      let decoder = {
        use iss <- decode.field("iss", decode.string)
        use sub <- decode.field("sub", decode.string)
        use aud <- decode.field("aud", aud_decoder())
        use iat <- decode.field("iat", decode.int)
        use exp <- decode.field("exp", decode.int)
        use nonce <- decode.optional_field(
          "nonce",
          None,
          non_empty_string_claim_decoder("NonEmptyString"),
        )
        use at_hash <- decode.optional_field(
          "at_hash",
          None,
          non_empty_string_claim_decoder("NonEmptyString"),
        )
        use name <- decode.optional_field(
          "name",
          None,
          non_empty_string_claim_decoder("NonEmptyString"),
        )
        decode.success(IdTokenClaims(
          iss:,
          sub:,
          aud:,
          iat:,
          exp:,
          nonce:,
          at_hash:,
          name:,
        ))
      }
      case json.parse(payload_str, decoder) {
        Ok(claims) -> Ok(claims)
        Error(_) -> Error(InvalidClaims("Malformed ID token claims JSON"))
      }
    }
  }
}

fn aud_decoder() -> decode.Decoder(String) {
  decode.one_of(decode.string, [
    {
      use items <- decode.then(decode.list(decode.string))
      case items {
        [single] -> decode.success(single)
        _ -> decode.failure("", "String")
      }
    },
  ])
}

fn non_empty_string_claim_decoder(
  expected: String,
) -> decode.Decoder(Option(String)) {
  use s <- decode.then(decode.string)
  case s != "" {
    True -> decode.success(Some(s))
    False -> decode.failure(None, expected)
  }
}

fn validate_claims(
  claims: IdTokenClaims,
  expected_issuer: String,
  expected_client_id: String,
  now_unix: Int,
) -> Result(IdTokenClaims, JwtError) {
  case claims.iss == expected_issuer {
    False -> Error(InvalidClaims("Issuer mismatch"))
    True ->
      case claims.aud == expected_client_id {
        False -> Error(InvalidClaims("Audience mismatch"))
        True ->
          case claims.sub != "" {
            False -> Error(InvalidClaims("Subject must not be empty"))
            True ->
              case claims.iat <= claims.exp {
                False -> Error(InvalidClaims("Issued-at exceeds expiration"))
                True ->
                  case claims.exp > now_unix {
                    False -> Error(ExpiredToken)
                    True -> Ok(claims)
                  }
              }
          }
      }
  }
}

@external(erlang, "lote_oidc_crypto_ffi", "generate_p256_key")
fn ffi_generate_p256_key() -> #(BitArray, BitArray, BitArray)

@external(erlang, "lote_oidc_crypto_ffi", "default_ephemeral_p256_key")
fn ffi_default_ephemeral_p256_key() -> #(BitArray, BitArray, BitArray)

@external(erlang, "lote_oidc_crypto_ffi", "parse_signing_key_pem")
fn ffi_parse_signing_key_pem(
  pem: String,
) -> Result(#(BitArray, BitArray, BitArray), String)

@external(erlang, "lote_oidc_crypto_ffi", "parse_verify_keys_pem")
fn ffi_parse_verify_keys_pem(
  pem: String,
) -> Result(List(#(BitArray, BitArray)), String)

@external(erlang, "lote_oidc_crypto_ffi", "sign_es256")
fn ffi_sign_es256(signing_input: BitArray, priv_scalar: BitArray) -> BitArray

@external(erlang, "lote_oidc_crypto_ffi", "verify_es256")
fn ffi_verify_es256(
  signing_input: BitArray,
  raw_sig: BitArray,
  x: BitArray,
  y: BitArray,
) -> Bool

@external(erlang, "lote_oidc_crypto_ffi", "export_private_key_pem")
fn ffi_export_private_key_pem(
  priv_scalar: BitArray,
  x: BitArray,
  y: BitArray,
) -> #(String, String, String)

@external(erlang, "lote_oidc_crypto_ffi", "unix_now_seconds")
fn ffi_unix_now_seconds() -> Int

@external(erlang, "lote_oidc_crypto_ffi", "validate_jws_header_json")
fn ffi_validate_jws_header_json(json_bytes: BitArray) -> Result(Nil, String)

@external(erlang, "lote_oidc_crypto_ffi", "validate_jwt_claims_json")
fn ffi_validate_jwt_claims_json(json_bytes: BitArray) -> Result(Nil, String)
