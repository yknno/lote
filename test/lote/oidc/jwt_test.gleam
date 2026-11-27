import gleam/bit_array
import gleam/crypto
import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import lote/oidc/jwt.{IdTokenClaims}

type JwkEntry {
  JwkEntry(
    kty: String,
    crv: String,
    key_use: String,
    alg: String,
    kid: String,
    x: String,
    y: String,
  )
}

fn parse_jwks(raw: String) -> List(JwkEntry) {
  let entry_decoder = {
    use kty <- decode.field("kty", decode.string)
    use crv <- decode.field("crv", decode.string)
    use key_use <- decode.field("use", decode.string)
    use alg <- decode.field("alg", decode.string)
    use kid <- decode.field("kid", decode.string)
    use x <- decode.field("x", decode.string)
    use y <- decode.field("y", decode.string)
    decode.success(JwkEntry(kty:, crv:, key_use:, alg:, kid:, x:, y:))
  }
  let decoder = {
    use keys <- decode.field("keys", decode.list(entry_decoder))
    decode.success(keys)
  }
  let assert Ok(entries) = json.parse(raw, decoder)
  entries
}

pub fn key_generation_rfc7638_thumbprint_and_64_byte_signature_test() {
  assert jwt.id_token_ttl_seconds == 3600
  assert jwt.now_unix_seconds() > 1_700_000_000

  let key1 = jwt.generate_signing_key()
  let key2 = jwt.generate_signing_key()
  let kr1 = jwt.new_keyring(key1, [])
  let kr2 = jwt.new_keyring(key2, [])

  let kid1 = jwt.active_kid(kr1)
  let kid2 = jwt.active_kid(kr2)
  assert kid1 != kid2
  assert string.length(kid1) == 43

  // default_keyring uses persistent_term so repeated calls share the same key
  let def1 = jwt.default_keyring()
  let def2 = jwt.default_keyring()
  assert jwt.active_kid(def1) == jwt.active_kid(def2)

  // Verify JWKS format and deterministic RFC 7638 SHA-256 thumbprint
  let assert [jwk] = parse_jwks(jwt.jwks_json(kr1))
  assert jwk.kty == "EC"
  assert jwk.crv == "P-256"
  assert jwk.key_use == "sig"
  assert jwk.alg == "ES256"
  assert jwk.kid == kid1
  assert string.length(jwk.x) == 43
  assert string.length(jwk.y) == 43

  let canonical_jwk =
    "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\""
    <> jwk.x
    <> "\",\"y\":\""
    <> jwk.y
    <> "\"}"
  let expected_thumbprint =
    crypto.hash(crypto.Sha256, <<canonical_jwk:utf8>>)
    |> bit_array.base64_url_encode(False)
  assert kid1 == expected_thumbprint

  // ES256 signature must be exact 64-byte IEEE P1363 (86 unpadded base64url chars)
  let claims =
    IdTokenClaims(
      iss: "https://lote.example.com",
      sub: "user-123",
      aud: "client-abc",
      iat: 1_700_000_000,
      exp: 1_700_003_600,
      nonce: None,
      at_hash: None,
      name: None,
    )
  let token = jwt.sign_id_token(kr1, claims)
  assert !string.contains(token, "=")

  let assert [_hdr_b64, _pay_b64, sig_b64] = string.split(token, ".")
  assert string.length(sig_b64) == 86
  let assert Ok(sig_bytes) = bit_array.base64_url_decode(sig_b64)
  assert bit_array.byte_size(sig_bytes) == 64
}

pub fn pem_roundtrip_sec1_pkcs8_spki_and_invalid_pem_rejection_test() {
  let orig_key = jwt.generate_signing_key()
  let orig_kr = jwt.new_keyring(orig_key, [])
  let orig_kid = jwt.active_kid(orig_kr)
  let #(sec1_pem, pkcs8_pem, spki_pem) = jwt.export_key_pems_for_test(orig_key)

  let assert Ok(sec1_key) = jwt.parse_signing_key_pem(sec1_pem)
  let assert Ok(pkcs8_key) = jwt.parse_signing_key_pem(pkcs8_pem)
  assert jwt.active_kid(jwt.new_keyring(sec1_key, [])) == orig_kid
  assert jwt.active_kid(jwt.new_keyring(pkcs8_key, [])) == orig_kid

  // Public SPKI PEM cannot be parsed as a signing private key
  let assert Error(jwt.InvalidPem(_)) = jwt.parse_signing_key_pem(spki_pem)

  // Public SPKI, SEC1, and PKCS#8 can all be parsed as verification keys
  let assert Ok([spki_vk]) = jwt.parse_verify_keys_pem(spki_pem)
  let other_key = jwt.generate_signing_key()
  let #(other_sec1, _, other_spki) = jwt.export_key_pems_for_test(other_key)

  let combined_verify_pem = spki_pem <> "\n" <> other_spki <> "\n" <> other_sec1
  let assert Ok(verify_list) = jwt.parse_verify_keys_pem(combined_verify_pem)
  assert list.length(verify_list) == 3

  // Signing key signed via PKCS#8 verifies under SPKI verify key
  let claims =
    IdTokenClaims(
      iss: "https://issuer.example.test",
      sub: "sub-pem",
      aud: "client-pem",
      iat: 1_700_000_000,
      exp: 1_700_003_600,
      nonce: Some("nonce-pem"),
      at_hash: None,
      name: None,
    )
  let signed_by_pkcs8 =
    jwt.sign_id_token(jwt.new_keyring(pkcs8_key, []), claims)
  let verify_only_kr = jwt.new_keyring(other_key, [spki_vk])
  assert jwt.verify_id_token(
      verify_only_kr,
      signed_by_pkcs8,
      "https://issuer.example.test",
      "client-pem",
      1_700_000_100,
    )
    == Ok(claims)

  // load_keyring_from_pem supports both ephemeral and configured PEM modes
  let assert Ok(#(_ephemeral_kr, True)) = jwt.load_keyring_from_pem(None, None)
  let assert Ok(#(configured_kr, False)) =
    jwt.load_keyring_from_pem(Some(sec1_pem), Some(other_spki))
  assert jwt.active_kid(configured_kr) == orig_kid
  assert list.length(parse_jwks(jwt.jwks_json(configured_kr))) == 2

  // Reject empty, garbage, multi-private-key, corrupted, and encrypted PEMs
  let assert Error(jwt.InvalidPem(_)) = jwt.parse_signing_key_pem("")
  let assert Error(jwt.InvalidPem(_)) = jwt.parse_verify_keys_pem("")
  let assert Error(jwt.InvalidPem(_)) = jwt.parse_signing_key_pem("not-a-pem")
  let assert Error(jwt.InvalidPem(_)) = jwt.parse_verify_keys_pem("not-a-pem")
  let assert Error(jwt.InvalidPem(_)) =
    jwt.load_keyring_from_pem(Some(""), None)
  let assert Error(jwt.InvalidPem(_)) =
    jwt.parse_signing_key_pem(sec1_pem <> "\n" <> other_sec1)
  let assert Error(jwt.InvalidPem(_)) =
    jwt.parse_signing_key_pem(
      "-----BEGIN EC PRIVATE KEY-----\n!!!corrupt!!!\n-----END EC PRIVATE KEY-----\n",
    )

  let encrypted_pkcs8_pem =
    "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
    <> "MIIBpjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQIAAAAAAAAAAAAAAAA\n"
    <> "-----END ENCRYPTED PRIVATE KEY-----\n"
  let assert Error(jwt.InvalidPem(_)) =
    jwt.parse_signing_key_pem(encrypted_pkcs8_pem)
  let assert Error(jwt.InvalidPem(_)) =
    jwt.parse_verify_keys_pem(encrypted_pkcs8_pem)

  let encrypted_sec1_pem =
    "-----BEGIN EC PRIVATE KEY-----\n"
    <> "Proc-Type: 4,ENCRYPTED\n"
    <> "DEK-Info: AES-128-CBC,00112233445566778899AABBCCDDEEFF\n\n"
    <> "AAAAAAAAAAAAAAAAAAAAAA==\n"
    <> "-----END EC PRIVATE KEY-----\n"
  let assert Error(jwt.InvalidPem(_)) =
    jwt.parse_signing_key_pem(encrypted_sec1_pem)
}

pub fn oidc_core_at_hash_test_vector_test() {
  // OIDC Core 1.0 Appendix A.3 test vector
  let access_token = "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y"
  assert jwt.compute_at_hash(access_token) == "77QmUPtjPfzWtF2AnpK9RQ"
}

pub fn sign_and_verify_id_token_with_and_without_optional_claims_test() {
  let keyring = jwt.new_keyring(jwt.generate_signing_key(), [])
  let issuer = "https://auth.lote.example"
  let client_id = "app-client-1"
  let now = 1_710_000_000

  // Without optional claims
  let minimal_claims =
    IdTokenClaims(
      iss: issuer,
      sub: "user-uuid-1",
      aud: client_id,
      iat: now,
      exp: now + jwt.id_token_ttl_seconds,
      nonce: None,
      at_hash: None,
      name: None,
    )
  let minimal_jwt = jwt.sign_id_token(keyring, minimal_claims)
  assert jwt.verify_id_token(keyring, minimal_jwt, issuer, client_id, now)
    == Ok(minimal_claims)

  let assert [_hdr, minimal_payload_b64, _sig] = string.split(minimal_jwt, ".")
  let assert Ok(minimal_payload_bytes) =
    bit_array.base64_url_decode(minimal_payload_b64)
  let assert Ok(minimal_payload_json) =
    bit_array.to_string(minimal_payload_bytes)
  assert !string.contains(minimal_payload_json, "\"nonce\"")
  assert !string.contains(minimal_payload_json, "\"at_hash\"")
  assert !string.contains(minimal_payload_json, "\"name\"")

  // With nonce, at_hash, and name
  let full_claims =
    IdTokenClaims(
      iss: issuer,
      sub: "user-uuid-2",
      aud: client_id,
      iat: now,
      exp: now + jwt.id_token_ttl_seconds,
      nonce: Some("n-0S6_WzA2Mj"),
      at_hash: Some(jwt.compute_at_hash("lote_at_example_access_token_value")),
      name: Some("Ada Lovelace"),
    )
  let full_jwt = jwt.sign_id_token(keyring, full_claims)
  assert jwt.verify_id_token(keyring, full_jwt, issuer, client_id, now + 3599)
    == Ok(full_claims)
}

pub fn key_rotation_verifies_previous_key_and_exposes_both_in_jwks_test() {
  let old_key = jwt.generate_signing_key()
  let new_key = jwt.generate_signing_key()
  let old_only_kr = jwt.new_keyring(old_key, [])
  let new_only_kr = jwt.new_keyring(new_key, [])

  let old_kid = jwt.active_kid(old_only_kr)
  let new_kid = jwt.active_kid(new_only_kr)

  let issuer = "https://rotate.lote.example"
  let client_id = "rotating-client"
  let now = 1_720_000_000

  let old_claims =
    IdTokenClaims(
      iss: issuer,
      sub: "user-old",
      aud: client_id,
      iat: now,
      exp: now + 3600,
      nonce: Some("old-nonce"),
      at_hash: None,
      name: None,
    )
  let old_token = jwt.sign_id_token(old_only_kr, old_claims)

  // Rotate active key to new_key while retaining old_key (plus duplicates to verify dedup)
  let rotated_kr =
    jwt.new_keyring(new_key, [
      jwt.signing_key_to_verify_key(old_key),
      jwt.signing_key_to_verify_key(new_key),
      jwt.signing_key_to_verify_key(old_key),
    ])
  assert jwt.active_kid(rotated_kr) == new_kid

  let jwks_entries = parse_jwks(jwt.jwks_json(rotated_kr))
  assert list.map(jwks_entries, fn(e) { e.kid }) == [new_kid, old_kid]

  let new_claims =
    IdTokenClaims(
      iss: issuer,
      sub: "user-new",
      aud: client_id,
      iat: now + 10,
      exp: now + 3610,
      nonce: None,
      at_hash: None,
      name: Some("Rotated User"),
    )
  let new_token = jwt.sign_id_token(rotated_kr, new_claims)

  // Both old_token and new_token verify against rotated_kr
  assert jwt.verify_id_token(rotated_kr, old_token, issuer, client_id, now + 20)
    == Ok(old_claims)
  assert jwt.verify_id_token(rotated_kr, new_token, issuer, client_id, now + 20)
    == Ok(new_claims)

  // Retiring old_key causes old_token to be rejected with UnknownKey
  assert jwt.verify_id_token(
      new_only_kr,
      old_token,
      issuer,
      client_id,
      now + 20,
    )
    == Error(jwt.UnknownKey)
}

pub fn adversarial_jws_and_claims_rejections_test() {
  let keyring = jwt.new_keyring(jwt.generate_signing_key(), [])
  let stranger_kr = jwt.new_keyring(jwt.generate_signing_key(), [])
  let issuer = "https://secure.lote.example"
  let client_id = "secure-client"
  let now = 1_730_000_000

  let valid_claims =
    IdTokenClaims(
      iss: issuer,
      sub: "victim-sub",
      aud: client_id,
      iat: now,
      exp: now + 3600,
      nonce: Some("n1"),
      at_hash: None,
      name: Some("Victim"),
    )
  let valid_jwt = jwt.sign_id_token(keyring, valid_claims)
  let assert [hdr_b64, pay_b64, sig_b64] = string.split(valid_jwt, ".")

  // 1. Tampered payload with original valid signature -> InvalidSignature
  let evil_payload_json =
    json.object([
      #("iss", json.string(issuer)),
      #("sub", json.string("admin-sub")),
      #("aud", json.string(client_id)),
      #("iat", json.int(now)),
      #("exp", json.int(now + 3600)),
    ])
    |> json.to_string
  let evil_pay_b64 =
    bit_array.base64_url_encode(<<evil_payload_json:utf8>>, False)
  assert jwt.verify_id_token(
      keyring,
      hdr_b64 <> "." <> evil_pay_b64 <> "." <> sig_b64,
      issuer,
      client_id,
      now,
    )
    == Error(jwt.InvalidSignature)

  // 2. Tampered signature & zero (r=0, s=0) signature -> InvalidSignature
  let flipped_sig_b64 = case string.starts_with(sig_b64, "A") {
    True -> "B" <> string.drop_start(sig_b64, up_to: 1)
    False -> "A" <> string.drop_start(sig_b64, up_to: 1)
  }
  assert jwt.verify_id_token(
      keyring,
      hdr_b64 <> "." <> pay_b64 <> "." <> flipped_sig_b64,
      issuer,
      client_id,
      now,
    )
    == Error(jwt.InvalidSignature)

  let zero_sig_b64 = bit_array.base64_url_encode(<<0:size(512)>>, False)
  assert jwt.verify_id_token(
      keyring,
      hdr_b64 <> "." <> pay_b64 <> "." <> zero_sig_b64,
      issuer,
      client_id,
      now,
    )
    == Error(jwt.InvalidSignature)

  // 3. alg: "none" (both empty-sig unsecured JWS and signed-looking) & alg: "HS256"
  let alg_none_hdr =
    bit_array.base64_url_encode(
      <<"{\"alg\":\"none\",\"typ\":\"JWT\"}":utf8>>,
      False,
    )
  assert jwt.verify_id_token(
      keyring,
      alg_none_hdr <> "." <> pay_b64 <> ".",
      issuer,
      client_id,
      now,
    )
    == Error(jwt.UnsupportedAlgorithm)
  assert jwt.verify_id_token(
      keyring,
      alg_none_hdr <> "." <> pay_b64 <> "." <> sig_b64,
      issuer,
      client_id,
      now,
    )
    == Error(jwt.UnsupportedAlgorithm)

  let hs256_hdr_json =
    "{\"alg\":\"HS256\",\"kid\":\""
    <> jwt.active_kid(keyring)
    <> "\",\"typ\":\"JWT\"}"
  let alg_hs256_hdr =
    bit_array.base64_url_encode(<<hs256_hdr_json:utf8>>, False)
  assert jwt.verify_id_token(
      keyring,
      alg_hs256_hdr <> "." <> pay_b64 <> "." <> sig_b64,
      issuer,
      client_id,
      now,
    )
    == Error(jwt.UnsupportedAlgorithm)

  // 4. Unknown kid
  let stranger_jwt = jwt.sign_id_token(stranger_kr, valid_claims)
  assert jwt.verify_id_token(keyring, stranger_jwt, issuer, client_id, now)
    == Error(jwt.UnknownKey)

  // 5. Wrong iss, wrong aud, empty sub, iat > exp
  let assert Error(jwt.InvalidClaims(_)) =
    jwt.verify_id_token(
      keyring,
      valid_jwt,
      "https://wrong-issuer.example",
      client_id,
      now,
    )
  let assert Error(jwt.InvalidClaims(_)) =
    jwt.verify_id_token(keyring, valid_jwt, issuer, "wrong-client-id", now)

  let empty_sub_jwt =
    jwt.sign_id_token(keyring, IdTokenClaims(..valid_claims, sub: ""))
  let assert Error(jwt.InvalidClaims(_)) =
    jwt.verify_id_token(keyring, empty_sub_jwt, issuer, client_id, now)

  let inverted_iat_jwt =
    jwt.sign_id_token(
      keyring,
      IdTokenClaims(..valid_claims, iat: now + 5000, exp: now + 3600),
    )
  let assert Error(jwt.InvalidClaims(_)) =
    jwt.verify_id_token(keyring, inverted_iat_jwt, issuer, client_id, now)

  // 6. Expired exp (boundary exp == now_unix and exp < now_unix)
  assert jwt.verify_id_token(keyring, valid_jwt, issuer, client_id, now + 3600)
    == Error(jwt.ExpiredToken)
  assert jwt.verify_id_token(keyring, valid_jwt, issuer, client_id, now + 9999)
    == Error(jwt.ExpiredToken)

  // 7. Padded base64url must be rejected with InvalidFormat
  let padded_sig = bit_array.base64_url_encode(<<0:size(512)>>, True)
  assert string.ends_with(padded_sig, "==")
  assert jwt.verify_id_token(
      keyring,
      hdr_b64 <> "." <> pay_b64 <> "." <> padded_sig,
      issuer,
      client_id,
      now,
    )
    == Error(jwt.InvalidFormat)

  // 8. Extra or missing '.' segments
  assert jwt.verify_id_token(
      keyring,
      valid_jwt <> ".extra",
      issuer,
      client_id,
      now,
    )
    == Error(jwt.InvalidFormat)
  assert jwt.verify_id_token(
      keyring,
      hdr_b64 <> "." <> pay_b64,
      issuer,
      client_id,
      now,
    )
    == Error(jwt.InvalidFormat)
  assert jwt.verify_id_token(keyring, "not-a-jwt", issuer, client_id, now)
    == Error(jwt.InvalidFormat)
  assert jwt.verify_id_token(keyring, "", issuer, client_id, now)
    == Error(jwt.InvalidFormat)
}

@external(erlang, "lote_oidc_crypto_ffi", "generate_p256_key")
fn raw_generate_p256_key() -> #(BitArray, BitArray, BitArray)

@external(erlang, "lote_oidc_crypto_ffi", "sign_es256")
fn raw_sign_es256(signing_input: BitArray, priv_scalar: BitArray) -> BitArray

pub fn audit_regressions_pem_ecparam_escaped_newlines_pkcs8_and_strict_json_test() {
  let #(priv_scalar, x, y) = raw_generate_p256_key()
  let key = {
    let base_key = jwt.generate_signing_key()
    let #(sec1_pem, pkcs8_pem, spki_pem) =
      jwt.export_key_pems_for_test(base_key)
    #(base_key, sec1_pem, pkcs8_pem, spki_pem)
  }
  let #(base_key, sec1_pem, pkcs8_pem, spki_pem) = key

  // 1. `openssl ecparam -name prime256v1 -genkey` two-block PEM (EC PARAMETERS + EC PRIVATE KEY)
  // ASN.1 DER for OID 1.2.840.10045.3.1.7 (prime256v1): 06 08 2A 86 48 CE 3D 03 01 07 -> Base64 "BggqhkjOPQMBBw=="
  let p256_params_pem =
    "-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n-----END EC PARAMETERS-----\n"
  let ecparam_two_block_pem = p256_params_pem <> sec1_pem
  let assert Ok(parsed_ecparam_key) =
    jwt.parse_signing_key_pem(ecparam_two_block_pem)
  assert jwt.active_kid(jwt.new_keyring(parsed_ecparam_key, []))
    == jwt.active_kid(jwt.new_keyring(base_key, []))
  let assert Ok([parsed_ecparam_verify]) =
    jwt.parse_verify_keys_pem(p256_params_pem <> spki_pem)
  assert jwt.jwks_json(jwt.new_keyring(base_key, []))
    == jwt.jwks_json(jwt.new_keyring(base_key, [parsed_ecparam_verify]))

  // Non-P-256 EC PARAMETERS block (secp384r1 OID 1.3.132.0.34 -> 06 05 2B 81 04 00 22 -> "BgUrgQQAIg==") must fail!
  let p384_params_pem =
    "-----BEGIN EC PARAMETERS-----\nBgUrgQQAIg==\n-----END EC PARAMETERS-----\n"
  let assert Error(jwt.InvalidPem(_)) =
    jwt.parse_signing_key_pem(p384_params_pem <> sec1_pem)
  let assert Error(jwt.InvalidPem(_)) =
    jwt.parse_verify_keys_pem(p384_params_pem <> spki_pem)
  let assert Error(jwt.InvalidPem(_)) =
    jwt.parse_signing_key_pem(p256_params_pem)

  // 2. Single-line env var PEM with literal `\n` and `\r\n` escape sequences
  let escaped_lf_pem = string.replace(pkcs8_pem, "\n", "\\n")
  let escaped_crlf_pem = string.replace(spki_pem, "\n", "\\r\\n")
  let assert Ok(parsed_escaped_sign) = jwt.parse_signing_key_pem(escaped_lf_pem)
  assert jwt.active_kid(jwt.new_keyring(parsed_escaped_sign, []))
    == jwt.active_kid(jwt.new_keyring(base_key, []))
  let assert Ok([_]) = jwt.parse_verify_keys_pem(escaped_crlf_pem)

  // 3. PKCS#8 outer=secp256r1 / inner=secp384r1 curve mismatch must be rejected!
  // Craft a PKCS#8 DER where outer AlgorithmIdentifier has prime256v1 (2A 86 48 CE 3D 03 01 07)
  // while inner ECPrivateKey embeds secp384r1 (06 05 2B 81 04 00 22)
  let inner_ec_der = <<
    0x30, 0x2E,
    // version = 1
    0x02, 0x01, 0x01,
    // privateKey OCTET STRING (32 bytes)
    0x04, 0x20, priv_scalar:bits,
    // [0] EXPLICIT secp384r1 OID (06 05 2B 81 04 00 22)
    0xA0, 0x07, 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22,
  >>
  let mismatched_pkcs8_der = <<
    0x30, 0x48,
    // version = 0
    0x02, 0x01, 0x00,
    // PrivateKeyAlgorithmIdentifier: id-ecPublicKey (06 07 2A 86 48 CE 3D 02 01) + prime256v1 (06 08 2A 86 48 CE 3D 03 01 07)
    0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08,
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
    // privateKey OCTET STRING wrapping inner_ec_der (48 = 0x30 bytes)
    0x04, 0x30, inner_ec_der:bits,
  >>
  let mismatched_pkcs8_pem =
    "-----BEGIN PRIVATE KEY-----\n"
    <> bit_array.base64_encode(mismatched_pkcs8_der, True)
    <> "\n-----END PRIVATE KEY-----\n"
  let assert Error(jwt.InvalidPem(_)) =
    jwt.parse_signing_key_pem(mismatched_pkcs8_pem)

  // 4. Signed JWS helper using raw_key so we can test `crit`, duplicate keys, and JSON null/empty claims
  let x_b64 = bit_array.base64_url_encode(x, False)
  let y_b64 = bit_array.base64_url_encode(y, False)
  let raw_spki_der = <<
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
    0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    0x04, x:bits, y:bits,
  >>
  let raw_spki_pem =
    "-----BEGIN PUBLIC KEY-----\n"
    <> bit_array.base64_encode(raw_spki_der, True)
    <> "\n-----END PUBLIC KEY-----\n"
  let assert Ok([raw_vk]) = jwt.parse_verify_keys_pem(raw_spki_pem)
  let kr = jwt.new_keyring(base_key, [raw_vk])
  let jwks_str = jwt.jwks_json(kr)
  assert string.contains(jwks_str, x_b64)
  assert string.contains(jwks_str, y_b64)
  // Build raw_vk's kid by parsing raw key as SEC1 signing key too
  let raw_sec1_der = <<
    0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, priv_scalar:bits, 0xA0, 0x0A, 0x06,
    0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0xA1, 0x44, 0x03, 0x42,
    0x00, 0x04, x:bits, y:bits,
  >>
  let raw_sec1_pem =
    "-----BEGIN EC PRIVATE KEY-----\n"
    <> bit_array.base64_encode(raw_sec1_der, True)
    <> "\n-----END EC PRIVATE KEY-----\n"
  let assert Ok(raw_sk) = jwt.parse_signing_key_pem(raw_sec1_pem)
  let raw_kr = jwt.new_keyring(raw_sk, [])
  let kid = jwt.active_kid(raw_kr)

  let sign_raw = fn(hdr_json: String, pay_json: String) -> String {
    let h = bit_array.base64_url_encode(<<hdr_json:utf8>>, False)
    let p = bit_array.base64_url_encode(<<pay_json:utf8>>, False)
    let input = h <> "." <> p
    let sig =
      raw_sign_es256(<<input:utf8>>, priv_scalar)
      |> bit_array.base64_url_encode(False)
    input <> "." <> sig
  }

  let valid_pay =
    "{\"iss\":\"https://iss.example\",\"sub\":\"u1\",\"aud\":\"c1\",\"iat\":1700000000,\"exp\":1700003600}"
  let valid_hdr = "{\"alg\":\"ES256\",\"kid\":\"" <> kid <> "\"}"
  let assert Ok(_) =
    jwt.verify_id_token(
      raw_kr,
      sign_raw(valid_hdr, valid_pay),
      "https://iss.example",
      "c1",
      1_700_000_010,
    )

  // RFC 7515 §4.1.11: ANY `crit` header parameter must be rejected!
  let crit_hdr =
    "{\"alg\":\"ES256\",\"kid\":\"" <> kid <> "\",\"crit\":[\"exp\"]}"
  assert jwt.verify_id_token(
      raw_kr,
      sign_raw(crit_hdr, valid_pay),
      "https://iss.example",
      "c1",
      1_700_000_010,
    )
    == Error(jwt.InvalidFormat)

  // RFC 7515 §4 / RFC 7519 §4: Duplicate JSON member names in header or payload must be rejected!
  let dup_hdr = "{\"alg\":\"ES256\",\"alg\":\"none\",\"kid\":\"" <> kid <> "\"}"
  assert jwt.verify_id_token(
      raw_kr,
      sign_raw(dup_hdr, valid_pay),
      "https://iss.example",
      "c1",
      1_700_000_010,
    )
    == Error(jwt.InvalidFormat)

  let dup_pay =
    "{\"iss\":\"https://iss.example\",\"sub\":\"victim\",\"sub\":\"attacker\",\"aud\":\"c1\",\"iat\":1700000000,\"exp\":1700003600}"
  let assert Error(jwt.InvalidClaims(_)) =
    jwt.verify_id_token(
      raw_kr,
      sign_raw(valid_hdr, dup_pay),
      "https://iss.example",
      "c1",
      1_700_000_010,
    )

  // Explicit JSON null or empty string in optional header/claims must be rejected!
  let null_typ_hdr =
    "{\"alg\":\"ES256\",\"kid\":\"" <> kid <> "\",\"typ\":null}"
  assert jwt.verify_id_token(
      raw_kr,
      sign_raw(null_typ_hdr, valid_pay),
      "https://iss.example",
      "c1",
      1_700_000_010,
    )
    == Error(jwt.InvalidFormat)

  let null_nonce_pay =
    "{\"iss\":\"https://iss.example\",\"sub\":\"u1\",\"aud\":\"c1\",\"iat\":1700000000,\"exp\":1700003600,\"nonce\":null}"
  let assert Error(jwt.InvalidClaims(_)) =
    jwt.verify_id_token(
      raw_kr,
      sign_raw(valid_hdr, null_nonce_pay),
      "https://iss.example",
      "c1",
      1_700_000_010,
    )

  let empty_nonce_pay =
    "{\"iss\":\"https://iss.example\",\"sub\":\"u1\",\"aud\":\"c1\",\"iat\":1700000000,\"exp\":1700003600,\"nonce\":\"\"}"
  let assert Error(jwt.InvalidClaims(_)) =
    jwt.verify_id_token(
      raw_kr,
      sign_raw(valid_hdr, empty_nonce_pay),
      "https://iss.example",
      "c1",
      1_700_000_010,
    )
}
