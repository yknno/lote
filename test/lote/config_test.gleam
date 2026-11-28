import gleam/dict
import gleam/option.{None, Some}
import gleam/string
import lote/config
import lote/oidc/jwt

const valid_secret =
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

fn env_from_pairs(
  pairs: List(#(String, String)),
) -> fn(String) -> Result(String, Nil) {
  let map = dict.from_list(pairs)
  fn(key) { dict.get(map, key) }
}

pub fn local_http_zero_config_allows_ephemeral_keys_test() {
  let assert Ok(cfg) = config.from_env(env_from_pairs([]))
  assert cfg.port == 8080
  assert cfg.issuer_url == "http://localhost:8080"
  assert cfg.oidc_signing_key_pem == None
  assert string.byte_size(cfg.secret_key_base)
    >= config.min_secret_key_base_bytes
}

pub fn https_issuer_requires_oidc_signing_key_and_secret_key_base_test() {
  let key = jwt.generate_signing_key()
  let #(_sec1_pem, pkcs8_pem, _spki_pem) = jwt.export_key_pems_for_test(key)

  // Missing OIDC_SIGNING_KEY_PEM on https:// issuer -> startup error
  assert config.from_env(
      env_from_pairs([
        #("ISSUER_URL", "https://lote.example.com/"),
        #("SECRET_KEY_BASE", valid_secret),
      ]),
    )
    == Error(config.MissingOidcSigningKeyForHttps("https://lote.example.com"))

  // Whitespace-only OIDC_SIGNING_KEY_PEM on https:// issuer -> startup error
  assert config.from_env(
      env_from_pairs([
        #("ISSUER_URL", "https://lote.example.com"),
        #("OIDC_SIGNING_KEY_PEM", "   \n  "),
        #("SECRET_KEY_BASE", valid_secret),
      ]),
    )
    == Error(config.MissingOidcSigningKeyForHttps("https://lote.example.com"))

  // Missing SECRET_KEY_BASE on https:// issuer -> startup error
  assert config.from_env(
      env_from_pairs([
        #("ISSUER_URL", "https://lote.example.com"),
        #("OIDC_SIGNING_KEY_PEM", pkcs8_pem),
      ]),
    )
    == Error(config.MissingSecretKeyBaseForHttps("https://lote.example.com"))

  // Short SECRET_KEY_BASE (< 64 bytes) -> startup error on both https:// and http://
  assert config.from_env(
      env_from_pairs([
        #("ISSUER_URL", "https://lote.example.com"),
        #("OIDC_SIGNING_KEY_PEM", pkcs8_pem),
        #("SECRET_KEY_BASE", "too-short"),
      ]),
    )
    == Error(config.ShortSecretKeyBase(9))

  assert config.from_env(
      env_from_pairs([#("SECRET_KEY_BASE", "too-short-for-wisp")]),
    )
    == Error(config.ShortSecretKeyBase(18))

  // Valid https:// configuration with both OIDC_SIGNING_KEY_PEM and 64-byte SECRET_KEY_BASE succeeds
  let assert Ok(cfg) =
    config.from_env(
      env_from_pairs([
        #("ISSUER_URL", "https://Lote.Example.com:443/"),
        #("OIDC_SIGNING_KEY_PEM", pkcs8_pem),
        #("SECRET_KEY_BASE", valid_secret),
      ]),
    )
  assert cfg.issuer_url == "https://lote.example.com"
  assert cfg.oidc_signing_key_pem == Some(string.trim(pkcs8_pem))
  assert cfg.secret_key_base == valid_secret
}

pub fn invalid_issuer_url_or_port_fails_fast_without_http_fallback_test() {
  // Typo in ISSUER_URL must NOT silently fall back to http://localhost:8080 and bypass https:// checks
  assert config.from_env(
      env_from_pairs([#("ISSUER_URL", "https://lote.example.com?bad=1")]),
    )
    == Error(config.InvalidIssuerUrl("https://lote.example.com?bad=1"))

  assert config.from_env(
      env_from_pairs([#("ISSUER_URL", "htps://lote.example.com")]),
    )
    == Error(config.InvalidIssuerUrl("htps://lote.example.com"))

  assert config.from_env(env_from_pairs([#("PORT", "0")]))
    == Error(config.InvalidPort("0"))
  assert config.from_env(env_from_pairs([#("PORT", "70000")]))
    == Error(config.InvalidPort("70000"))
  assert config.from_env(env_from_pairs([#("PORT", "abc")]))
    == Error(config.InvalidPort("abc"))
}
