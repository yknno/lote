import gleam/bit_array
import gleam/erlang/atom.{type Atom}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/set.{type Set}
import gleam/string
import gleam/uri.{type Uri}
import lote/oidc/client
import lote/oidc/scope.{type Scope}
import pog

pub const max_document_bytes = 16_384

pub const default_cache_ttl_seconds = 300

pub const min_cache_ttl_seconds = 60

pub const max_cache_ttl_seconds = 86_400

const max_client_id_bytes = 512

const max_client_name_chars = 100

pub type FetchResponse {
  FetchResponse(
    status: Int,
    content_type: String,
    cache_control: Option(String),
    body: BitArray,
  )
}

pub type FetchError {
  InvalidUrl(String)
  BlockedAddress(String)
  DnsError(String)
  TlsOrConnectError(String)
  Timeout
  ResponseTooLarge
  InvalidHttpResponse(String)
}

pub type Fetcher =
  fn(String) -> Result(FetchResponse, FetchError)

pub type CimdError {
  InvalidClientIdUrl(String)
  FetchFailed(FetchError)
  UnexpectedStatus(Int)
  InvalidContentType(String)
  InvalidDocument(String)
  DatabaseError
}

pub type ParsedMetadata {
  ParsedMetadata(
    client_id: String,
    client_name: String,
    application_type: client.ApplicationType,
    redirect_uris: List(String),
    allowed_scopes: Set(Scope),
    cache_ttl_seconds: Int,
  )
}

pub fn default_fetcher() -> Fetcher {
  fn(raw_url) { fetch_url(raw_url) }
}

pub fn is_cimd_client_id(raw: String) -> Bool {
  string.starts_with(raw, "https://")
}

pub fn validate_client_id_url(raw: String) -> Result(Uri, String) {
  use _ <- result.try(case raw != "" {
    True -> Ok(Nil)
    False -> Error("Client ID URL must not be empty")
  })
  use _ <- result.try(
    case bit_array.byte_size(<<raw:utf8>>) <= max_client_id_bytes {
      True -> Ok(Nil)
      False -> Error("Client ID URL must be at most 512 bytes")
    },
  )
  use _ <- result.try(case !has_control_or_whitespace(raw) {
    True -> Ok(Nil)
    False ->
      Error(
        "Client ID URL must not contain whitespace or ASCII control characters",
      )
  })
  use _ <- result.try(case string.starts_with(raw, "https://") {
    True -> Ok(Nil)
    False -> Error("Client ID URL must use the https:// scheme")
  })
  use _ <- result.try(case !string.contains(raw, "#") {
    True -> Ok(Nil)
    False -> Error("Client ID URL must not contain a fragment")
  })
  use _ <- result.try(case !string.contains(raw, "?") {
    True -> Ok(Nil)
    False -> Error("Client ID URL must not contain a query string")
  })
  use _ <- result.try(case !string.contains(raw, "\\") {
    True -> Ok(Nil)
    False -> Error("Client ID URL must not contain backslashes")
  })

  let after_scheme = string.drop_start(raw, up_to: 8)
  use #(authority, _) <- result.try(
    string.split_once(after_scheme, "/")
    |> result.replace_error("Client ID URL must include a non-root path"),
  )
  use _ <- result.try(validate_authority(authority))

  use parsed <- result.try(
    uri.parse(raw)
    |> result.replace_error("Invalid Client ID URL syntax"),
  )

  case
    parsed.scheme,
    parsed.userinfo,
    parsed.query,
    parsed.fragment,
    valid_uri_port(parsed.port),
    parsed.host
  {
    Some("https"), None, None, None, True, Some(host) -> {
      use _ <- result.try(validate_cimd_hostname(host))
      use _ <- result.try(validate_cimd_path(parsed.path))
      Ok(parsed)
    }
    _, _, _, _, _, _ -> Error("Invalid Client ID URL components")
  }
}

pub fn client_id_host(raw: String) -> Option(String) {
  case validate_client_id_url(raw) {
    Ok(parsed) -> option.map(parsed.host, string.lowercase)
    Error(_) -> None
  }
}

pub fn client_id_authority(raw: String) -> Option(String) {
  case validate_client_id_url(raw) {
    Ok(parsed) ->
      case parsed.host, parsed.port {
        Some(host), None | Some(host), Some(443) -> Some(string.lowercase(host))
        Some(host), Some(port) ->
          Some(string.lowercase(host) <> ":" <> int.to_string(port))
        None, _ -> None
      }
    Error(_) -> None
  }
}

pub fn parse_and_validate_document(
  expected_client_id: String,
  resp: FetchResponse,
) -> Result(ParsedMetadata, CimdError) {
  use parsed_url <- result.try(
    validate_client_id_url(expected_client_id)
    |> result.map_error(InvalidClientIdUrl),
  )

  use _ <- result.try(case resp.status {
    200 -> Ok(Nil)
    other -> Error(UnexpectedStatus(other))
  })

  let base_media_type =
    resp.content_type
    |> string.split(";")
    |> list.first
    |> result.unwrap("")
    |> string.trim
    |> string.lowercase

  use _ <- result.try(case base_media_type == "application/json" {
    True -> Ok(Nil)
    False -> Error(InvalidContentType(resp.content_type))
  })

  use _ <- result.try(
    case bit_array.byte_size(resp.body) <= max_document_bytes {
      True -> Ok(Nil)
      False ->
        Error(InvalidDocument("Client metadata document exceeds maximum size"))
    },
  )

  use raw_fields <- result.try(
    ffi_parse_strict_metadata_json(resp.body)
    |> result.map_error(InvalidDocument),
  )

  let #(
    doc_client_id,
    client_name_opt,
    app_type_opt,
    raw_redirect_uris,
    token_auth_opt,
    grant_types_opt,
    response_types_opt,
    scope_opt,
  ) = raw_fields

  use _ <- result.try(case doc_client_id == expected_client_id {
    True -> Ok(Nil)
    False ->
      Error(InvalidDocument("Document client_id does not match fetched URL"))
  })

  use _ <- result.try(case token_auth_opt {
    None | Some("none") -> Ok(Nil)
    Some(_) ->
      Error(InvalidDocument(
        "CIMD clients must use token_endpoint_auth_method \"none\"",
      ))
  })

  use application_type <- result.try(case app_type_opt {
    None | Some("web") -> Ok(client.Web)
    Some("native") -> Ok(client.Native)
    Some(_) ->
      Error(InvalidDocument(
        "Invalid application_type; expected \"web\" or \"native\"",
      ))
  })

  use allows_refresh <- result.try(validate_grant_types(grant_types_opt))
  use _ <- result.try(validate_response_types(response_types_opt))
  use redirect_uris <- result.try(validate_doc_redirect_uris(raw_redirect_uris))

  let fallback_host =
    parsed_url.host
    |> option.unwrap("client")
    |> string.lowercase
    |> string.slice(at_index: 0, length: max_client_name_chars)

  use client_name <- result.try(validate_doc_client_name(
    client_name_opt,
    fallback_host,
  ))

  use allowed_scopes <- result.try(validate_doc_scopes(
    scope_opt,
    allows_refresh,
  ))
  let cache_ttl_seconds = compute_cache_ttl(resp.cache_control)

  Ok(ParsedMetadata(
    client_id: doc_client_id,
    client_name:,
    application_type:,
    redirect_uris:,
    allowed_scopes:,
    cache_ttl_seconds:,
  ))
}

pub fn resolve_client(
  db: pog.Connection,
  fetcher: Fetcher,
  raw_client_id: String,
  on_network_fetch: fn() -> Result(Nil, e),
) -> Result(Result(client.Client, CimdError), e) {
  case validate_client_id_url(raw_client_id) {
    Error(msg) -> Ok(Error(InvalidClientIdUrl(msg)))
    Ok(_) ->
      case client.find_fresh_cimd_by_client_id(db, raw_client_id) {
        Ok(Some(cached)) -> Ok(Ok(cached))
        Error(_) -> Ok(Error(DatabaseError))
        Ok(None) ->
          case on_network_fetch() {
            Error(rate_err) -> Error(rate_err)
            Ok(Nil) ->
              case fetcher(raw_client_id) {
                Error(fetch_err) -> Ok(Error(FetchFailed(fetch_err)))
                Ok(resp) ->
                  case parse_and_validate_document(raw_client_id, resp) {
                    Error(cimd_err) -> Ok(Error(cimd_err))
                    Ok(meta) ->
                      case
                        client.upsert_cimd_client(
                          db,
                          meta.client_id,
                          meta.client_name,
                          meta.application_type,
                          meta.redirect_uris,
                          meta.allowed_scopes,
                          meta.cache_ttl_seconds,
                        )
                      {
                        Ok(saved) -> Ok(Ok(saved))
                        Error(_) -> Ok(Error(DatabaseError))
                      }
                  }
              }
          }
      }
  }
}

// Internal: Fetcher & URL Validation

fn fetch_url(raw_url: String) -> Result(FetchResponse, FetchError) {
  case
    raw_url != ""
    && bit_array.byte_size(<<raw_url:utf8>>) <= max_client_id_bytes
    && !has_control_or_whitespace(raw_url)
    && string.starts_with(raw_url, "https://")
    && !string.contains(raw_url, "#")
    && !string.contains(raw_url, "?")
    && !string.contains(raw_url, "\\")
  {
    False -> Error(InvalidUrl("Invalid HTTPS URL"))
    True -> {
      let after_scheme = string.drop_start(raw_url, up_to: 8)
      case string.split_once(after_scheme, "/") {
        Error(_) -> Error(InvalidUrl("URL path is required"))
        Ok(#(authority, _)) ->
          case parse_fetch_authority(authority) {
            Error(err) -> Error(err)
            Ok(#(host, port)) ->
              case validate_cimd_hostname(host) {
                Error(msg) -> Error(BlockedAddress(msg))
                Ok(Nil) ->
                  case uri.parse(raw_url) {
                    Error(_) -> Error(InvalidUrl("Invalid HTTPS URL syntax"))
                    Ok(parsed) ->
                      case
                        parsed.scheme,
                        parsed.userinfo,
                        parsed.query,
                        parsed.fragment
                      {
                        Some("https"), None, None, None ->
                          case validate_cimd_path(parsed.path) {
                            Error(msg) -> Error(InvalidUrl(msg))
                            Ok(Nil) ->
                              ffi_fetch_https(
                                string.lowercase(host),
                                port,
                                parsed.path,
                                max_document_bytes,
                              )
                              |> map_ffi_fetch_result
                          }
                        _, _, _, _ -> Error(InvalidUrl("Invalid HTTPS URL"))
                      }
                  }
              }
          }
      }
    }
  }
}

fn parse_fetch_authority(
  authority: String,
) -> Result(#(String, Int), FetchError) {
  case authority == "" || string.contains(authority, "@") {
    True -> Error(InvalidUrl("Invalid URL authority"))
    False ->
      case string.contains(authority, "[") || string.contains(authority, "]") {
        True -> Error(BlockedAddress("IP literals are not permitted"))
        False ->
          case string.split(authority, ":") {
            [host] if host != "" -> Ok(#(host, 443))
            [host, port_str] if host != "" ->
              case parse_strict_port(port_str) {
                Ok(port) -> Ok(#(host, port))
                Error(msg) -> Error(InvalidUrl(msg))
              }
            _ ->
              case ffi_is_ip_literal(authority) {
                True -> Error(BlockedAddress("IP literals are not permitted"))
                False -> Error(InvalidUrl("Invalid URL authority"))
              }
          }
      }
  }
}

fn map_ffi_fetch_result(
  raw: Result(#(Int, String, Option(String), BitArray), #(Atom, String)),
) -> Result(FetchResponse, FetchError) {
  case raw {
    Ok(#(status, content_type, cache_control, body)) ->
      Ok(FetchResponse(status:, content_type:, cache_control:, body:))
    Error(#(tag, detail)) ->
      case atom.to_string(tag) {
        "invalid_url" -> Error(InvalidUrl(detail))
        "blocked_address" -> Error(BlockedAddress(detail))
        "dns_error" -> Error(DnsError(detail))
        "tls_or_connect_error" -> Error(TlsOrConnectError(detail))
        "timeout" -> Error(Timeout)
        "response_too_large" -> Error(ResponseTooLarge)
        "invalid_http_response" -> Error(InvalidHttpResponse(detail))
        _ -> Error(TlsOrConnectError(detail))
      }
  }
}

fn validate_authority(authority: String) -> Result(Nil, String) {
  case authority == "" {
    True -> Error("Client ID URL must include a host")
    False ->
      case string.contains(authority, "@") {
        True -> Error("Client ID URL must not contain userinfo")
        False ->
          case
            string.contains(authority, "[") || string.contains(authority, "]")
          {
            True -> Error("Client ID URL host must not be an IP literal")
            False ->
              case string.split(authority, ":") {
                [host] if host != "" -> Ok(Nil)
                [host, port_raw] if host != "" ->
                  parse_strict_port(port_raw) |> result.replace(Nil)
                _ -> Error("Invalid Client ID URL authority or port")
              }
          }
      }
  }
}

fn parse_strict_port(raw: String) -> Result(Int, String) {
  let len = string.byte_size(raw)
  case
    len >= 1
    && len <= 5
    && !string.starts_with(raw, "0")
    && is_all_ascii_digits(raw)
  {
    False -> Error("Client ID URL has an invalid port")
    True ->
      case int.parse(raw) {
        Ok(p) if p >= 1 && p <= 65_535 -> Ok(p)
        _ -> Error("Client ID URL port must be in 1..65535")
      }
  }
}

fn valid_uri_port(port: Option(Int)) -> Bool {
  case port {
    None -> True
    Some(p) -> p >= 1 && p <= 65_535
  }
}

fn validate_cimd_hostname(host: String) -> Result(Nil, String) {
  use _ <- result.try(case host != "" && string.byte_size(host) <= 253 {
    True -> Ok(Nil)
    False -> Error("Client ID URL host length is invalid")
  })
  use _ <- result.try(case !ffi_is_ip_literal(host) {
    True -> Ok(Nil)
    False -> Error("Client ID URL host must not be an IP address literal")
  })

  let lower = string.lowercase(host)
  use _ <- result.try(
    case
      lower == "localhost"
      || string.ends_with(lower, ".localhost")
      || string.ends_with(lower, ".local")
      || string.ends_with(lower, ".internal")
      || string.ends_with(lower, ".home.arpa")
    {
      True -> Error("Client ID URL host must be a public domain name")
      False -> Ok(Nil)
    },
  )

  let labels = string.split(lower, ".")
  use _ <- result.try(case list.length(labels) >= 2 {
    True -> Ok(Nil)
    False ->
      Error("Client ID URL host must be a multi-label public domain name")
  })
  use _ <- result.try(case list.all(labels, is_valid_dns_label) {
    True -> Ok(Nil)
    False -> Error("Client ID URL host contains an invalid DNS label")
  })

  case list.last(labels) {
    Ok(tld) ->
      case !is_all_ascii_digits(tld) {
        True -> Ok(Nil)
        False -> Error("Client ID URL top-level domain must not be numeric")
      }
    Error(_) -> Error("Client ID URL host is invalid")
  }
}

fn is_valid_dns_label(label: String) -> Bool {
  let len = string.byte_size(label)
  len >= 1
  && len <= 63
  && !string.starts_with(label, "-")
  && !string.ends_with(label, "-")
  && {
    label
    |> string.to_utf_codepoints
    |> list.all(fn(cp) {
      case string.utf_codepoint_to_int(cp) {
        n if n >= 0x61 && n <= 0x7A -> True
        n if n >= 0x30 && n <= 0x39 -> True
        0x2D -> True
        _ -> False
      }
    })
  }
}

fn validate_cimd_path(path: String) -> Result(Nil, String) {
  use _ <- result.try(
    case
      string.starts_with(path, "/")
      && path != "/"
      && !string.contains(path, "//")
    {
      True -> Ok(Nil)
      False ->
        Error(
          "Client ID URL must include a non-root path without empty segments",
        )
    },
  )

  use _ <- result.try(
    case has_valid_percent_escapes(string.to_utf_codepoints(path)) {
      True -> Ok(Nil)
      False -> Error("Client ID URL path contains invalid percent-encoding")
    },
  )

  let lower_path = string.lowercase(path)
  use _ <- result.try(
    case
      string.contains(lower_path, "%2e")
      || string.contains(lower_path, "%2f")
      || string.contains(lower_path, "%5c")
      || string.contains(lower_path, "%00")
    {
      True ->
        Error(
          "Client ID URL path must not contain encoded dot or slash segments",
        )
      False -> Ok(Nil)
    },
  )

  let segments = string.split(path, "/")
  case
    list.any(segments, fn(seg) { seg != "" })
    && !list.any(segments, fn(seg) { seg == "." || seg == ".." })
  {
    True -> Ok(Nil)
    False -> Error("Client ID URL path must not contain dot-segments")
  }
}

fn has_valid_percent_escapes(cps: List(UtfCodepoint)) -> Bool {
  case cps {
    [] -> True
    [cp, ..rest] ->
      case string.utf_codepoint_to_int(cp) == 0x25 {
        False -> has_valid_percent_escapes(rest)
        True ->
          case rest {
            [h1, h2, ..tail] ->
              is_ascii_hex(h1)
              && is_ascii_hex(h2)
              && has_valid_percent_escapes(tail)
            _ -> False
          }
      }
  }
}

fn is_ascii_hex(cp: UtfCodepoint) -> Bool {
  case string.utf_codepoint_to_int(cp) {
    n if n >= 0x30 && n <= 0x39 -> True
    n if n >= 0x41 && n <= 0x46 -> True
    n if n >= 0x61 && n <= 0x66 -> True
    _ -> False
  }
}

// Internal: Metadata Document Field Validators

fn validate_grant_types(
  grant_types_opt: Option(List(String)),
) -> Result(Bool, CimdError) {
  case grant_types_opt {
    None -> Ok(False)
    Some([]) -> Error(InvalidDocument("grant_types must not be an empty array"))
    Some(gts) ->
      case
        list.contains(gts, "authorization_code")
        && list.all(gts, fn(g) {
          g == "authorization_code" || g == "refresh_token"
        })
      {
        True -> Ok(list.contains(gts, "refresh_token"))
        False ->
          Error(InvalidDocument("Unsupported grant_types in client metadata"))
      }
  }
}

fn validate_response_types(
  response_types_opt: Option(List(String)),
) -> Result(Nil, CimdError) {
  case response_types_opt {
    None | Some(["code"]) -> Ok(Nil)
    Some(_) -> Error(InvalidDocument("response_types must equal [\"code\"]"))
  }
}

fn validate_doc_redirect_uris(
  raw_uris: List(String),
) -> Result(List(String), CimdError) {
  case raw_uris != [] && list.length(raw_uris) <= client.max_redirect_uris {
    False ->
      Error(InvalidDocument(
        "redirect_uris must contain between 1 and 20 valid URIs",
      ))
    True -> {
      use validated <- result.try(
        list.try_map(raw_uris, fn(u) {
          client.validate_redirect_uri(u)
          |> result.map_error(InvalidDocument)
        }),
      )
      Ok(list.unique(validated))
    }
  }
}

fn validate_doc_client_name(
  client_name_opt: Option(String),
  fallback_host: String,
) -> Result(String, CimdError) {
  case client_name_opt {
    None -> Ok(fallback_host)
    Some(raw) ->
      case has_unsafe_display_codepoint(raw) {
        True ->
          Error(InvalidDocument(
            "client_name must not contain control or bidirectional override characters",
          ))
        False -> {
          let trimmed = string.trim(raw)
          let len = string.length(trimmed)
          case
            len >= 1
            && len <= max_client_name_chars
            && has_visible_display_codepoint(trimmed)
          {
            True -> Ok(trimmed)
            False ->
              Error(InvalidDocument(
                "client_name must contain between 1 and 100 visible characters",
              ))
          }
        }
      }
  }
}

fn has_unsafe_display_codepoint(s: String) -> Bool {
  s
  |> string.to_utf_codepoints
  |> list.any(fn(cp) {
    case string.utf_codepoint_to_int(cp) {
      n if n < 0x20 || n == 0x7F -> True
      n if n >= 0x80 && n <= 0x9F -> True
      0x061C | 0x200E | 0x200F | 0x2028 | 0x2029 -> True
      n if n >= 0x202A && n <= 0x202E -> True
      n if n >= 0x2066 && n <= 0x2069 -> True
      n if n >= 0xE0000 && n <= 0xE007F -> True
      _ -> False
    }
  })
}

fn has_visible_display_codepoint(s: String) -> Bool {
  s
  |> string.to_utf_codepoints
  |> list.any(fn(cp) {
    case string.utf_codepoint_to_int(cp) {
      0x20 | 0x00A0 | 0x1680 | 0x3000 -> False
      n if n >= 0x2000 && n <= 0x200A -> False
      0x00AD | 0x034F | 0x180E | 0x3164 | 0xFEFF | 0xFFA0 -> False
      n if n >= 0x115F && n <= 0x1160 -> False
      n if n >= 0x17B4 && n <= 0x17B5 -> False
      n if n >= 0x200B && n <= 0x200D -> False
      n if n >= 0x2060 && n <= 0x2064 -> False
      _ -> True
    }
  })
}

fn validate_doc_scopes(
  scope_opt: Option(String),
  allows_refresh: Bool,
) -> Result(Set(Scope), CimdError) {
  let base_result = case scope_opt {
    None -> Ok(set.from_list(scope.all()))
    Some(raw_scope) ->
      case is_valid_rfc6749_scope_string(raw_scope) {
        False ->
          Error(InvalidDocument("scope contains invalid RFC 6749 characters"))
        True -> {
          let tokens =
            raw_scope
            |> string.trim
            |> string.split(" ")
            |> list.filter(fn(tok) { tok != "" })

          case tokens {
            [] -> Error(InvalidDocument("scope must not be empty"))
            _ -> {
              let recognized =
                tokens
                |> list.filter_map(fn(tok) {
                  scope.from_string(tok)
                  |> result.replace_error(Nil)
                })
                |> set.from_list
              Ok(recognized)
            }
          }
        }
      }
  }

  use base_scopes <- result.try(base_result)
  let effective = case allows_refresh {
    True -> base_scopes
    False -> set.delete(base_scopes, scope.OfflineAccess)
  }

  case set.is_empty(effective) {
    True -> Error(InvalidDocument("No supported scopes in client metadata"))
    False -> Ok(effective)
  }
}

fn is_valid_rfc6749_scope_string(s: String) -> Bool {
  s
  |> string.to_utf_codepoints
  |> list.all(fn(cp) {
    case string.utf_codepoint_to_int(cp) {
      0x20 | 0x21 -> True
      n if n >= 0x23 && n <= 0x5B -> True
      n if n >= 0x5D && n <= 0x7E -> True
      _ -> False
    }
  })
}

fn compute_cache_ttl(cache_control: Option(String)) -> Int {
  case cache_control {
    None -> default_cache_ttl_seconds
    Some(raw) -> {
      let directives =
        raw
        |> string.split(",")
        |> list.map(fn(part) { string.lowercase(string.trim(part)) })
        |> list.filter(fn(part) { part != "" })

      let has_no_store_or_no_cache =
        list.any(directives, fn(d) {
          d == "no-store"
          || string.starts_with(d, "no-store=")
          || d == "no-cache"
          || string.starts_with(d, "no-cache=")
        })

      case has_no_store_or_no_cache {
        True -> min_cache_ttl_seconds
        False ->
          case find_max_age(directives) {
            Some(seconds) ->
              seconds
              |> int.max(min_cache_ttl_seconds)
              |> int.min(max_cache_ttl_seconds)
            None -> default_cache_ttl_seconds
          }
      }
    }
  }
}

fn find_max_age(directives: List(String)) -> Option(Int) {
  case directives {
    [] -> None
    [directive, ..rest] ->
      case directive {
        "max-age=" <> raw_val -> {
          let unquoted = strip_double_quotes(string.trim(raw_val))
          case is_all_ascii_digits(unquoted) {
            True ->
              case int.parse(unquoted) {
                Ok(n) if n >= 0 -> Some(n)
                _ -> find_max_age(rest)
              }
            False -> find_max_age(rest)
          }
        }
        _ -> find_max_age(rest)
      }
  }
}

fn strip_double_quotes(s: String) -> String {
  case
    string.byte_size(s) >= 2
    && string.starts_with(s, "\"")
    && string.ends_with(s, "\"")
  {
    True ->
      s
      |> string.drop_start(up_to: 1)
      |> string.drop_end(up_to: 1)
    False -> s
  }
}

fn has_control_or_whitespace(s: String) -> Bool {
  s
  |> string.to_utf_codepoints
  |> list.any(fn(cp) {
    case string.utf_codepoint_to_int(cp) {
      n if n <= 0x20 || n == 0x7F -> True
      _ -> False
    }
  })
}

fn is_all_ascii_digits(s: String) -> Bool {
  s != ""
  && {
    s
    |> string.to_utf_codepoints
    |> list.all(fn(cp) {
      case string.utf_codepoint_to_int(cp) {
        n if n >= 0x30 && n <= 0x39 -> True
        _ -> False
      }
    })
  }
}

// FFI Declarations

@external(erlang, "lote_cimd_http_ffi", "fetch_https")
fn ffi_fetch_https(
  host: String,
  port: Int,
  path: String,
  max_body_bytes: Int,
) -> Result(#(Int, String, Option(String), BitArray), #(Atom, String))

@external(erlang, "lote_cimd_http_ffi", "is_ip_literal")
fn ffi_is_ip_literal(host: String) -> Bool

@external(erlang, "lote_cimd_http_ffi", "parse_strict_metadata_json")
fn ffi_parse_strict_metadata_json(
  json_bytes: BitArray,
) -> Result(
  #(
    String,
    Option(String),
    Option(String),
    List(String),
    Option(String),
    Option(List(String)),
    Option(List(String)),
    Option(String),
  ),
  String,
)
