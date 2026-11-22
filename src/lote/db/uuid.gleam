import gleam/bit_array
import gleam/dynamic/decode
import gleam/list
import gleam/string

pub fn decoder() -> decode.Decoder(String) {
  use bytes <- decode.then(decode.bit_array)
  case format(bytes) {
    Ok(uuid) -> decode.success(uuid)
    Error(_) -> decode.failure("", "UUID")
  }
}

pub fn normalize(input: String) -> Result(String, Nil) {
  let lower = string.lowercase(input)
  case string.split(lower, "-") {
    [a, b, c, d, e] ->
      case
        is_hex_len(a, 8)
        && is_hex_len(b, 4)
        && is_hex_len(c, 4)
        && is_hex_len(d, 4)
        && is_hex_len(e, 12)
      {
        True -> Ok(lower)
        False -> Error(Nil)
      }
    _ -> Error(Nil)
  }
}

fn format(bytes: BitArray) -> Result(String, Nil) {
  case bytes {
    <<
      a:bytes-size(4),
      b:bytes-size(2),
      c:bytes-size(2),
      d:bytes-size(2),
      e:bytes-size(6),
    >> ->
      Ok(
        hex(a)
        <> "-"
        <> hex(b)
        <> "-"
        <> hex(c)
        <> "-"
        <> hex(d)
        <> "-"
        <> hex(e),
      )
    _ -> Error(Nil)
  }
}

fn hex(bytes: BitArray) -> String {
  bytes |> bit_array.base16_encode |> string.lowercase
}

fn is_hex_len(s: String, expected_len: Int) -> Bool {
  string.length(s) == expected_len
  && s
  |> string.to_utf_codepoints
  |> list.all(fn(cp) {
    let n = string.utf_codepoint_to_int(cp)
    { n >= 48 && n <= 57 } || { n >= 97 && n <= 102 }
  })
}
