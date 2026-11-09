//// @hidden
//// Structural CBOR scanning for the authenticated ordinary-output array.
//// Payloads retain their exact bytes. Ledger validation checks output semantics;
//// this scanner checks item boundaries and counts only top-level elements.

use aiken/builtin

/// Count one complete CBOR array, rejecting truncation and trailing bytes.
/// Embedded byte strings are skipped by length, including encoded Plutus Data
/// and scripts. Definite and indefinite containers and nonminimal heads work.
pub fn count(bytes: ByteArray) -> Int {
  let length = builtin.length_of_bytearray(bytes)
  expect length > 0
  let major, argument, cursor <- head(bytes, length, 0)
  expect major == 4
  if argument == -1 {
    let count, end <- indefinite_items(bytes, length, cursor, 0)
    expect end == length
    count
  } else {
    expect skip_items(bytes, length, cursor, argument) == length
    argument
  }
}

// A negative argument denotes an indefinite item. Reserved head values fail.
fn head(
  bytes: ByteArray,
  length: Int,
  cursor: Int,
  return: fn(Int, Int, Int) -> result,
) -> result {
  let byte = builtin.index_bytearray(bytes, cursor)
  let major = byte / 32
  let additional = byte % 32
  if additional < 24 {
    return(major, additional, cursor + 1)
  } else if additional == 31 {
    return(major, -1, cursor + 1)
  } else {
    let width = when additional is {
      24 -> 1
      25 -> 2
      26 -> 4
      27 -> 8
      _ -> fail
    }
    let end = cursor + 1 + width
    expect end <= length
    let argument = builtin.bytearray_to_integer(
      True,
      builtin.slice_bytearray(cursor + 1, width, bytes),
    )
    return(major, argument, end)
  }
}

fn skip_item(bytes: ByteArray, length: Int, cursor: Int) -> Int {
  let major, argument, cursor <- head(bytes, length, cursor)
  when major is {
    2 | 3 ->
      if argument == -1 {
        skip_chunks(bytes, length, cursor, major)
      } else {
        let end = cursor + argument
        expect end <= length
        end
      }
    4 | 5 ->
      if argument == -1 {
        let count, end <- indefinite_items(bytes, length, cursor, 0)
        // An indefinite map must contain complete key/value pairs.
        expect major == 4 || count % 2 == 0
        end
      } else {
        skip_items(
          bytes,
          length,
          cursor,
          if major == 5 {
            argument * 2
          } else {
            argument
          },
        )
      }
    6 -> {
      expect argument >= 0
      skip_item(bytes, length, cursor)
    }
    _ -> {
      // Integers and simple/float items have no payload beyond their head.
      // A break is only legal when consumed by an indefinite-container loop.
      expect argument >= 0
      cursor
    }
  }
}

fn skip_items(bytes: ByteArray, length: Int, cursor: Int, remaining: Int) -> Int {
  if remaining == 0 {
    cursor
  } else {
    skip_items(bytes, length, skip_item(bytes, length, cursor), remaining - 1)
  }
}

fn indefinite_items(
  bytes: ByteArray,
  length: Int,
  cursor: Int,
  count: Int,
  return: fn(Int, Int) -> result,
) -> result {
  if builtin.index_bytearray(bytes, cursor) == 255 {
    return(count, cursor + 1)
  } else {
    indefinite_items(
      bytes,
      length,
      skip_item(bytes, length, cursor),
      count + 1,
      return,
    )
  }
}

fn skip_chunks(
  bytes: ByteArray,
  length: Int,
  cursor: Int,
  string_major: Int,
) -> Int {
  if builtin.index_bytearray(bytes, cursor) == 255 {
    cursor + 1
  } else {
    let major, argument, cursor <- head(bytes, length, cursor)
    expect major == string_major
    expect argument >= 0
    let end = cursor + argument
    expect end <= length
    skip_chunks(bytes, length, end, string_major)
  }
}
