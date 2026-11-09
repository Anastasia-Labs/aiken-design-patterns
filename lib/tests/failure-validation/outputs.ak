use aiken/builtin
use aiken/collection/list
use aiken/fuzz
use aiken_design_patterns/failure_validation/outputs
use tests/failure_validation/bodies

test count__ordinary_outputs() {
  outputs.count(bodies.outputs) == 1
}

test count__embedded_datum() {
  outputs.count(bodies.inline_datum_output) == 1
}

test count__embedded_reference_script() {
  outputs.count(bodies.reference_script_output) == 1
}

test count__empty_definite() {
  outputs.count(#"80") == 0
}

test count__empty_indefinite() {
  outputs.count(#"9fff") == 0
}

test count__nested_definite_containers() {
  outputs.count(#"82a2018201020282020380") == 2
}

test count__nested_indefinite_containers() {
  outputs.count(#"9fbf009f01ffffff") == 1
}

test count__nested_arrays_and_sibling() {
  outputs.count(#"9f9f019f02ffff03ff") == 2
}

test count__byte_string_with_break_bytes() {
  outputs.count(#"8144ffffffff") == 1
}

test count__tagged_byte_string() {
  outputs.count(#"81d8184240ff") == 1
}

test count__chunked_bytes() {
  outputs.count(#"815f42ffff410040ff") == 1
}

test count__chunked_text() {
  outputs.count(#"817f616162626360ff") == 1
}

test count__empty_strings() {
  outputs.count(#"824060") == 2
}

test count__integers_and_simple_values() {
  outputs.count(#"8b0018181901001a000100001b010000000000000020381841416141f6f5") == 11
}

test count__floats_and_extended_simple() {
  outputs.count(#"84f93c00fa3f800000fb3ff0000000000000f820") == 4
}

test count__array_head_one_byte() {
  outputs.count(#"980100") == 1
}

test count__array_head_two_bytes() {
  outputs.count(#"99000100") == 1
}

test count__array_head_four_bytes() {
  outputs.count(#"9a0000000100") == 1
}

test count__array_head_eight_bytes() {
  outputs.count(#"9b000000000000000100") == 1
}

test count__nonminimal_nested_heads() {
  outputs.count(#"819801580100") == 1
}

const twenty_three_outputs =
  builtin.append_bytearray(#"97", builtin.replicate_byte(23, 0))

const twenty_four_outputs =
  builtin.append_bytearray(#"9818", builtin.replicate_byte(24, 0))

const two_hundred_fifty_six_outputs =
  builtin.append_bytearray(#"990100", builtin.replicate_byte(256, 0))

test count__header_boundary_23() {
  outputs.count(twenty_three_outputs) == 23
}

test count__header_boundary_24() {
  outputs.count(twenty_four_outputs) == 24
}

test count__header_boundary_256() {
  outputs.count(two_hundred_fifty_six_outputs) == 256
}

test count__rejects_empty_bytes() fail {
  expect _ = outputs.count(#"")
}

test count__rejects_non_array() fail {
  expect _ = outputs.count(#"00")
}

test count__rejects_tagged_array() fail {
  expect _ = outputs.count(#"d81880")
}

test count__rejects_truncated_array_head() fail {
  expect _ = outputs.count(#"98")
}

test count__rejects_truncated_wide_array_head() fail {
  expect _ = outputs.count(#"9b00000000000000")
}

test count__rejects_reserved_head() fail {
  expect _ = outputs.count(#"9c")
}

test count__rejects_reserved_nested_head() fail {
  expect _ = outputs.count(#"819e")
}

test count__rejects_missing_array_item() fail {
  expect _ = outputs.count(#"8200")
}

test count__rejects_extra_array_item() fail {
  expect _ = outputs.count(#"810000")
}

test count__rejects_truncated_byte_string() fail {
  expect _ = outputs.count(#"814201")
}

test count__rejects_truncated_text_string() fail {
  expect _ = outputs.count(#"816201")
}

test count__rejects_truncated_integer() fail {
  expect _ = outputs.count(#"811a001122")
}

test count__rejects_truncated_float() fail {
  expect _ = outputs.count(#"81fb00000000000000")
}

test count__rejects_unterminated_array() fail {
  expect _ = outputs.count(#"9f00")
}

test count__rejects_unterminated_nested_array() fail {
  expect _ = outputs.count(#"819f00")
}

test count__rejects_unterminated_map() fail {
  expect _ = outputs.count(#"81bf0000")
}

test count__rejects_incomplete_definite_map() fail {
  expect _ = outputs.count(#"81a100")
}

test count__rejects_incomplete_indefinite_map() fail {
  expect _ = outputs.count(#"81bf00ff")
}

test count__rejects_missing_tag_value() fail {
  expect _ = outputs.count(#"81d818")
}

test count__rejects_indefinite_unsigned_integer() fail {
  expect _ = outputs.count(#"811f")
}

test count__rejects_indefinite_negative_integer() fail {
  expect _ = outputs.count(#"813f")
}

test count__rejects_indefinite_tag() fail {
  expect _ = outputs.count(#"81df00")
}

test count__rejects_unexpected_break() fail {
  expect _ = outputs.count(#"81ff")
}

test count__rejects_break_in_definite_array() fail {
  expect _ = outputs.count(#"8181ff")
}

test count__rejects_unterminated_chunked_bytes() fail {
  expect _ = outputs.count(#"815f4100")
}

test count__rejects_wrong_byte_chunk_type() fail {
  expect _ = outputs.count(#"815f6161ff")
}

test count__rejects_wrong_text_chunk_type() fail {
  expect _ = outputs.count(#"817f4100ff")
}

test count__rejects_indefinite_byte_chunk() fail {
  expect _ = outputs.count(#"815f5f40ffff")
}

test count__rejects_truncated_byte_chunk() fail {
  expect _ = outputs.count(#"815f4200")
}

test count__rejects_trailing_bytes_after_indefinite_array() fail {
  expect _ = outputs.count(#"9fff00")
}

test count__rejects_oversized_declared_array() fail {
  expect _ = outputs.count(#"9bffffffffffffffff")
}

test count__rejects_oversized_declared_string() fail {
  expect _ = outputs.count(#"815bffffffffffffffff")
}

// Compare against independently serialized nested Plutus Data, rather than a
// second implementation of the scanner.
test count__serialized_data_lists(
  items via fuzz.list_between(fuzz.data(), 0, 30),
) {
  outputs.count(builtin.serialise_data(builtin.list_data(items))) == list.length(
    items,
  )
}

test count__skips_arbitrary_byte_payloads(
  payload via fuzz.bytearray_between(0, 256),
) {
  outputs.count(
    builtin.serialise_data(builtin.list_data([builtin.b_data(payload)])),
  ) == 1
}

test count__rejects_appended_data(
  items via fuzz.list_between(fuzz.data(), 0, 10),
) fail {
  expect _ = outputs.count(
    builtin.append_bytearray(
      builtin.serialise_data(builtin.list_data(items)),
      #"00",
    ),
  )
}
