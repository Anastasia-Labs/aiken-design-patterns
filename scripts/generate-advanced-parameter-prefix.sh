#!/usr/bin/env bash
set -euo pipefail

AIKEN="${AIKEN:-aiken}"
BLUEPRINT="${BLUEPRINT:-plutus.json}"
OUT_DIR="${OUT_DIR:-build}"
ENV_FILE="${ENV_FILE:-env/default.ak}"
MODULE="examples/parameter_validation/advanced"
BYTES_PARAMETER="${BYTES_PARAMETER:-5820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f}"
INT_PARAMETER="${INT_PARAMETER:-1a000f4240}"
LIST_PARAMETER="${LIST_PARAMETER:-83182a1903e81a000f4240}"
CUSTOM_PARAMETER="${CUSTOM_PARAMETER:-d8798245aabbccddee1a000f4240}"

"$AIKEN" build

: >"$ENV_FILE"

write_prefix() {
  name="$1"
  validator="$2"
  parameter="$3"
  out="$OUT_DIR/advanced-parameter-$validator.json"
  title="\"title\":\"$MODULE.$validator.spend\""

  "$AIKEN" blueprint apply "$parameter" \
    -m "$MODULE" \
    -v "$validator" \
    -i "$BLUEPRINT" \
    -o "$out"

  json="$(<"$out")"
  json="${json//[[:space:]]/}"
  validator_json="${json#*$title}"
  compiled="${validator_json#*\"compiledCode\":\"}"
  compiled="${compiled%%\"*}"
  before_parameter="${compiled%%$parameter*}"

  case "${compiled:0:2}" in
    58) outer_header_hex_chars=4 ;;
    59) outer_header_hex_chars=6 ;;
    5a) outer_header_hex_chars=10 ;;
    5b) outer_header_hex_chars=18 ;;
    *) outer_header_hex_chars=2 ;;
  esac

  flat_prefix="${before_parameter:$outer_header_hex_chars:${#before_parameter} - outer_header_hex_chars - 2}"

  printf 'pub const %s = #"%s"\n\n' "$name" "$flat_prefix" >>"$ENV_FILE"
}

write_prefix flat_prefix_without_parameter_header parameterized_spend "$BYTES_PARAMETER"
write_prefix int_flat_prefix_without_parameter_header parameterized_spend_int "$INT_PARAMETER"
write_prefix list_flat_prefix_without_parameter_header parameterized_spend_list "$LIST_PARAMETER"
write_prefix custom_flat_prefix_without_parameter_header parameterized_spend_custom "$CUSTOM_PARAMETER"
"$AIKEN" fmt
