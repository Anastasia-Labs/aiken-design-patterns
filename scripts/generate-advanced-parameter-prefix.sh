#!/usr/bin/env bash
set -euo pipefail

AIKEN="${AIKEN:-aiken}"
BLUEPRINT="${BLUEPRINT:-plutus.json}"
OUT="${OUT:-build/advanced-parameter-applied.json}"
ENV_FILE="${ENV_FILE:-env/default.ak}"
PARAMETER="${PARAMETER:-5820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f}"
TITLE='"title":"examples/parameter_validation/advanced.parameterized_spend.spend"'

"$AIKEN" build
"$AIKEN" blueprint apply "$PARAMETER" \
  -m examples/parameter_validation/advanced \
  -v parameterized_spend \
  -i "$BLUEPRINT" \
  -o "$OUT"

json="$(<"$OUT")"
json="${json//[[:space:]]/}"
validator_json="${json#*$TITLE}"
compiled="${validator_json#*\"compiledCode\":\"}"
compiled="${compiled%%\"*}"
before_parameter="${compiled%%$PARAMETER*}"

case "${compiled:0:2}" in
  58) outer_header_hex_chars=4 ;;
  59) outer_header_hex_chars=6 ;;
  5a) outer_header_hex_chars=10 ;;
  5b) outer_header_hex_chars=18 ;;
  *) outer_header_hex_chars=2 ;;
esac

flat_prefix="${before_parameter:$outer_header_hex_chars:${#before_parameter} - outer_header_hex_chars - 2}"

printf 'pub const flat_prefix_without_parameter_header = #"%s"\n' "$flat_prefix" >"$ENV_FILE"
"$AIKEN" fmt
