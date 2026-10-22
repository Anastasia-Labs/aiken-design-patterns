#!/usr/bin/env bash
set -euo pipefail

# Aiken diagnostics and benchmark plots require a terminal.
if [[ ! -t 1 ]]; then
  printf '%s\n' 'Run this benchmark script in a terminal (stdout must be a TTY).' >&2
  exit 1
fi

aiken_bin="${AIKEN_BIN:-aiken}"
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
benchmark_dir="$repo_root/lib/benchs"
scratch_dir="$(mktemp -d "${TMPDIR:-/tmp}/aiken-value-benchmarks.XXXXXX")"
trap 'rm -rf -- "$scratch_dir"' EXIT

cp "$repo_root/aiken.toml" "$repo_root/aiken.lock" "$scratch_dir/"
cp -R "$repo_root/lib" "$repo_root/validators" "$repo_root/env" "$scratch_dir/"
if [[ -d "$repo_root/build/packages" ]]; then
  mkdir -p "$scratch_dir/build"
  cp -R "$repo_root/build/packages" "$scratch_dir/build/"
fi

printf '%s\n' 'Checking benchmark fixtures with the Assets accumulator.'
"$aiken_bin" check "$scratch_dir" \
  -m benchs/linked_list_value --max-success 10 --seed 42 -t silent

printf '%s\n' 'Benchmarking the Assets accumulator.'
"$aiken_bin" bench "$scratch_dir" \
  -m benchs/linked_list_value --max-size 1 --seed 42 --plain-numbers -t silent

patch --batch --fuzz=0 --silent -d "$scratch_dir" -p1 \
  < "$benchmark_dir/linked-list-native-value.patch"

printf '%s\n' 'Checking the native Value accumulator and nested-list properties.'
"$aiken_bin" check "$scratch_dir" \
  -m benchs/linked_list_value -m tests/linked_list/nested \
  --max-success 10 --seed 42 -t silent

printf '%s\n' 'Benchmarking the native Value accumulator.'
"$aiken_bin" bench "$scratch_dir" \
  -m benchs/linked_list_value --max-size 1 --seed 42 --plain-numbers -t silent
