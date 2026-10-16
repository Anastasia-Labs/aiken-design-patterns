# Builtin Value benchmarks

These benchmarks compare `cardano/assets` and `cardano/value` with Aiken 1.1.24,
stdlib 4.0.0, and the compiler's default Plutus V3 cost model.

## Isolated operations

`builtin-value.ak` contains 30 comparisons covering:

- singleton NFT/lovelace extraction;
- `dict.expect_pop` versus native lookup/delete, in ascending and descending
  order, for 1, 4, 16, and 64 tokens;
- repeated `Assets` lookups, cached token-dictionary lookups, and native lookups.

Inputs are `const` fixtures delivered as runtime sampler arguments. Fixture
construction is excluded, while each native implementation includes conversion
from `Assets`. The removal fixtures contain exactly one policy and no leftover
tokens; they measure the removal operation rather than a complete mint policy.

Run in a terminal:

```sh
/home/km/code/aiken/target/debug/aiken bench -m benchs/builtin_value --max-size 1 --seed 42 --plain-numbers -t silent
```

## Complete nested-list helper

`linked-list-value.ak` exercises the public inner-list insertion helpers and
their application callbacks. Its fixtures and assertions are drawn from
`lib/tests/linked-list/nested.ak`, with larger child chains added by the sampler.
Fixtures cover empty and two-node inner lists, plus 16 and 64 nodes in both
ascending and descending order. Each fixture also has a corresponding property
test so a false callback result cannot pass unnoticed as a benchmark.

The native prototype changes only `validate_inner_node_outputs`: it converts
the pending same-policy mint dictionary once, looks up and deletes each
required node NFT, and converts the remainder back for namespace checks and
callbacks. The change is stored in `linked-list-native-value.patch`.

Run both implementations with identical seeds and silent traces:

```sh
bash lib/benchs/run-value-comparison.sh
```

The runner copies the project to a temporary directory, checks and benchmarks
the Assets baseline, applies the patch there, then checks and benchmarks the
native prototype. It also runs the existing nested-list properties against the
prototype, using `--max-success 10`. It stops on a failed command and removes
the temporary directory on exit. `AIKEN_BIN` can select a different compiler;
the default is `/home/km/code/aiken/target/debug/aiken`.

To run just the current implementation:

```sh
/home/km/code/aiken/target/debug/aiken bench -m benchs/linked_list_value --max-size 1 --seed 42 --plain-numbers -t silent
```

Linked-list spend helpers delegate structural validation to their dedicated
mint helpers and must be paired with them. These benchmarks exercise the
mint-side helpers; they do not replace that pairing.

## Reading the results

Each sampler has a fixed asset/node count. `--max-size 1` produces one
measurement per benchmark; it does not set that count. The compiler's
projected maximum sizes are not meaningful for these constant-size samplers.

Compare CPU and memory together, including the empty and small cases. The
nested-list measurements include test callback/assertion costs and conversion
costs. They measure helper execution, not a full validator entrypoint or
transaction budget. The 64-node cases are scaling stress fixtures.

Fixture construction happens in the sampler and is outside the measured
program. The same seed reproduces the same contexts for both implementations.
Plot-axis labels can round large integers; use suitable precision when
reporting percentage changes.
