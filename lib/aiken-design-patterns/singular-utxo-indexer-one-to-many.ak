use aiken/collection/list
use aiken_design_patterns/utils as utils
use cardano/assets.{Value}
use cardano/transaction.{
  Input, NoDatum, Output, OutputReference, Transaction, placeholder,
}

/// Spend endpoint helper function. By including this in your validator, you'll
/// an efficient access to your input, its corresponding outputs, total output
/// value and count.
///
/// > [!NOTE]
/// > This function has no protection against
/// > [double satisfaction](https://github.com/Plutonomicon/plutonomicon/blob/b6906173c3f98fb5d7b40fd206f9d6fe14d0b03b/vulnerabilities.md#double-satisfaction)
/// > vulnerability, as this can be done in multiple ways depending on the
/// > contract. If you can tolerate some extra overhead, consider using the
/// > multi-utxo-indexer (one-to-many) pattern for a convenient way of
/// > preventing this attack vector.
///
/// Required validation functions are provided with:
/// 1. The input itself
/// 2. The resolved input, its corresponding output
/// 3. Total output value, and total output count
pub fn spend(
  input_validator: fn(Input) -> Bool,
  input_output_validator: fn(Output, Output) -> Bool,
  output_value_and_count_validator: fn(Value, Int) -> Bool,
  redeemer: Pair<Int, List<Int>>,
  own_ref: OutputReference,
  tx: Transaction,
) -> Bool {
  let Transaction { inputs, outputs, .. } = tx

  let Pair(in_ix, out_ixs) = redeemer

  expect Some(Input { output: in_utxo, output_reference: in_ref } as input) =
    inputs |> list.at(in_ix)

  expect input_validator(input)?

  let
    _,
    total_output_value,
    output_count,
  <-
    utils.foldl3(
      out_ixs,
      -1,
      assets.zero,
      0,
      fn(curr_ix, prev_ix, value_so_far, count, return) {
        if curr_ix > prev_ix {
          expect Some(out_utxo) = outputs |> list.at(curr_ix)
          expect input_output_validator(in_utxo, out_utxo)?
          return(curr_ix, assets.merge(value_so_far, out_utxo.value), count + 1)
        } else {
          fail @"Output indices must be in ascending order"
        }
      },
    )

  // Indicated input must match the spending one.
  expect (own_ref == in_ref)?

  output_value_and_count_validator(total_output_value, output_count)
}

test success_spend(
  script_hash_and_inputs via utils.inputs_with_an_authentic_script_input_fuzzer(
    NoDatum,
  ),
) {
  let (_script_hash, script_input, inputs) = script_hash_and_inputs
  let input_index = utils.find_index_of_first_script_input(inputs)
  let tx =
    Transaction {
      ..placeholder,
      inputs: inputs,
      outputs: list.repeat(script_input.output, 10),
    }
  spend(
    fn(_i) { True },
    fn(_i, _o) { True },
    fn(_v, _c) { True },
    Pair(input_index, list.range(0, 9)),
    script_input.output_reference,
    tx,
  )
}

test fail_spend(
  script_hash_and_inputs via utils.inputs_with_an_authentic_script_input_fuzzer(
    NoDatum,
  ),
) {
  let (_script_hash, script_input, inputs) = script_hash_and_inputs
  let input_index = utils.find_index_of_first_script_input(inputs)
  let tx = Transaction { ..placeholder, inputs: inputs, outputs: [] }
  spend(
    fn(_i) { True },
    fn(_i, _o) { True },
    fn(_v, _c) { True },
    Pair(input_index, list.range(0, 9)),
    script_input.output_reference,
    tx,
  )
}
