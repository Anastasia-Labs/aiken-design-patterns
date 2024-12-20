use aiken/collection/list
use aiken_design_patterns/utils
use aiken_scott_utils/list as list_extra
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
/// 1. Input index, `Input` itself, redeemer, output index, and `Output` itself
///    (this validation is executed for each output)
/// 2. Input index, `Input` itself, redeemer, and the list of all `Output`s
///    (this validation is executed only once)
pub fn spend(
  input_output_validator: fn(Int, Input, a, Int, Output) -> Bool,
  input_collective_outputs_validator: fn(Int, Input, a, List<Output>) -> Bool,
  redeemer: a,
  input_index: Int,
  output_indices: List<Int>,
  own_ref: OutputReference,
  tx: Transaction,
) -> Bool {
  let Transaction { inputs, outputs, .. } = tx

  expect Some(input) = inputs |> list.at(input_index)

  let
    _,
    all_outputs,
  <-
    list_extra.foldr2(
      output_indices,
      // sufficiently large index to ensure first check passes
      511,
      [],
      fn(curr_ix, prev_ix, outputs_acc, return) {
        if curr_ix < prev_ix {
          expect Some(out_utxo) = outputs |> list.at(curr_ix)
          expect
            input_output_validator(
              input_index,
              input,
              redeemer,
              curr_ix,
              out_utxo,
            )?
          return(curr_ix, list.push(outputs_acc, out_utxo))
        } else {
          fail @"Output indices must be in ascending order"
        }
      },
    )

  // Indicated input must match the spending one.
  expect (own_ref == input.output_reference)?

  input_collective_outputs_validator(input_index, input, redeemer, all_outputs)
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
  trace Pair(input_index, list.range(0, 9))
  spend(
    fn(_ii, _i, _r, _oi, _o) { True },
    fn(_ii, _i, _r, _os) { True },
    0,
    input_index,
    list.range(0, 9),
    script_input.output_reference,
    tx,
  )
}

test fail_spend(
  script_hash_and_inputs via utils.inputs_with_an_authentic_script_input_fuzzer(
    NoDatum,
  ),
) fail {
  let (_script_hash, script_input, inputs) = script_hash_and_inputs
  let input_index = utils.find_index_of_first_script_input(inputs)
  let tx = Transaction { ..placeholder, inputs: inputs, outputs: [] }
  spend(
    fn(_ii, _i, _r, _oi, _o) { True },
    fn(_ii, _i, _r, _os) { True },
    0,
    input_index,
    list.range(0, 9),
    script_input.output_reference,
    tx,
  )
}
