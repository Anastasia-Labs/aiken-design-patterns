use aiken/collection/list
use aiken_design_patterns/utils
use cardano/transaction.{
  Input, NoDatum, Output, OutputReference, Transaction, placeholder,
}

/// Spend endpoint helper function. By including this in your validator, you'll
/// get an efficient access to your input, and a corresponding output.
///
/// > [!NOTE]
/// > This function has no protection against
/// > [double satisfaction](https://github.com/Plutonomicon/plutonomicon/blob/b6906173c3f98fb5d7b40fd206f9d6fe14d0b03b/vulnerabilities.md#double-satisfaction)
/// > vulnerability, as this can be done in multiple ways depending on the
/// > contract. If you can tolerate some extra overhead, consider using the
/// > multi-utxo-indexer (one-to-one) pattern for a convenient way of preventing
/// > this attack vector. Otherwise, consider tagging your output with input's
/// > output reference.
pub fn spend(
  validation_logic: fn(Int, Input, a, Int, Output) -> Bool,
  redeemer: a,
  input_index: Int,
  output_index: Int,
  own_ref: OutputReference,
  tx: Transaction,
) -> Bool {
  let Transaction { inputs, outputs, .. } = tx

  expect Some(Input { output_reference: in_ref, .. } as in_input) =
    inputs |> list.at(input_index)

  expect Some(out_utxo) = outputs |> list.at(output_index)

  // Indicated input must match the spending one.
  expect (own_ref == in_ref)?

  validation_logic(input_index, in_input, redeemer, output_index, out_utxo)
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
      outputs: [script_input.output],
    }
  spend(
    fn(_ii, _i, _r, _oi, _o) { True },
    0,
    input_index,
    0,
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
    0,
    input_index,
    0,
    script_input.output_reference,
    tx,
  )
}
