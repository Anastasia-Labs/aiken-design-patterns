use aiken_design_patterns/singular_utxo_indexer.{spend}
use aiken_design_patterns/utils
use cardano/transaction.{NoDatum, Transaction, placeholder}

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
