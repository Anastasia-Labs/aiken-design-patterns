use aiken/collection/list
use aiken_design_patterns/singular_utxo_indexer.{one_to_many, one_to_one}
use aiken_design_patterns/utils
use cardano/transaction.{Input, NoDatum, Output}

fn always_true_in_out(_i: Input, _o: Output) -> Bool {
  True
}

fn always_true_in_outs(_i: Input, _os: List<Output>) -> Bool {
  True
}

test success__one_to_one(
  script_hash_and_inputs via utils.inputs_with_an_authentic_script_input_fuzzer(
    NoDatum,
  ),
) {
  let (_script_hash, script_input, inputs) = script_hash_and_inputs
  let input_index = utils.find_index_of_first_script_input(inputs)
  one_to_one(
    input_index,
    0,
    script_input.output_reference,
    inputs,
    [script_input.output],
    True,
    always_true_in_out,
  )
}

test fail__one_to_one__bad_outputs(
  script_hash_and_inputs via utils.inputs_with_an_authentic_script_input_fuzzer(
    NoDatum,
  ),
) fail {
  let (_script_hash, script_input, inputs) = script_hash_and_inputs
  let input_index = utils.find_index_of_first_script_input(inputs)
  one_to_one(
    input_index,
    0,
    script_input.output_reference,
    inputs,
    [],
    True,
    always_true_in_out,
  )
}

test success__one_to_many(
  script_hash_and_inputs via utils.inputs_with_an_authentic_script_input_fuzzer(
    NoDatum,
  ),
) {
  let (_script_hash, script_input, inputs) = script_hash_and_inputs
  let input_index = utils.find_index_of_first_script_input(inputs)
  trace Pair(input_index, list.range(0, 9))
  one_to_many(
    input_index,
    list.range(0, 9),
    script_input.output_reference,
    inputs,
    list.repeat(script_input.output, 10),
    True,
    always_true_in_outs,
    fn(_i, _oi, _o) { True },
  )
}

test fail__one_to_many__bad_outputs(
  script_hash_and_inputs via utils.inputs_with_an_authentic_script_input_fuzzer(
    NoDatum,
  ),
) fail {
  let (_script_hash, script_input, inputs) = script_hash_and_inputs
  let input_index = utils.find_index_of_first_script_input(inputs)
  one_to_many(
    input_index,
    list.range(0, 9),
    script_input.output_reference,
    inputs,
    [],
    True,
    always_true_in_outs,
    fn(_i, _oi, _o) { True },
  )
}
