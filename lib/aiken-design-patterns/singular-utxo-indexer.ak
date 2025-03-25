use aiken/collection/list
use aiken_design_patterns/utils
use aiken_scott_utils/list as list_extra
use cardano/transaction.{Input, NoDatum, Output, OutputReference}

/// Helper function to be defined in the spending endpoint of your contract, for
/// appointing an input at `input_index` against an output at `output_index`. By
/// including this in your spending endpoint, you'll get an efficient access to
/// your input, and its corresponding output.
///
/// Within the function you pass as `validation_logic`, you have access to the
/// picked input and output.
///
/// Apart from `validation_logic`, the only other validation this function
/// performs for you is the equality of the picked input's output reference with
/// the one extracted from [`ScriptInfo`](https://aiken-lang.github.io/stdlib/cardano/script_context.html#ScriptInfo).
///
/// `double_satisfaction_prevented` is a required `Bool`, which is just a
/// reminder that this function does NOT cover the
/// [double satisfaction](https://github.com/Plutonomicon/plutonomicon/blob/b6906173c3f98fb5d7b40fd206f9d6fe14d0b03b/vulnerabilities.md#double-satisfaction)
/// vulnerability out-of-the-box.
pub fn one_to_one(
  validation_logic: fn(Input, Output) -> Bool,
  input_index: Int,
  output_index: Int,
  own_ref: OutputReference,
  inputs: List<Input>,
  outputs: List<Output>,
  double_satisfaction_prevented: Bool,
) -> Bool {
  expect double_satisfaction_prevented
  expect Some(Input { output_reference: in_ref, .. } as in_input) =
    inputs |> list.at(input_index)

  expect Some(out_utxo) = outputs |> list.at(output_index)

  // Indicated input must match the spending one.
  expect own_ref == in_ref

  validation_logic(in_input, out_utxo)
}

/// Helper function for appointing an input against a set of outputs in a
/// transaction. Similar to [`one_to_one`](#one_to-one), this function also
/// validates the spent UTxO's output reference matches the one found using the
/// input index.
///
/// Required validation functions are provided with:
/// 1. `Input` itself, output index, and `Output` itself (this validation is
///    executed for each output)
/// 2. `Input` itself, and the list of all `Output`s (this validation is
///    executed only once)
///
/// Here we also have the `double_satisfaction_prevented` argument as a mere
/// reminder that this function does not cover double satisfaction on its own.
pub fn one_to_many(
  input_output_validator: fn(Input, Int, Output) -> Bool,
  input_collective_outputs_validator: fn(Input, List<Output>) -> Bool,
  input_index: Int,
  output_indices: List<Int>,
  own_ref: OutputReference,
  inputs: List<Input>,
  outputs: List<Output>,
  double_satisfaction_prevented: Bool,
) -> Bool {
  expect double_satisfaction_prevented
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
          expect input_output_validator(input, curr_ix, out_utxo)
          return(curr_ix, list.push(outputs_acc, out_utxo))
        } else {
          fail @"Output indices must be in ascending order"
        }
      },
    )

  // Indicated input must match the spending one.
  expect (own_ref == input.output_reference)?

  input_collective_outputs_validator(input, all_outputs)
}

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
    always_true_in_out,
    input_index,
    0,
    script_input.output_reference,
    inputs,
    [script_input.output],
    double_satisfaction_prevented: True,
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
    always_true_in_out,
    input_index,
    0,
    script_input.output_reference,
    inputs,
    [],
    double_satisfaction_prevented: True,
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
    fn(_i, _oi, _o) { True },
    always_true_in_outs,
    input_index,
    list.range(0, 9),
    script_input.output_reference,
    inputs,
    list.repeat(script_input.output, 10),
    double_satisfaction_prevented: True,
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
    fn(_i, _oi, _o) { True },
    always_true_in_outs,
    input_index,
    list.range(0, 9),
    script_input.output_reference,
    inputs,
    [],
    double_satisfaction_prevented: True,
  )
}
