use aiken/builtin
use aiken/collection/list
use aiken/crypto.{ScriptHash}
use aiken/fuzz
use aiken_design_patterns/multi_utxo_indexer.{
  one_to_one_no_redeemer, one_to_one_with_redeemer,
}
use aiken_design_patterns/utils
use cardano/address.{Script}
use cardano/transaction.{Input, NoDatum, Output, Redeemer, ScriptPurpose, Spend}

fn tests_fuzzer() -> Fuzzer<
  (
    ScriptHash,
    List<Input>,
    List<Output>,
    Pairs<Int, Int>,
    Pairs<ScriptPurpose, Redeemer>,
  ),
> {
  let script_hash <- fuzz.and_then(fuzz.bytearray_fixed(28))
  let wallet_inputs <- fuzz.and_then(utils.user_inputs_fuzzer())
  let script_inputs <-
    fuzz.and_then(
      fuzz.list_between(
        utils.specific_script_input_fuzzer(script_hash, NoDatum),
        1,
        10,
      ),
    )
  let inputs = list.concat(wallet_inputs, script_inputs) |> utils.sort_inputs
  let (script_input_indices, script_outputs) =
    list.indexed_foldr(
      inputs,
      ([], []),
      fn(i, input, acc) {
        let (i_indices, outputs) = acc
        when input.output.address.payment_credential is {
          Script(_) ->
            (i_indices |> list.push(i), outputs |> list.push(input.output))
          _ -> acc
        }
      },
    )
  let indices =
    script_input_indices
      |> list.indexed_foldr(
          [],
          fn(i, script_input_index, acc) {
            list.push(acc, Pair(script_input_index, i))
          },
        )
  fuzz.constant(
    (
      script_hash,
      inputs,
      script_outputs,
      indices,
      list.map(
        script_inputs,
        fn(i) { Pair(Spend(i.output_reference), builtin.i_data(0)) },
      ),
    ),
  )
}

test success__one_to_one_no_redeemer(test_values via tests_fuzzer()) {
  let (script_hash, inputs, script_outputs, indices, _redeemers) = test_values
  one_to_one_no_redeemer(
    indices: indices,
    spending_script_hash: script_hash,
    inputs: inputs,
    outputs: script_outputs,
    validation_logic: fn(_ii, _i, _oi, _o) { True },
  )
}

test fail__one_to_one_no_redeemer__no_output(
  test_values via tests_fuzzer(),
) fail {
  let (script_hash, inputs, _script_outputs, indices, _redeemers) = test_values
  one_to_one_no_redeemer(
    indices: indices,
    spending_script_hash: script_hash,
    inputs: inputs,
    outputs: [],
    validation_logic: fn(_ii, _i, _oi, _o) { True },
  )
}

test success__one_to_one_with_redeemer(test_values via tests_fuzzer()) {
  let (script_hash, inputs, script_outputs, indices, redeemers) = test_values
  one_to_one_with_redeemer(
    indices: indices,
    spending_script_hash: script_hash,
    stake_script_hash: script_hash,
    inputs: inputs,
    outputs: script_outputs,
    redeemers: redeemers,
    spend_redeemer_coercer_and_stake_credential_extractor: fn(_d) {
      (0, Script(script_hash))
    },
    validation_logic: fn(_ii, _i, _r, _oi, _o) { True },
  )
}

test fail__one_to_one_with_redeemer__no_outputs(
  test_values via tests_fuzzer(),
) fail {
  let (script_hash, inputs, _script_outputs, indices, redeemers) = test_values
  one_to_one_with_redeemer(
    indices: indices,
    spending_script_hash: script_hash,
    stake_script_hash: script_hash,
    inputs: inputs,
    outputs: [],
    redeemers: redeemers,
    spend_redeemer_coercer_and_stake_credential_extractor: fn(_d) {
      (0, Script(script_hash))
    },
    validation_logic: fn(_ii, _i, _r, _oi, _o) { True },
  )
}
