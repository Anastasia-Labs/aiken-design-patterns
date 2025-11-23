use aiken/builtin
use aiken/collection/list
use aiken/crypto.{ScriptHash}
use aiken/fuzz
use aiken_design_patterns/multi_utxo_indexer.{
  withdraw_no_redeemer, withdraw_with_redeemer,
}
use aiken_design_patterns/utils
use cardano/address.{Script}
use cardano/transaction.{
  Input, NoDatum, Output, Redeemer, ScriptPurpose, Spend, Transaction,
  placeholder,
}

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
  let redeemer =
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
      redeemer,
      list.map(
        script_inputs,
        fn(i) { Pair(Spend(i.output_reference), builtin.i_data(0)) },
      ),
    ),
  )
}

test success_withdraw_no_redeemer(test_values via tests_fuzzer()) {
  let (script_hash, inputs, script_outputs, redeemer, _redeemers) = test_values
  let tx = Transaction { ..placeholder, inputs, outputs: script_outputs }
  withdraw_no_redeemer(
    fn(_ii, _i, _oi, _o) { True },
    redeemer,
    Script(script_hash),
    tx,
  )
}

test fail_withdraw_no_redeemer(test_values via tests_fuzzer()) fail {
  let (script_hash, inputs, _script_outputs, redeemer, _redeemers) = test_values
  let tx = Transaction { ..placeholder, inputs, outputs: [] }
  withdraw_no_redeemer(
    fn(_ii, _i, _oi, _o) { True },
    redeemer,
    Script(script_hash),
    tx,
  )
}

test success_withdraw_with_redeemer(test_values via tests_fuzzer()) {
  let (script_hash, inputs, script_outputs, redeemer, redeemers) = test_values
  let tx =
    Transaction { ..placeholder, inputs, outputs: script_outputs, redeemers }
  withdraw_with_redeemer(
    fn(_d) { (0, Script(script_hash)) },
    fn(_ii, _i, _r, _oi, _o) { True },
    redeemer,
    Script(script_hash),
    tx,
  )
}

test fail_withdraw_with_redeemer(test_values via tests_fuzzer()) fail {
  let (script_hash, inputs, script_outputs, redeemer, _redeemers) = test_values
  let tx =
    Transaction {
      ..placeholder,
      inputs,
      outputs: script_outputs,
      redeemers: [],
    }
  withdraw_with_redeemer(
    fn(_d) { (0, Script(script_hash)) },
    fn(_ii, _i, _r, _oi, _o) { True },
    redeemer,
    Script(script_hash),
    tx,
  )
}
