use aiken/builtin
use aiken/collection/list
use aiken/crypto.{ScriptHash}
use aiken/fuzz
use aiken_design_patterns/stake_validator
use aiken_design_patterns/utils
use aiken_scott_utils/list as list_extra
use cardano/address.{Address, Credential, Script}
use cardano/transaction.{
  Input, NoDatum, Output, Redeemer, ScriptPurpose, Spend, Transaction,
  placeholder,
}

/// Helper function to complement your staking script. Note that this function
/// expects to see an equal number of inputs coming from addresses whose payment
/// parts are **equal to its own** (`stake_cred`). This is an important detail,
/// as the validator needs to guarantee an exact number of inputs are spent.
///
/// The validation function you should provide has access to:
/// - Index of the `Input` being validated
/// - The `Input` itself
/// - Index of the `Output` being validated
/// - The `Output` itself
pub fn withdraw_no_redeemer(
  validation_logic: fn(Int, Input, Int, Output) -> Bool,
  indices: Pairs<Int, Int>,
  stake_cred: Credential,
  tx: Transaction,
) -> Bool {
  stake_validator.withdraw(
    fn(indices, own_validator, tx) {
      let Transaction { inputs, outputs, .. } = tx
      let
        processed_indices,
        _,
        _,
        _,
      <-
        list_extra.foldl4(
          inputs,
          indices,
          -1,
          -1,
          0,
          fn(input, remaining_indices, in0, out0, i, return) {
            let next_i = i + 1
            when input.output.address.payment_credential is {
              Script(script) ->
                if script == own_validator {
                  when remaining_indices is {
                    [] -> fail @"More UTxOs are spent than specified"
                    [Pair(in1, out1), ..rest_of_indices] ->
                      if i == in1 && in1 > in0 && out1 > out0 {
                        expect Some(out_utxo) = outputs |> list.at(out1)
                        if validation_logic(in1, input, out1, out_utxo) {
                          return(rest_of_indices, in1, out1, next_i)
                        } else {
                          fail @"Validation failed"
                        }
                      } else {
                        fail @"Input and output indices must be in ascending orders"
                      }
                  }
                } else {
                  return(remaining_indices, in0, out0, next_i)
                }
              _ -> return(remaining_indices, in0, out0, next_i)
            }
          },
        )
      (processed_indices == [])?
    },
    indices,
    stake_cred,
    tx,
  )
}

/// Another variant that is independent of the spending validator, and also
/// provides the validation logic with each UTxO's redeemer. Subsequently, an
/// additional argument must be provided, capable of coercing a redeemer `Data`
/// to spending script's redeemer, and also extracting the staking credential of
/// the script that performs the validation.
///
/// Under the hood, one other difference is that here, instead of traversing all
/// the inputs, there are two traversals: one over the `redeemers`, and another
/// over the indices.
pub fn withdraw_with_redeemer(
  spend_redeemer_coercer_and_stake_credential_extractor: fn(Data) ->
    (a, Credential),
  validation_logic: fn(Int, Input, a, Int, Output) -> Bool,
  indices: Pairs<Int, Int>,
  stake_cred: Credential,
  tx: Transaction,
) -> Bool {
  let Transaction { inputs, outputs, redeemers, .. } = tx
  let script_redeemers =
    list.foldr(
      redeemers,
      [],
      fn(redeemer, acc) {
        let Pair(redeemer_purpose, redeemer_data) = redeemer
        when redeemer_purpose is {
          Spend(_) -> {
            let (coerced_redeemer, stake_credential_from_spend_redeemer) =
              spend_redeemer_coercer_and_stake_credential_extractor(
                redeemer_data,
              )
            if stake_cred == stake_credential_from_spend_redeemer {
              list.push(acc, coerced_redeemer)
            } else {
              acc
            }
          }
          _ -> acc
        }
      },
    )
  let
    processed_redeemers,
    _,
    _,
    _,
  <-
    list_extra.foldl4(
      indices,
      script_redeemers,
      -1,
      -1,
      0,
      fn(curr_in_out_indices, remaining_script_redeemers, in0, out0, i, return) {
        when remaining_script_redeemers is {
          [] -> fail @"Too many indices specified"
          [script_redeemer, ..rest_of_script_redeemers] -> {
            let Pair(in1, out1) = curr_in_out_indices
            if in1 > in0 && out1 > out0 {
              expect Some(in_utxo) = inputs |> list.at(in1)
              expect Some(out_utxo) = outputs |> list.at(out1)
              if validation_logic(in1, in_utxo, script_redeemer, out1, out_utxo) {
                return(rest_of_script_redeemers, in1, out1, i + 1)
              } else {
                fail @"Validation failed"
              }
            } else {
              // Input and output indices must be ordered to disallow duplicates.
              fail @"Input and output indices must be in ascending orders"
            }
          }
        }
      },
    )
  (processed_redeemers == [])?
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
  let tx =
    Transaction { ..placeholder, inputs: inputs, outputs: script_outputs }
  withdraw_no_redeemer(
    fn(_ii, _i, _oi, _o) { True },
    redeemer,
    Script(script_hash),
    tx,
  )
}

test fail_withdraw_no_redeemer(test_values via tests_fuzzer()) fail {
  let (script_hash, inputs, _script_outputs, redeemer, _redeemers) = test_values
  let tx = Transaction { ..placeholder, inputs: inputs, outputs: [] }
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
    Transaction {
      ..placeholder,
      inputs: inputs,
      outputs: script_outputs,
      redeemers: redeemers,
    }
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
      inputs: inputs,
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
