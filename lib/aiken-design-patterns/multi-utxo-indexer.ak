use aiken/collection/list
use aiken/crypto.{ScriptHash}
use aiken/fuzz
use aiken_design_patterns/stake_validator as stake_validator
use aiken_design_patterns/utils as utils
use cardano/address.{Address, Credential, Script}
use cardano/transaction.{Input, NoDatum, Output, Transaction, placeholder}

/// Helper function to compelement your staking script. Note that this function
/// expects to see an equal number of inputs coming from addresses which their
/// payment parts are equal to its own (`stake_cred`).
pub fn withdraw(
  validation_logic: fn(Output, Output) -> Bool,
  redeemer: Pairs<Int, Int>,
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
        utils.foldl4(
          inputs,
          indices,
          -1,
          -1,
          0,
          fn(input, remaining_indices, in0, out0, i, return) {
            let next_i = i + 1
            let Input { output: in_utxo, .. } = input
            when in_utxo.address.payment_credential is {
              Script(script) ->
                if script == own_validator {
                  when remaining_indices is {
                    [] -> fail @"More UTxOs are spent than specified"
                    [Pair(in1, out1), ..rest_of_indices] ->
                      if i == in1 && in1 > in0 && out1 > out0 {
                        expect Some(out_utxo) = outputs |> list.at(out1)
                        if validation_logic(in_utxo, out_utxo) {
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
    redeemer,
    stake_cred,
    tx,
  )
}

fn tests_fuzzer() -> Fuzzer<
  (ScriptHash, List<Input>, List<Output>, Pairs<Int, Int>),
> {
  let script_hash <- fuzz.and_then(fuzz.bytearray_fixed(28))
  let wallet_inputs <- fuzz.and_then(utils.user_inputs_fuzzer())
  let script_inputs <-
    fuzz.and_then(
      fuzz.list(utils.specific_script_input_fuzzer(script_hash, NoDatum)),
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
  fuzz.constant((script_hash, inputs, script_outputs, redeemer))
}

test success_withdraw(test_values via tests_fuzzer()) {
  let (script_hash, inputs, script_outputs, redeemer) = test_values
  let tx =
    Transaction { ..placeholder, inputs: inputs, outputs: script_outputs }
  withdraw(fn(_i, _o) { True }, redeemer, Script(script_hash), tx)
}

test fail_withdraw(test_values via tests_fuzzer()) fail {
  let (script_hash, inputs, script_outputs, redeemer) = test_values
  let tx = Transaction { ..placeholder, inputs: inputs, outputs: [] }
  withdraw(fn(_i, _o) { True }, redeemer, Script(script_hash), tx)
}
