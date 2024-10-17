use aiken/collection/list
use aiken_design_patterns/stake_validator as stake_validator
use aiken_design_patterns/utils as utils
use cardano/address.{Address, Credential, Script}
use cardano/transaction.{Input, Output, Transaction}

/// Helper function to compelement your staking script. Note that this function
/// expects to see an equal number of inputs coming from addresses which their
/// payment parts are equal to its own (`stake_cred`).
pub fn withdraw(
  validation_logic: fn(Output, Output) -> Bool,
  redeemer: List<Pair<Int, Int>>,
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

test success_spend(
  spend_script_hash_and_inputs via utils.inputs_with_an_authentic_script_input_fuzzer(
    None,
  ),
) {
  let (spend_script_hash, _script_input, inputs) = spend_script_hash_and_inputs
  let tx =
    Transaction {
      ..placeholder,
      inputs: inputs,
      withdrawals: [Pair(Script(spend_script_hash), 0)],
    }
  spend(spend_script_hash, tx)
}
