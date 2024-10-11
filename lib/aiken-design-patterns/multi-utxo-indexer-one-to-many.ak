use aiken/collection/list
use aiken_design_patterns/stake_validator as stake_validator
use aiken_design_patterns/utils as utils
use cardano/address.{Address, Credential, Script}
use cardano/transaction.{Input, Output, Transaction}

/// Use this function inside your withdrawal script to validate all the inputs
/// coming from the script's spend endpoint. This is an important detail, as the
/// validator needs to guarantee an exact number of inputs are spent.
pub fn withdraw(
  input_validator: fn(Input) -> Bool,
  input_output_validator: fn(Output, Output) -> Bool,
  output_count_validator: fn(Int) -> Bool,
  redeemer: List<(Int, List<Int>)>,
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
                    [Pair(in1, outs), ..rest_of_indices] -> {
                      if i == in1 && in1 > in0 {
                        expect input_validator(input)?
                        let
                          new_latest_out_ix,
                          output_count,
                        <-
                          utils.foldl2(
                            outs,
                            out0,
                            0,
                            fn(curr_out_ix, prev_out_ix, count, inner_return) {
                              if curr_out_ix > prev_out_ix {
                                expect Some(out_utxo) =
                                  outputs |> list.at(curr_out_ix)
                                if input_output_validator(in_utxo, out_utxo) {
                                  inner_return(curr_out_ix, count + 1)
                                } else {
                                  fail @"Validation on an input with one of its corresponding outputs failed"
                                }
                              } else {
                                fail @"All output indices must be in ascending order"
                              }
                            },
                          )
                        if output_count_validator(output_count) {
                          return(rest_of_indices, in1, new_latest_out_ix, next_i)
                        } else {
                          fail @"Validation on the output count failed"
                        }
                      } else {
                        fail @"Input and output indices must be in ascending orders"
                      }
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
