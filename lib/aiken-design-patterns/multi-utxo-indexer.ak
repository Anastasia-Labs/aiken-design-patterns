use aiken/collection/list
use aiken/crypto.{ScriptHash}
use aiken_design_patterns/stake_validator
use aiken_scott_utils/list as list_extra
use cardano/address.{Address, Credential, Script}
use cardano/transaction.{
  Input, Output, OutputReference, Redeemer, ScriptPurpose, Spend, Transaction,
}

// ## One-to-One

/// Helper function for performing spending validation on multiple inputs from
/// the same script, each with a corresponding output. It expects both the input
/// and output indices be in ascending order.
///
/// The validation function you should provide has access to:
/// - Index of the `Input` being validated
/// - The `Input` itself
/// - Index of the `Output` being validated
/// - The `Output` itself
pub fn one_to_one_no_redeemer(
  indices: Pairs<Int, Int>,
  script_hash: ScriptHash,
  inputs: List<Input>,
  outputs: List<Output>,
  validation_logic: fn(Int, Input, Int, Output) -> Bool,
) -> Bool {
  let script_spending_credential = Script(script_hash)
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
        if input.output.address.payment_credential == script_spending_credential {
          when remaining_indices is {
            [] -> fail @"More UTxOs of the script are spent than specified"
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
      },
    )
  expect processed_indices == []
  True
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
pub fn one_to_one_with_redeemer(
  indices: Pairs<Int, Int>,
  stake_cred: Credential,
  inputs: List<Input>,
  outputs: List<Output>,
  redeemers: Pairs<ScriptPurpose, Redeemer>,
  spend_redeemer_coercer_and_stake_credential_extractor: fn(Data) ->
    (a, Credential),
  validation_logic: fn(Int, Input, a, Int, Output) -> Bool,
) -> Bool {
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

// ## One-to-Many

/// Use this function inside your withdrawal script to validate all the inputs
/// coming from **the script's spend endpoint**. This is an important detail, as
/// the validator needs to guarantee an exact number of inputs are spent.
///
/// If you want to work with an external staking script, consider
/// using [`withdraw_with_redeemer`](#withdraw_with_redeemer).
///
/// The arguments are:
/// 1. Validation function on each input, and each of its corresponding outputs
/// 2. Validation function on each input, against all its outputs
/// 3. Validation function on all the inputs and all the outputs
/// 4. `Pairs` of indices, mapping each input to multiple outputs
/// 5. **Total** number of **inputs**
/// 6. Staking credential of the wrapping validator (provided by `withdraw`).
///    **Note** that in this variant, it can only validate spending the UTxOs
///    from its own spending endpoint
/// 7. `Transaction` provided by the validator
///
/// For validation functions, corresponding indices of inputs/outputs are also
/// provided in these functions.
pub fn withdraw_no_redeemer(
  input_output_validator: fn(Int, Input, Int, Output) -> Bool,
  input_collective_outputs_validator: fn(Int, Input, List<Output>) -> Bool,
  collective_inputs_outputs_validator: fn(List<Input>, List<Output>) -> Bool,
  outer_indices: Pairs<Int, List<Int>>,
  total_input_count: Int,
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
        all_inputs,
        all_outputs,
        remaining_script_inputs_count,
      <-
        list_extra.foldr6(
          inputs,
          list.reverse(indices),
          total_input_count,
          511,
          [],
          [],
          total_input_count - 1,
          fn(
            input,
            remaining_indices,
            in0,
            out0,
            all_inputs_so_far,
            all_outputs_so_far,
            i,
            return,
          ) {
            let next_i = i - 1
            when input.output.address.payment_credential is {
              Script(script) ->
                if script == own_validator {
                  when remaining_indices is {
                    [] -> fail @"More UTxOs are spent than specified"
                    [Pair(in1, outs), ..rest_of_indices] ->
                      if i == in1 && in1 < in0 {
                        let
                          new_latest_out_ix,
                          collected_outputs,
                          all_outputs_so_far_updated,
                        <-
                          list_extra.foldr3(
                            outs,
                            out0,
                            [],
                            all_outputs_so_far,
                            fn(
                              curr_out_ix,
                              prev_out_ix,
                              outputs_so_far,
                              outer_all_outputs,
                              inner_return,
                            ) {
                              if curr_out_ix < prev_out_ix {
                                expect Some(out_utxo) =
                                  outputs |> list.at(curr_out_ix)
                                if input_output_validator(
                                  in1,
                                  input,
                                  curr_out_ix,
                                  out_utxo,
                                ) {
                                  inner_return(
                                    curr_out_ix,
                                    list.push(outputs_so_far, out_utxo),
                                    list.push(outer_all_outputs, out_utxo),
                                  )
                                } else {
                                  fail @"Validation on an input with one of its corresponding outputs failed"
                                }
                              } else {
                                fail @"All output indices must be in ascending order"
                              }
                            },
                          )
                        if input_collective_outputs_validator(
                          in1,
                          input,
                          collected_outputs,
                        ) {
                          return(
                            rest_of_indices,
                            in1,
                            new_latest_out_ix,
                            list.push(all_inputs_so_far, input),
                            all_outputs_so_far_updated,
                            next_i,
                          )
                        } else {
                          fail @"Validation on the output count failed"
                        }
                      } else {
                        fail @"Input and output indices must be in ascending orders"
                      }
                  }
                } else {
                  return(
                    remaining_indices,
                    in0,
                    out0,
                    all_inputs_so_far,
                    all_outputs_so_far,
                    next_i,
                  )
                }
              _ ->
                return(
                  remaining_indices,
                  in0,
                  out0,
                  all_inputs_so_far,
                  all_outputs_so_far,
                  next_i,
                )
            }
          },
        )
      and {
        collective_inputs_outputs_validator(all_inputs, all_outputs),
        list.is_empty(processed_indices),
        remaining_script_inputs_count == -1,
      }
    },
    outer_indices,
    stake_cred,
    tx,
  )
}
