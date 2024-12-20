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

/// A variant of [`withdraw_no_redeemer`](#withdraw_no_redeemer). The difference
/// here is that it gives access to the spend redeemers to your validation
/// functions.
///
/// Note that your spend redeemers are expected to carry the `Credential` to the
/// resulting staking script (which is the purpose of the first argument).
///
/// The arguments are:
/// 1. Validation function on each input, and each of its corresponding outputs
/// 2. Validation function on each input, against all its outputs
/// 3. Validation function on all the inputs and all the outputs
/// 4. `Pairs` of indices, mapping each input to multiple outputs
/// 5. **Total** number of **script inputs**
/// 6. Staking credential of the wrapping validator (provided by `withdraw`)
/// 7. `Transaction` provided by the validator
///
/// For validation functions, corresponding indices of inputs/outputs are also
/// provided in these functions.
///
/// Under the hood, one other difference is that here, instead of traversing all
/// the inputs, there are two traversals: one over the `redeemers`, and another
/// over the indices.
pub fn withdraw_with_redeemer(
  spend_redeemer_coercer_and_stake_credential_extractor: fn(Redeemer) ->
    (a, Credential),
  input_output_validator: fn(Int, Input, a, Int, Output) -> Bool,
  input_collective_outputs_validator: fn(Int, Input, a, List<Output>) -> Bool,
  collective_inputs_outputs_validator: fn(List<Input>, List<Output>) -> Bool,
  indices: Pairs<Int, List<Int>>,
  total_script_inputs: Int,
  stake_cred: Credential,
  tx: Transaction,
) -> Bool {
  let Transaction { inputs, outputs, redeemers, .. } = tx
  // Folding from left so that redeemers are ordered in reverse. This allows
  // for cheaper collection of UTxOs in the next fold.
  let script_redeemers =
    list.foldl(
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
    all_inputs,
    all_outputs,
    remaining_script_inputs_count,
  <-
    list_extra.foldr6(
      indices,
      script_redeemers,
      511,
      511,
      [],
      [],
      total_script_inputs - 1,
      fn(
        curr_input_outputs_indices,
        remaining_redeemers,
        in0,
        out0,
        all_inputs_so_far,
        all_outputs_so_far,
        i,
        return,
      ) {
        let next_i = i - 1
        let Pair(in1, outs) = curr_input_outputs_indices
        if in1 < in0 {
          expect Some(in_utxo) = inputs |> list.at(in1)
          when remaining_redeemers is {
            [] -> fail @"More UTxOs are spent than there are redeemers"
            [current_redeemer, ..rest_of_redeemers] -> {
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
                      expect Some(out_utxo) = outputs |> list.at(curr_out_ix)
                      if input_output_validator(
                        in1,
                        in_utxo,
                        current_redeemer,
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
                in_utxo,
                current_redeemer,
                collected_outputs,
              ) {
                return(
                  rest_of_redeemers,
                  in1,
                  new_latest_out_ix,
                  list.push(all_inputs_so_far, in_utxo),
                  all_outputs_so_far_updated,
                  next_i,
                )
              } else {
                fail @"Validation on the output count failed"
              }
            }
          }
        } else {
          fail @"All input indices must be in ascending order"
        }
      },
    )
  and {
    collective_inputs_outputs_validator(all_inputs, all_outputs),
    list.is_empty(processed_redeemers),
    remaining_script_inputs_count == -1,
  }
}

fn tests_fuzzer() -> Fuzzer<
  (
    ScriptHash,
    List<Input>,
    List<Output>,
    Pairs<Int, List<Int>>,
    Int,
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
            (
              i_indices |> list.push(i),
              outputs
                |> list.push(input.output)
                |> list.push(input.output)
                |> list.push(input.output)
                |> list.push(input.output)
                |> list.push(input.output),
            )
          _ -> acc
        }
      },
    )
  let redeemer =
    script_input_indices
      |> list.indexed_foldr(
          [],
          fn(i, script_input_index, acc) {
            list.push(
              acc,
              Pair(script_input_index, list.range(i * 5, i * 5 + 4)),
            )
          },
        )
  fuzz.constant(
    (
      script_hash,
      inputs,
      script_outputs,
      redeemer,
      list.length(script_inputs),
      list.map(
        script_inputs,
        fn(i) { Pair(Spend(i.output_reference), builtin.i_data(0)) },
      ),
    ),
  )
}

test success_withdraw_no_redeemer(test_values via tests_fuzzer()) {
  let (
    script_hash,
    inputs,
    script_outputs,
    indices,
    _script_input_count,
    _redeemers,
  ) = test_values
  let tx =
    Transaction { ..placeholder, inputs: inputs, outputs: script_outputs }
  withdraw_no_redeemer(
    fn(_ii, _i, _oi, _o) { True },
    fn(_ii, _i, _os) { True },
    fn(_is, _os) { True },
    indices,
    list.length(inputs),
    Script(script_hash),
    tx,
  )
}

test fail_withdraw_no_redeemer(test_values via tests_fuzzer()) fail {
  let (
    script_hash,
    inputs,
    _script_outputs,
    indices,
    script_input_count,
    _redeemers,
  ) = test_values
  let tx = Transaction { ..placeholder, inputs: inputs, outputs: [] }
  withdraw_no_redeemer(
    fn(_ii, _i, _oi, _o) { True },
    fn(_ii, _i, _os) { True },
    fn(_is, _os) { True },
    indices,
    script_input_count,
    Script(script_hash),
    tx,
  )
}

test success_withdraw_with_redeemer(test_values via tests_fuzzer()) {
  let (
    script_hash,
    inputs,
    script_outputs,
    indices,
    script_input_count,
    redeemers,
  ) = test_values
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
    fn(_ii, _i, _r, _os) { True },
    fn(_is, _os) { True },
    indices,
    script_input_count,
    Script(script_hash),
    tx,
  )
}

test fail_withdraw_with_redeemer(test_values via tests_fuzzer()) fail {
  let (
    script_hash,
    inputs,
    _script_outputs,
    indices,
    script_input_count,
    _redeemers,
  ) = test_values
  let tx =
    Transaction { ..placeholder, inputs: inputs, outputs: [], redeemers: [] }
  withdraw_with_redeemer(
    fn(_d) { (0, Script(script_hash)) },
    fn(_ii, _i, _r, _oi, _o) { True },
    fn(_ii, _i, _r, _os) { True },
    fn(_is, _os) { True },
    indices,
    script_input_count,
    Script(script_hash),
    tx,
  )
}
