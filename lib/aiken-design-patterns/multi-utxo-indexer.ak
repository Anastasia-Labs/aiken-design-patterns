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
/// a given script, each with a corresponding output. It expects both the input
/// and output indices be in ascending order.
///
/// The validation function you should provide has access to:
/// - Index of the `Input` being validated
/// - The `Input` itself
/// - Index of the `Output` being validated
/// - The `Output` itself
pub fn one_to_one_no_redeemer(
  indices: Pairs<Int, Int>,
  spending_script_hash: ScriptHash,
  inputs: List<Input>,
  outputs: List<Output>,
  validation_logic: fn(Int, Input, Int, Output) -> Bool,
) -> Bool {
  let script_spending_credential = Script(spending_script_hash)
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

/// Another variant with a staking script (i.e. withdraw-0 script) as a coupling
/// element for spending multiple UTxOs from a given spending script.
///
/// Here the `redeemers` is also traversed to provide the validation logic with
/// the redeemer used for spending each of the UTxOs.
/// 
/// Assumption here is that redeemers carry the staking credential of the
/// withdraw-0 validator, which is the purpose of the additional argument, i.e.
/// coercing the redeemer `Data` into an expected structure, and extracting the
/// staking credential.
pub fn one_to_one_with_redeemer(
  indices: Pairs<Int, Int>,
  spending_script_hash: ScriptHash,
  stake_script_hash: ScriptHash,
  inputs: List<Input>,
  outputs: List<Output>,
  redeemers: Pairs<ScriptPurpose, Redeemer>,
  spend_redeemer_coercer_and_stake_credential_extractor: fn(Data) ->
    (a, Credential),
  validation_logic: fn(Int, Input, a, Int, Output) -> Bool,
) -> Bool {
  let spending_credential = Script(spending_script_hash)
  let stake_credential = Script(stake_script_hash)
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
              expect in_utxo.output.address.payment_credential == spending_credential
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
  expect processed_redeemers == []
  True
}
