use aiken/list
use aiken/transaction.{Input, Output, ScriptContext, Transaction}
use aiken/transaction/credential.{Address, ScriptCredential}
use aiken_design_patterns/stake_validator as stake_validator

pub fn withdraw(
  validation_logic: fn(Output, Output) -> Bool,
  redeemer: List<(Int, Int)>,
  ctx: ScriptContext,
) -> Bool {
  stake_validator.withdraw(
    fn(indicesData, own_validator, tx) {
      let Transaction { inputs, outputs, .. } = tx
      let (script_inputs, script_input_count) =
        list.foldr(
          inputs,
          ([], 0),
          fn(i, acc_tuple) {
            let Input { output, .. } = i
            when output.address.payment_credential is {
              ScriptCredential(script) ->
                if script == own_validator {
                  let (acc, count) = acc_tuple
                  ([output, ..acc], count + 1)
                } else {
                  acc_tuple
                }
              _ -> acc_tuple
            }
          },
        )

      expect indices: List<(Int, Int)> = indicesData
      let (_, _, input_index_count) =
        list.foldl(
          indices,
          (-1, -1, 0),
          fn(curr, acc) {
            let (in0, out0, count) = acc
            let (in1, out1) = curr
            if in1 > in0 && out1 > out0 {
              expect Some(in_utxo) = script_inputs |> list.at(in1)
              expect Some(out_utxo) = outputs |> list.at(out1)
              if validation_logic(in_utxo, out_utxo) {
                (in1, out1, count + 1)
              } else {
                fail @"Validation failed"
              }
            } else {
              // Input and output indices must be ordered to disallow
              // duplicates.
              fail @"Input and output indices must be in ascending orders"
            }
          },
        )
      (script_input_count == input_index_count)?
    },
    redeemer,
    ctx,
  )
}
