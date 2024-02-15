use aiken/list
use aiken/transaction.{Input, Output, ScriptContext, Transaction}
use aiken_design_patterns/stake_validator as stake_validator

pub fn withdraw(
  validation_logic: fn(Output, Output) -> Bool,
  redeemer: List<(Int, Int)>,
  ctx: ScriptContext,
) -> Bool {
  stake_validator.withdraw(
    fn(indicesData, _own_validator, tx) {
      let Transaction { inputs, outputs, .. } = tx
      expect indices: List<(Int, Int)> = indicesData
      when indices is {
        [head, ..tail] -> {
          let (_, _) =
            list.foldl(
              tail,
              head,
              fn(curr, prev) {
                let (in0, out0) = prev
                let (in1, out1) = curr
                if in1 > in0 && out1 > out0 {
                  expect Some(Input { output: in_utxo, .. }) =
                    inputs |> list.at(in1)
                  expect Some(out_utxo) = outputs |> list.at(out1)
                  if validation_logic(in_utxo, out_utxo) {
                    curr
                  } else {
                    fail
                  }
                } else {
                  // Input and output indices must be ordered to disallow duplicates.
                  fail
                }
              },
            )
          True
        }
        _ -> fail
      }
    },
    redeemer,
    ctx,
  )
}
