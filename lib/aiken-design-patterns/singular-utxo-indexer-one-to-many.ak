use aiken/list
use aiken/transaction.{Input, Output, ScriptContext, Spend, Transaction}

pub fn spend(
  input_validator: fn(Input) -> Bool,
  input_output_validator: fn(Output, Output) -> Bool,
  collective_output_validator: fn(List<Output>) -> Bool,
  redeemer: (Int, List<Int>),
  ctx: ScriptContext,
) -> Bool {
  expect ScriptContext { transaction: tx, purpose: Spend(own_ref) } = ctx

  let Transaction { inputs, outputs, .. } = tx

  let (in_ix, out_ixs) = redeemer

  expect Some(Input { output: in_utxo, output_reference: in_ref } as input) =
    inputs |> list.at(in_ix)

  expect input_validator(input)?

  let fold_res =
    list.foldr(
      out_ixs,
      (list.length(outputs), []),
      fn(curr_ix, acc_tuple) {
        let (prev_ix, acc) = acc_tuple
        // Folding from right and expecting ascending order from head to tail
        // (for a more intuitive API) to disallow duplicates.
        if curr_ix < prev_ix {
          expect Some(out_utxo) = outputs |> list.at(curr_ix)
          expect input_output_validator(in_utxo, out_utxo)?
          (curr_ix, acc |> list.push(out_utxo))
        } else {
          fail @"Output indices must be in ascending order"
        }
      },
    )

  let (_, out_utxos) = fold_res

  // Indicated input must match the spending one.
  expect (own_ref == in_ref)?

  collective_output_validator(out_utxos)
}
