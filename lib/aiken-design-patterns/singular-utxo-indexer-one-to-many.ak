use aiken/list
use aiken/transaction.{Input, Output, ScriptContext, Spend, Transaction}

pub fn spend(
  validation_logic: fn(Output, List<Output>) -> Bool,
  redeemer: (Int, List<Int>),
  ctx: ScriptContext,
) -> Bool {
  expect ScriptContext { transaction: tx, purpose: Spend(own_ref) } = ctx

  let Transaction { inputs, outputs, .. } = tx

  let (in_ix, out_ixs) = redeemer

  expect Some(Input { output: in_utxo, output_reference: in_ref }) =
    inputs |> list.at(in_ix)

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
          (curr_ix, acc |> list.push(out_utxo))
        } else {
          // Output indices must be ordered.
          fail
        }
      },
    )

  let (_, out_utxos) = fold_res

  // Indicated input must match the spending one.
  expect (own_ref == in_ref)?

  validation_logic(in_utxo, out_utxos)
}
