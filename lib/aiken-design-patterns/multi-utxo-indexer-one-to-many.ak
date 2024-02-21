use aiken/list
use aiken/transaction.{Input, Output, ScriptContext, Transaction}
use aiken_design_patterns/stake_validator as stake_validator

pub fn withdraw(
  validation_logic: fn(Output, List<Output>) -> Bool,
  redeemer: List<(Int, List<Int>)>,
  ctx: ScriptContext,
) -> Bool {
  stake_validator.withdraw(
    fn(indicesData, _own_validator, tx) {
      let Transaction { inputs, outputs, .. } = tx
      expect indices: List<(Int, List<Int>)> = indicesData
      // Folding the outer list of indices from left.
      let (_, _) =
        list.foldl(
          indices,
          (-1, -1),
          fn(curr, prev_ixs) {
            let (prev_in_ix, latest_out_ix) = prev_ixs
            let (curr_in_ix, out_ixs) = curr
            if curr_in_ix > prev_in_ix {
              // Folding the inner list of output indices from left. Since
              // found UTxOs are going to be added to the head of the
              // accumulator while the folding occurs from left, in order to
              // provide a more intuitive interface, the UTxOs list need to be
              // reversed before `validation_logic` applies to it.
              let (new_latest_out_ix, out_utxos_reversed) =
                list.foldl(
                  out_ixs,
                  (latest_out_ix, []),
                  fn(curr_out_ix, acc_tuple) {
                    let (prev_out_ix, utxos_so_far) = acc_tuple
                    if curr_out_ix > prev_out_ix {
                      expect Some(out_utxo) = outputs |> list.at(curr_out_ix)
                      (curr_out_ix, utxos_so_far |> list.push(out_utxo))
                    } else {
                      // Output indices must be ordered.
                      fail
                    }
                  },
                )
              let out_utxos = list.reverse(out_utxos_reversed)
              expect Some(Input { output: in_utxo, .. }) =
                inputs |> list.at(curr_in_ix)
              if validation_logic(in_utxo, out_utxos) {
                // Passing the current input index, and the biggest output
                // index found with the inner fold.
                (curr_in_ix, new_latest_out_ix)
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
    },
    redeemer,
    ctx,
  )
}
