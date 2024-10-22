use aiken/list
use aiken/transaction.{Input, Output, ScriptContext, Transaction}
use aiken/transaction/credential.{Address, ScriptCredential}
use aiken_design_patterns/stake_validator as stake_validator

pub fn withdraw(
  input_validator: fn(Input) -> Bool,
  input_output_validator: fn(Output, Output) -> Bool,
  collective_output_validator: fn(List<Output>, Int) -> Bool,
  redeemer: List<(Int, List<Int>)>,
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
            when i.output.address.payment_credential is {
              ScriptCredential(script) ->
                if script == own_validator {
                  let (acc, count) = acc_tuple
                  ([i, ..acc], count + 1)
                } else {
                  acc_tuple
                }
              _ -> acc_tuple
            }
          },
        )
      expect indices: List<(Int, List<Int>)> = indicesData
      // Folding the outer list of indices from left.
      let (_, _, input_index_count) =
        list.foldl(
          indices,
          (-1, -1, 0),
          fn(curr, prev_ixs_and_count) {
            let (prev_in_ix, latest_out_ix, input_count_so_far) =
              prev_ixs_and_count

            let (curr_in_ix, out_ixs) = curr

            expect Some(Input { output: in_utxo, .. } as input) =
              script_inputs |> list.at(curr_in_ix)

            expect input_validator(input)?

            if curr_in_ix > prev_in_ix {
              // Folding the inner list of output indices from left. Since
              // found UTxOs are going to be added to the head of the
              // accumulator while the folding occurs from left, in order to
              // provide a more intuitive interface, the UTxOs list need to be
              // reversed before `validation_logic` is applied to it.
              let (new_latest_out_ix, out_utxos_reversed, output_count) =
                list.foldl(
                  out_ixs,
                  (latest_out_ix, [], 0),
                  fn(curr_out_ix, acc_triplet) {
                    let (prev_out_ix, utxos_so_far, count) = acc_triplet
                    if curr_out_ix > prev_out_ix {
                      expect Some(out_utxo) = outputs |> list.at(curr_out_ix)
                      expect input_output_validator(in_utxo, out_utxo)?
                      (
                        curr_out_ix,
                        utxos_so_far |> list.push(out_utxo),
                        count + 1,
                      )
                    } else {
                      fail @"All output indices must be in ascending order"
                    }
                  },
                )
              let out_utxos = list.reverse(out_utxos_reversed)
              if collective_output_validator(out_utxos, output_count) {
                // Passing the current input index, and the biggest output
                // index found with the inner fold.
                (curr_in_ix, new_latest_out_ix, input_count_so_far + 1)
              } else {
                fail @"Collection of outputs are not valid"
              }
            } else {
              fail @"Input indices must be in ascending order"
            }
          },
        )
      (script_input_count == input_index_count)?
    },
    redeemer,
    ctx,
  )
}
