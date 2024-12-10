//// @hidden

use aiken_design_patterns/multi_utxo_indexer_one_to_many as multi_utxo_indexer
use aiken_design_patterns/stake_validator
use aiken_design_patterns/utils as utils
use cardano/address.{Address, Credential, Script}
use cardano/transaction.{Output, OutputReference, Transaction}

pub type MultiWithdrawExampleRedeemer {
  indices: Pairs<Int, List<Int>>,
  input_count: Int,
}

validator example {
  spend(_datum, _redeemer, own_ref: OutputReference, tx: Transaction) {
    expect Output {
      address: Address { payment_credential: Script(own_hash), .. },
      ..
    } = utils.resolve_output_reference(tx.inputs, own_ref)
    stake_validator.spend(
      withdraw_script_hash: own_hash,
      withdraw_redeemer_validator: fn(r, qty) {
        expect coerced: Pairs<Int, List<Int>> = r
        when coerced is {
          [] -> False
          _ -> qty > 0
        }
      },
      tx: tx,
    )
  }

  withdraw(
    redeemer: MultiWithdrawExampleRedeemer,
    stake_cred: Credential,
    tx: Transaction,
  ) {
    let MultiWithdrawExampleRedeemer { indices, input_count } = redeemer
    multi_utxo_indexer.withdraw_no_redeemer(
      input_output_validator: fn(_input_index, _input, _output_index, _output) {
        True
      },
      input_collective_outputs_validator: fn(_input_index, _input, _output) {
        True
      },
      collective_inputs_outputs_validator: fn(_inputs, _outputs) { True },
      outer_indices: indices,
      total_input_count: input_count,
      stake_cred: stake_cred,
      tx: tx,
    )
  }

  else(_) {
    fail
  }
}
