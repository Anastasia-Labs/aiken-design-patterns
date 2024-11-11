use aiken_design_patterns/multi_utxo_indexer_one_to_many as multi_utxo_indexer
use aiken_design_patterns/stake_validator as stake_validator
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
      own_hash,
      fn(r) {
        expect coerced: Pairs<Int, List<Int>> = r
        when coerced is {
          [] -> False
          _ -> True
        }
      },
      fn(qty) { qty > 0 },
      tx,
    )
  }

  withdraw(
    redeemer: MultiWithdrawExampleRedeemer,
    stake_cred: Credential,
    tx: Transaction,
  ) {
    let MultiWithdrawExampleRedeemer { indices, input_count } = redeemer
    multi_utxo_indexer.withdraw_no_redeemer(
      fn(_in_index, _in_utxo, _out_index, _out_utxo) { True },
      fn(_in_index, _in_utxo, _out_utxo) { True },
      fn(_inputs, _outputs) { True },
      indices,
      input_count,
      stake_cred,
      tx,
    )
  }

  else(_) {
    fail
  }
}
