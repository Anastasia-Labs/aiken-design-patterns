use aiken_design_patterns/multi_utxo_indexer_one_to_many as multi_utxo_indexer
use aiken_design_patterns/stake_validator as stake_validator
use aiken_design_patterns/utils as utils
use cardano/address.{Address, Credential, Script}
use cardano/transaction.{Input, NoDatum, Output, OutputReference, Transaction}

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
    redeemer: Pairs<Int, List<Int>>,
    stake_cred: Credential,
    tx: Transaction,
  ) {
    multi_utxo_indexer.withdraw(
      fn(_input) { True },
      fn(_in_utxo, _out_utxo) { True },
      fn(_output_value, _output_count) { True },
      redeemer,
      stake_cred,
      tx,
    )
  }

  else(_) {
    fail
  }
}
