//// @hidden

use aiken/collection/list
use aiken_design_patterns/parameter_validation/advanced
use cardano/address.{Address, Script}
use cardano/assets.{PolicyId}
use cardano/transaction.{Output, OutputReference, Transaction}
use env

validator parameterized_spend(parameter: ByteArray) {
  spend(
    _datum: Option<Data>,
    redeemer: ByteArray,
    _own_out_ref: OutputReference,
    _tx: Transaction,
  ) {
    parameter == redeemer
  }

  else(_) {
    fail
  }
}

validator dependent_mint {
  mint(redeemer: ByteArray, _own_policy: PolicyId, tx: Transaction) {
    let Transaction { mint, outputs, .. } = tx
    let target_script_hash =
      advanced.apply_param(
        version: 3,
        flat_prefix_without_parameter_header: env.flat_prefix_without_parameter_header,
        parameter: redeemer,
      )
    expect [
      Output {
        address: Address {
          payment_credential: Script(destination_script_hash),
          ..
        },
        value: produced_value,
        ..
      },
    ] = outputs
    and {
      assets.without_lovelace(produced_value) == mint,
      destination_script_hash == target_script_hash,
      list.length(assets.flatten(mint)) == 1,
    }
  }

  else(_) {
    fail
  }
}
