//// @hidden

use aiken/collection/list
use aiken_design_patterns/parameter_validation/advanced
use cardano/address.{Address, Script}
use cardano/assets.{PolicyId}
use cardano/transaction.{Output, OutputReference, Transaction}
use env

pub type SampleDatum {
  SampleDatum { label: ByteArray, count: Int }
}

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

validator parameterized_spend_int(parameter: Int) {
  spend(
    _datum: Option<Data>,
    redeemer: Int,
    _own_out_ref: OutputReference,
    _tx: Transaction,
  ) {
    parameter == redeemer
  }

  else(_) {
    fail
  }
}

validator parameterized_spend_list(parameter: List<Int>) {
  spend(
    _datum: Option<Data>,
    redeemer: List<Int>,
    _own_out_ref: OutputReference,
    _tx: Transaction,
  ) {
    parameter == redeemer
  }

  else(_) {
    fail
  }
}

validator parameterized_spend_pairs(parameter: Pairs<ByteArray, Int>) {
  spend(
    _datum: Option<Data>,
    redeemer: Pairs<ByteArray, Int>,
    _own_out_ref: OutputReference,
    _tx: Transaction,
  ) {
    parameter == redeemer
  }

  else(_) {
    fail
  }
}

validator parameterized_spend_custom(parameter: SampleDatum) {
  spend(
    _datum: Option<Data>,
    redeemer: SampleDatum,
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
    let target_script_hash = advanced.apply_param(
      version: 3,
      flat_prefix_without_parameter_header: env.flat_prefix_without_parameter_header,
      parameter: redeemer,
    )
    expect  
        [
          Output {
            address: Address {
              payment_credential: Script(destination_script_hash),
              ..
            },
            value: produced_value,
            ..
          },
        ]
      = outputs
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

validator dependent_mint_int {
  mint(redeemer: Int, _own_policy: PolicyId, tx: Transaction) {
    let Transaction { mint, outputs, .. } = tx
    let target_script_hash = advanced.apply_param(
      version: 3,
      flat_prefix_without_parameter_header: env.int_flat_prefix_without_parameter_header,
      parameter: redeemer,
    )
    expect  
        [
          Output {
            address: Address {
              payment_credential: Script(destination_script_hash),
              ..
            },
            value: produced_value,
            ..
          },
        ]
      = outputs
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

validator dependent_mint_list {
  mint(redeemer: List<Int>, _own_policy: PolicyId, tx: Transaction) {
    let Transaction { mint, outputs, .. } = tx
    let target_script_hash = advanced.apply_param(
      version: 3,
      flat_prefix_without_parameter_header: env.list_flat_prefix_without_parameter_header,
      parameter: redeemer,
    )
    expect  
        [
          Output {
            address: Address {
              payment_credential: Script(destination_script_hash),
              ..
            },
            value: produced_value,
            ..
          },
        ]
      = outputs
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

validator dependent_mint_pairs {
  mint(redeemer: Pairs<ByteArray, Int>, _own_policy: PolicyId, tx: Transaction) {
    let Transaction { mint, outputs, .. } = tx
    let target_script_hash = advanced.apply_param(
      version: 3,
      flat_prefix_without_parameter_header: env.pairs_flat_prefix_without_parameter_header,
      parameter: redeemer,
    )
    expect  
        [
          Output {
            address: Address {
              payment_credential: Script(destination_script_hash),
              ..
            },
            value: produced_value,
            ..
          },
        ]
      = outputs
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

validator dependent_mint_custom {
  mint(redeemer: SampleDatum, _own_policy: PolicyId, tx: Transaction) {
    let Transaction { mint, outputs, .. } = tx
    let target_script_hash = advanced.apply_param(
      version: 3,
      flat_prefix_without_parameter_header: env.custom_flat_prefix_without_parameter_header,
      parameter: redeemer,
    )
    expect  
        [
          Output {
            address: Address {
              payment_credential: Script(destination_script_hash),
              ..
            },
            value: produced_value,
            ..
          },
        ]
      = outputs
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
