//// @hidden

use aiken/builtin
use aiken/cbor
use aiken/collection/list
use aiken/crypto.{ScriptHash}
use aiken_design_patterns/parameter_validation/advanced
use cardano/address.{Address, Script}
use cardano/assets.{PolicyId}
use cardano/transaction.{NoDatum, Output, OutputReference, Transaction}
use env

pub type SampleDatum {
  SampleDatum { label: ByteArray, count: Int }
}

validator parameterized_spend_bytearray(parameter: ByteArray) {
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

validator dependent_mint_bytearray {
  mint(redeemer: ByteArray, _own_policy: PolicyId, tx: Transaction) {
    let Transaction { mint, outputs, .. } = tx
    let target_script_hash = advanced.apply_param(
      version: 3,
      flat_prefix_without_parameter_header: env.bytearray_flat_prefix_without_parameter_header,
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

fn deserialise_parameter(bytes: ByteArray) -> Data {
  expect Some(parameter) = cbor.deserialise(bytes)
  parameter
}

const bytearray_parameter: ByteArray = {
    expect parameter: ByteArray = deserialise_parameter(
      env.bytearray_parameter_cbor,
    )
    parameter
  }

const int_parameter: Int = {
    expect parameter: Int = deserialise_parameter(env.int_parameter_cbor)
    parameter
  }

const list_parameter: List<Int> = {
    expect parameter: List<Int> = deserialise_parameter(env.list_parameter_cbor)
    parameter
  }

const pairs_parameter: Pairs<ByteArray, Int> = {
    expect parameter: Pairs<ByteArray, Int> = deserialise_parameter(
      env.pairs_parameter_cbor,
    )
    parameter
  }

const custom_parameter: SampleDatum = {
    expect parameter: SampleDatum = deserialise_parameter(
      env.custom_parameter_cbor,
    )
    parameter
  }

const test_policy_id = builtin.replicate_byte(28, 1)

const test_asset_name = #"00"

const test_mint = assets.from_asset(test_policy_id, test_asset_name, 1)

const test_output_value =
  assets.from_lovelace(2_000_000)
    |> assets.add(test_policy_id, test_asset_name, 1)

fn mint_transaction(destination_script_hash: ScriptHash) -> Transaction {
  Transaction {
    ..transaction.placeholder,
    mint: test_mint,
    outputs: [
      Output {
        address: Address {
          payment_credential: Script(destination_script_hash),
          stake_credential: None,
        },
        value: test_output_value,
        datum: NoDatum,
        reference_script: None,
      },
    ],
  }
}

const bytearray_transaction = mint_transaction(env.bytearray_script_hash)

const int_transaction = mint_transaction(env.int_script_hash)

const list_transaction = mint_transaction(env.list_script_hash)

const pairs_transaction = mint_transaction(env.pairs_script_hash)

const custom_transaction = mint_transaction(env.custom_script_hash)

const wrong_transaction = mint_transaction(builtin.replicate_byte(28, 0))

const flat_chunk_255_parameter =
  list.repeat(
    env.list_flat_chunk_element,
    env.list_flat_chunk_255_element_count,
  )

const flat_chunk_256_parameter =
  list.repeat(
    env.list_flat_chunk_element,
    env.list_flat_chunk_256_element_count,
  )

const flat_chunk_510_parameter =
  list.repeat(
    env.list_flat_chunk_element,
    env.list_flat_chunk_510_element_count,
  )

const flat_chunk_511_parameter =
  list.repeat(
    env.list_flat_chunk_element,
    env.list_flat_chunk_511_element_count,
  )

test success__dependent_mint_bytearray() {
  dependent_mint_bytearray.mint(
    bytearray_parameter,
    test_policy_id,
    bytearray_transaction,
  )
}

test success__dependent_mint_int() {
  dependent_mint_int.mint(int_parameter, test_policy_id, int_transaction)
}

test success__dependent_mint_list() {
  dependent_mint_list.mint(list_parameter, test_policy_id, list_transaction)
}

test success__dependent_mint_pairs() {
  dependent_mint_pairs.mint(pairs_parameter, test_policy_id, pairs_transaction)
}

test success__dependent_mint_custom() {
  dependent_mint_custom.mint(
    custom_parameter,
    test_policy_id,
    custom_transaction,
  )
}

test fail__dependent_mint_bytearray__wrong_destination() fail {
  dependent_mint_bytearray.mint(
    bytearray_parameter,
    test_policy_id,
    wrong_transaction,
  )
}

test fail__dependent_mint_int__wrong_destination() fail {
  dependent_mint_int.mint(int_parameter, test_policy_id, wrong_transaction)
}

test fail__dependent_mint_list__wrong_destination() fail {
  dependent_mint_list.mint(list_parameter, test_policy_id, wrong_transaction)
}

test fail__dependent_mint_pairs__wrong_destination() fail {
  dependent_mint_pairs.mint(pairs_parameter, test_policy_id, wrong_transaction)
}

test fail__dependent_mint_custom__wrong_destination() fail {
  dependent_mint_custom.mint(
    custom_parameter,
    test_policy_id,
    wrong_transaction,
  )
}

test success__apply_param__empty_bytearray() {
  advanced.apply_param(
    version: 3,
    flat_prefix_without_parameter_header: env.bytearray_flat_prefix_without_parameter_header,
    parameter: #"",
  ) == env.bytearray_empty_script_hash
}

test success__apply_param__negative_int() {
  advanced.apply_param(
    version: 3,
    flat_prefix_without_parameter_header: env.int_flat_prefix_without_parameter_header,
    parameter: -1,
  ) == env.int_negative_one_script_hash
}

test success__apply_param__flat_chunk_boundaries() {
  and {
    advanced.apply_param(
      version: 3,
      flat_prefix_without_parameter_header: env.list_flat_prefix_without_parameter_header,
      parameter: flat_chunk_255_parameter,
    ) == env.list_flat_chunk_255_script_hash,
    advanced.apply_param(
      version: 3,
      flat_prefix_without_parameter_header: env.list_flat_prefix_without_parameter_header,
      parameter: flat_chunk_256_parameter,
    ) == env.list_flat_chunk_256_script_hash,
  }
}

test success__apply_param__repeated_flat_chunk_boundaries() {
  and {
    advanced.apply_param(
      version: 3,
      flat_prefix_without_parameter_header: env.list_flat_prefix_without_parameter_header,
      parameter: flat_chunk_510_parameter,
    ) == env.list_flat_chunk_510_script_hash,
    advanced.apply_param(
      version: 3,
      flat_prefix_without_parameter_header: env.list_flat_prefix_without_parameter_header,
      parameter: flat_chunk_511_parameter,
    ) == env.list_flat_chunk_511_script_hash,
  }
}
