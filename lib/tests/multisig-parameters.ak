//// Exercise datum callbacks independently of the governance integer schema.

use aiken/builtin
use aiken_design_patterns/multisig_parameters
use cardano/address
use cardano/assets
use cardano/transaction.{
  InlineDatum, Input, Mint, NoDatum, Output, OutputReference, Spend, Transaction,
}

type ExampleParameters {
  enabled: Bool,
  label: ByteArray,
}

const initial_parameters =
  ExampleParameters { enabled: False, label: "initial" }

const updated_parameters = ExampleParameters { enabled: True, label: "updated" }

const own_policy = builtin.replicate_byte(28, 16)

const asset_name = "EXAMPLE_PARAMETERS"

const signer_a = builtin.replicate_byte(28, 1)

const signer_b = builtin.replicate_byte(28, 2)

const authorized_signers = [signer_a, signer_b]

const bootstrap_nonce =
  OutputReference {
    transaction_id: builtin.replicate_byte(32, 16),
    output_index: 0,
  }

const own_outref =
  OutputReference {
    transaction_id: builtin.replicate_byte(32, 32),
    output_index: 0,
  }

const funding_output =
  Output {
    address: address.from_verification_key(signer_a),
    value: assets.from_lovelace(10_000_000),
    datum: NoDatum,
    reference_script: None,
  }

const initial_output =
  Output {
    address: address.from_script(own_policy),
    value: assets.from_lovelace(5_000_000)
      |> assets.add(own_policy, asset_name, 1),
    datum: InlineDatum(initial_parameters),
    reference_script: None,
  }

const updated_output =
  Output {
    ..initial_output,
    value: assets.from_lovelace(4_000_000)
      |> assets.add(own_policy, asset_name, 1),
    datum: InlineDatum(updated_parameters),
  }

const change_output =
  Output { ..funding_output, value: assets.from_lovelace(4_000_000) }

// Constants keep balanced fixture construction outside validation budgets.
const bootstrap_tx =
  Transaction {
    ..transaction.placeholder,
    inputs: [
      Input { output_reference: bootstrap_nonce, output: funding_output },
    ],
    outputs: [initial_output, change_output],
    fee: 1_000_000,
    mint: assets.from_asset(own_policy, asset_name, 1),
    extra_signatories: authorized_signers,
    redeemers: [Pair(Mint(own_policy), builtin.i_data(0))],
  }

const update_tx =
  Transaction {
    ..transaction.placeholder,
    inputs: [Input { output_reference: own_outref, output: initial_output }],
    outputs: [updated_output],
    fee: 1_000_000,
    extra_signatories: authorized_signers,
    redeemers: [Pair(Spend(own_outref), builtin.i_data(0))],
  }

fn mint(tx: Transaction, validate_datum: fn(Data) -> Bool) -> Bool {
  let datum <- multisig_parameters.validate_mint(
    bootstrap_nonce,
    authorized_signers,
    2,
    asset_name,
    0,
    own_policy,
    tx,
  )
  validate_datum(datum)
}

fn spend(tx: Transaction, validate_datum: fn(Data) -> Bool) -> Bool {
  let datum <- multisig_parameters.validate_spend(
    authorized_signers,
    2,
    asset_name,
    0,
    own_outref,
    tx,
  )
  validate_datum(datum)
}

test mint__accepts_record_datum_and_custom_asset_name() {
  let datum <- mint(bootstrap_tx)
  expect parameters: ExampleParameters = datum
  parameters == initial_parameters
}

test spend__validates_continuing_record_datum() {
  let datum <- spend(update_tx)
  expect parameters: ExampleParameters = datum
  parameters == updated_parameters
}

const wrong_schema_bootstrap_tx =
  Transaction {
    ..bootstrap_tx,
    outputs: [
      Output { ..initial_output, datum: InlineDatum(builtin.i_data(42)) },
      change_output,
    ],
  }

const wrong_schema_update_tx =
  Transaction {
    ..update_tx,
    outputs: [
      Output { ..updated_output, datum: InlineDatum(builtin.i_data(42)) },
    ],
  }

test mint__callback_rejects_wrong_datum_schema() fail {
  let datum <- mint(wrong_schema_bootstrap_tx)
  expect _: ExampleParameters = datum
  True
}

test spend__callback_rejects_wrong_datum_schema() fail {
  let datum <- spend(wrong_schema_update_tx)
  expect _: ExampleParameters = datum
  True
}

// Even callbacks that accept every datum cannot bypass NFT authentication.
const missing_nft_bootstrap_tx =
  Transaction {
    ..bootstrap_tx,
    outputs: [
      Output { ..initial_output, value: assets.from_lovelace(5_000_000) },
      Output {
        ..change_output,
        value: assets.from_lovelace(4_000_000)
          |> assets.add(own_policy, asset_name, 1),
      },
    ],
  }

const missing_nft_update_tx =
  Transaction {
    ..update_tx,
    outputs: [
      Output { ..updated_output, value: assets.from_lovelace(2_000_000) },
      Output {
        ..funding_output,
        value: assets.from_lovelace(2_000_000)
          |> assets.add(own_policy, asset_name, 1),
      },
    ],
  }

test mint__rejects_missing_nft_with_permissive_callback() fail {
  let _datum <- mint(missing_nft_bootstrap_tx)
  True
}

test spend__rejects_missing_nft_with_permissive_callback() fail {
  let _datum <- spend(missing_nft_update_tx)
  True
}

test mint__propagates_callback_false() {
  let accepted = {
    let _datum <- mint(bootstrap_tx)
    False
  }
  !accepted
}

test spend__propagates_callback_false() {
  let accepted = {
    let _datum <- spend(update_tx)
    False
  }
  !accepted
}

test mint__propagates_callback_failure() fail {
  let _datum <- mint(bootstrap_tx)
  fail
}

test spend__propagates_callback_failure() fail {
  let _datum <- spend(update_tx)
  fail
}
