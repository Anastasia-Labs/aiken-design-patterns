//// @hidden

use aiken/builtin
use aiken_design_patterns/failure_validation.{FailedTransactionWitness}
use aiken_design_patterns/transaction_serialization.{
  ListEncoding, MapEncoding, RedeemerEncoding,
}
use cardano/address
use cardano/assets
use cardano/transaction.{
  InlineDatum, Input, NoDatum, Output, OutputReference, Transaction,
}
use config
use tests/failure_validation/bodies

pub const script_hash = builtin.replicate_byte(28, 2)

pub const policy_id = builtin.replicate_byte(28, 9)

// RFC 8032 test 1's public key and signature, with an altered message.
// Argument decoding succeeds and the builtin returns False.
pub const builtin_arguments =
  builtin.list_data(
    [
      builtin.b_data(
        #"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
      ),
      builtin.b_data(#"01"),
      builtin.b_data(
        #"e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
      ),
    ],
  )

pub const script_output =
  Output {
    address: address.from_script(script_hash),
    value: assets.from_lovelace(20_000_000),
    datum: InlineDatum(builtin_arguments),
    reference_script: None,
  }

pub const ordinary_output =
  Output {
    address: address.from_verification_key(builtin.replicate_byte(28, 4)),
    value: assets.from_lovelace(21_000_000),
    datum: NoDatum,
    reference_script: None,
  }

pub const collateral_return =
  Output { ..ordinary_output, value: assets.from_lovelace(98_500_000) }

pub const first_script_reference =
  OutputReference {
    transaction_id: builtin.replicate_byte(32, 16),
    output_index: 1,
  }

pub const second_script_reference =
  OutputReference {
    transaction_id: builtin.replicate_byte(32, 128),
    output_index: 1,
  }

pub const first_other_reference =
  OutputReference { ..second_script_reference, output_index: 0 }

pub const second_other_reference =
  OutputReference { ..first_script_reference, output_index: 0 }

pub const failed_reference_inputs =
  [
    OutputReference {
      transaction_id: builtin.replicate_byte(32, 160),
      output_index: 0,
    },
  ]

pub type ProofFixture {
  transaction: Transaction,
  witness: FailedTransactionWitness,
  collateral_return_input_index: Int,
  spending_reference_input_index: Int,
}

pub fn from_body(
  body: ByteArray,
  script_reference: OutputReference,
  other_input: OutputReference,
  redeemer_encoding: RedeemerEncoding,
  reference_inputs: List<OutputReference>,
) -> ProofFixture {
  let transaction_id = builtin.blake2b_256(body)
  ProofFixture {
    transaction: Transaction {
      ..transaction.placeholder,
      inputs: [
        Input {
          output_reference: OutputReference { transaction_id, output_index: 1 },
          output: collateral_return,
        },
      ],
      reference_inputs: [
        Input { output_reference: script_reference, output: script_output },
      ],
      mint: assets.from_asset(policy_id, transaction_id, 1),
    },
    witness: FailedTransactionWitness {
      outputs_cbor: bodies.outputs,
      fee: 1_000_000,
      other_input,
      collateral_input: OutputReference {
        transaction_id: builtin.replicate_byte(32, 144),
        output_index: 0,
      },
      total_collateral: 1_500_000,
      reference_inputs,
      redeemer_encoding,
      cost_model: bodies.cost_model,
    },
    collateral_return_input_index: 0,
    spending_reference_input_index: 0,
  }
}

// Give the collateral-return input and NFT the independently generated body's
// hash. Negative cases must get past the NFT-name check to test reconstruction.
pub fn with_body(proof: ProofFixture, body: ByteArray) -> ProofFixture {
  let ProofFixture { transaction, .. } = proof
  let transaction_id = builtin.blake2b_256(body)
  ProofFixture {
    ..proof,
    transaction: Transaction {
      ..transaction,
      inputs: [
        Input {
          output_reference: OutputReference { transaction_id, output_index: 1 },
          output: collateral_return,
        },
      ],
      mint: assets.from_asset(policy_id, transaction_id, 1),
    },
  }
}

pub fn with_script_output(proof: ProofFixture, output: Output) -> ProofFixture {
  let ProofFixture { transaction, .. } = proof
  let Transaction { reference_inputs, .. } = transaction
  expect [Input { output_reference, .. }] = reference_inputs
  ProofFixture {
    ..proof,
    transaction: Transaction {
      ..transaction,
      reference_inputs: [Input { output_reference, output }],
    },
  }
}

pub fn with_outputs(
  proof: ProofFixture,
  body: ByteArray,
  outputs_cbor: ByteArray,
) -> ProofFixture {
  let ProofFixture { witness, .. } = proof
  with_body(
    ProofFixture {
      ..proof,
      witness: FailedTransactionWitness { ..witness, outputs_cbor },
    },
    body,
  )
}

pub const first =
  from_body(
    bodies.first_map,
    first_script_reference,
    first_other_reference,
    MapEncoding,
    [],
  )

pub const second =
  from_body(
    bodies.second_map,
    second_script_reference,
    second_other_reference,
    MapEncoding,
    [],
  )

pub const first_list =
  from_body(
    bodies.first_list,
    first_script_reference,
    first_other_reference,
    ListEncoding,
    [],
  )

pub const second_list =
  from_body(
    bodies.second_list,
    second_script_reference,
    second_other_reference,
    ListEncoding,
    [],
  )

pub const first_references =
  from_body(
    bodies.first_map_references,
    first_script_reference,
    first_other_reference,
    MapEncoding,
    failed_reference_inputs,
  )

pub const second_references =
  from_body(
    bodies.second_map_references,
    second_script_reference,
    second_other_reference,
    MapEncoding,
    failed_reference_inputs,
  )

pub const first_list_references =
  from_body(
    bodies.first_list_references,
    first_script_reference,
    first_other_reference,
    ListEncoding,
    failed_reference_inputs,
  )

pub const second_list_references =
  from_body(
    bodies.second_list_references,
    second_script_reference,
    second_other_reference,
    ListEncoding,
    failed_reference_inputs,
  )

pub const same_transaction_reference =
  OutputReference {
    transaction_id: builtin.replicate_byte(32, 32),
    output_index: 0,
  }

pub const first_same_transaction =
  from_body(
    bodies.first_same_transaction,
    same_transaction_reference,
    OutputReference { ..same_transaction_reference, output_index: 1 },
    MapEncoding,
    [],
  )

pub const second_same_transaction =
  from_body(
    bodies.second_same_transaction,
    OutputReference { ..same_transaction_reference, output_index: 1 },
    same_transaction_reference,
    MapEncoding,
    [],
  )

pub const first_current_network =
  if config.network_tag == 0 {
    first
  } else {
    with_outputs(first, bodies.first_mainnet, bodies.mainnet_outputs)
  }

pub const second_current_network =
  if config.network_tag == 0 {
    second
  } else {
    with_outputs(second, bodies.second_mainnet, bodies.mainnet_outputs)
  }
