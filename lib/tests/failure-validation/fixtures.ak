//// @hidden

use aiken/builtin
use aiken_design_patterns/failure_validation.{FailedTransactionWitness}
use aiken_design_patterns/transaction_serialization.{
  MapEncoding, RedeemerEncoding,
}
use cardano/address
use cardano/assets
use cardano/transaction.{Input, NoDatum, Output, OutputReference, Transaction}
use config
use tests/failure_validation/bodies

pub const script_hash = builtin.replicate_byte(28, 2)

pub const policy_id = builtin.replicate_byte(28, 9)

// RFC 8032, section 7.1, test 1: a signature of the empty message.
pub const public_key =
  #"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"

pub const signature =
  #"e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"

pub const successful_arguments =
  builtin.list_data(
    [builtin.b_data(public_key), builtin.b_data(#""), builtin.b_data(signature)],
  )

// Changing the message preserves argument shapes and makes verification False.
pub const builtin_arguments =
  builtin.list_data(
    [
      builtin.b_data(public_key),
      builtin.b_data(#"01"),
      builtin.b_data(signature),
    ],
  )

pub const bad_signature_arguments =
  builtin.list_data(
    [
      builtin.b_data(public_key),
      builtin.b_data(#""),
      builtin.b_data(builtin.replicate_byte(64, 0)),
    ],
  )

pub const malformed_key_arguments =
  builtin.list_data(
    [builtin.b_data(#""), builtin.b_data(#""), builtin.b_data(signature)],
  )

pub const malformed_signature_arguments =
  builtin.list_data(
    [builtin.b_data(public_key), builtin.b_data(#""), builtin.b_data(#"")],
  )

pub const non_list_arguments = builtin.i_data(42)

pub const missing_argument =
  builtin.list_data([builtin.b_data(public_key), builtin.b_data(#"")])

pub const extra_argument =
  builtin.list_data(
    [
      builtin.b_data(public_key),
      builtin.b_data(#""),
      builtin.b_data(signature),
      builtin.i_data(0),
    ],
  )

pub const wrong_key_type =
  builtin.list_data(
    [builtin.i_data(0), builtin.b_data(#""), builtin.b_data(signature)],
  )

pub const wrong_message_type =
  builtin.list_data(
    [builtin.b_data(public_key), builtin.i_data(0), builtin.b_data(signature)],
  )

pub const wrong_signature_type =
  builtin.list_data(
    [builtin.b_data(public_key), builtin.b_data(#""), builtin.i_data(0)],
  )

pub const long_message_arguments =
  builtin.list_data(
    [
      builtin.b_data(public_key),
      builtin.b_data(builtin.replicate_byte(256, 171)),
      builtin.b_data(signature),
    ],
  )

pub const raw_map_arguments =
  builtin.map_data(
    [
      Pair(builtin.i_data(2), builtin.i_data(20)),
      Pair(builtin.i_data(1), builtin.i_data(10)),
      Pair(builtin.i_data(2), builtin.i_data(21)),
    ],
  )

pub const ordinary_output =
  Output {
    address: address.from_verification_key(builtin.replicate_byte(28, 4)),
    value: assets.from_lovelace(21_000_000),
    datum: NoDatum,
    reference_script: None,
  }

pub const collateral_return =
  Output { ..ordinary_output, value: assets.from_lovelace(98_500_000) }

pub const ordinary_input =
  OutputReference {
    transaction_id: builtin.replicate_byte(32, 16),
    output_index: 0,
  }

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
}

pub fn from_body(
  body: ByteArray,
  redeemer_encoding: RedeemerEncoding,
  builtin_arguments: Data,
) -> ProofFixture {
  let transaction_id = builtin.blake2b_256(body)
  ProofFixture {
    transaction: Transaction {
      ..transaction.placeholder,
      inputs: [
        Input {
          output_reference: OutputReference { transaction_id, output_index: 0 },
          output: collateral_return,
        },
      ],
      mint: assets.from_asset(policy_id, transaction_id, 1),
    },
    witness: FailedTransactionWitness {
      fee: 1_000_000,
      ordinary_inputs: [ordinary_input],
      builtin_arguments,
      collateral_input: OutputReference {
        transaction_id: builtin.replicate_byte(32, 144),
        output_index: 0,
      },
      total_collateral: 1_500_000,
      reference_inputs: [],
      redeemer_encoding,
      cost_model: bodies.cost_model,
    },
    collateral_return_input_index: 0,
  }
}

// All callers construct fixtures in constants so test budgets cover validation.
pub const base =
  from_body(bodies.withdrawal_map, MapEncoding, builtin_arguments)

// Change the evidence and NFT hash together to exercise authentication checks.
pub fn with_body(proof: ProofFixture, body: ByteArray) -> ProofFixture {
  let ProofFixture { transaction, .. } = proof
  let Transaction { inputs, .. } = transaction
  expect [input] = inputs
  let Input { output_reference, .. } = input
  let transaction_id = builtin.blake2b_256(body)
  ProofFixture {
    ..proof,
    transaction: Transaction {
      ..transaction,
      inputs: [
        Input {
          ..input,
          output_reference: OutputReference {
            ..output_reference,
            transaction_id,
          },
        },
      ],
      mint: assets.from_asset(policy_id, transaction_id, 1),
    },
  }
}

pub fn with_arguments(
  proof: ProofFixture,
  body: ByteArray,
  builtin_arguments: Data,
) -> ProofFixture {
  let ProofFixture { witness, .. } = proof
  with_body(
    ProofFixture {
      ..proof,
      witness: FailedTransactionWitness { ..witness, builtin_arguments },
    },
    body,
  )
}

pub fn argument_proof(
  builtin_arguments: Data,
  testnet_body: ByteArray,
  mainnet_body: ByteArray,
) -> ProofFixture {
  from_body(
    if config.network_tag == 0 {
      testnet_body
    } else {
      mainnet_body
    },
    MapEncoding,
    builtin_arguments,
  )
}
