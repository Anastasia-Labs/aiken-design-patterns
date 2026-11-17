//// @hidden

use aiken/builtin
use aiken_design_patterns/failure_validation.{
  BuiltinRedeemer, DirectArguments, FailedTransactionWitness, FailureParameters,
  ReferencedArguments, failure_parameters_asset_name,
}
use aiken_design_patterns/transaction_serialization.{
  MapEncoding, RedeemerEncoding,
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

pub const failure_parameters_policy = builtin.replicate_byte(28, 16)

pub const failure_parameters =
  FailureParameters { max_mem: 17_500_000, max_cpu: 10_000_000_000 }

pub const failure_parameters_input =
  Input {
    output_reference: OutputReference {
      transaction_id: builtin.replicate_byte(32, 48),
      output_index: 0,
    },
    output: Output {
      address: address.from_script(failure_parameters_policy),
      value: assets.from_lovelace(5_000_000)
        |> assets.add(
            failure_parameters_policy,
            failure_parameters_asset_name,
            1,
          ),
      datum: InlineDatum(failure_parameters),
      reference_script: None,
    },
  }

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

// Output indexes compare numerically within one transaction; the transaction
// ID takes precedence when it differs, even when the next output index is zero.
pub const ordered_input_references =
  [
    OutputReference { ..ordinary_input, output_index: 2 },
    OutputReference { ..ordinary_input, output_index: 10 },
    OutputReference {
      transaction_id: builtin.replicate_byte(32, 32),
      output_index: 0,
    },
  ]

pub const descending_input_transaction_ids = {
    expect [first, second, third] = ordered_input_references
    [first, third, second]
  }

pub const descending_input_output_indexes = {
    expect [first, second, third] = ordered_input_references
    [second, first, third]
  }

pub const duplicate_input_references = {
    expect [first, second, _third] = ordered_input_references
    [first, second, second]
  }

pub const argument_reference_outref_0 =
  OutputReference {
    transaction_id: builtin.replicate_byte(32, 176),
    output_index: 0,
  }

pub const argument_reference_outref_1 =
  OutputReference {
    transaction_id: builtin.replicate_byte(32, 192),
    output_index: 1,
  }

pub const argument_reference_outref_2 =
  OutputReference {
    transaction_id: builtin.replicate_byte(32, 208),
    output_index: 2,
  }

pub const argument_reference_outrefs =
  [
    argument_reference_outref_0, argument_reference_outref_1,
    argument_reference_outref_2,
  ]

// These outputs deliberately use unrelated credentials and values. Only their
// inline datum is relevant when a redeemer selects builtin arguments.
pub const argument_reference_inputs =
  [
    Input {
      output_reference: argument_reference_outref_0,
      output: Output {
        address: address.from_verification_key(builtin.replicate_byte(28, 11)),
        value: assets.from_lovelace(3_000_000)
          |> assets.add(builtin.replicate_byte(28, 12), #"01", 2),
        datum: InlineDatum(builtin.b_data(#"")),
        reference_script: None,
      },
    },
    Input {
      output_reference: argument_reference_outref_1,
      output: Output {
        address: address.from_script(builtin.replicate_byte(28, 13)),
        value: assets.from_lovelace(7_000_000)
          |> assets.add(builtin.replicate_byte(28, 14), #"02", 9),
        datum: InlineDatum(builtin.b_data(signature)),
        reference_script: None,
      },
    },
    Input {
      output_reference: argument_reference_outref_2,
      output: Output {
        address: address.from_verification_key(builtin.replicate_byte(28, 15)),
        value: assets.from_lovelace(13_000_000)
          |> assets.add(builtin.replicate_byte(28, 16), #"03", 4),
        datum: InlineDatum(builtin.b_data(public_key)),
        reference_script: None,
      },
    },
  ]

pub const successful_reference_redeemer = ReferencedArguments([2, 0, 1])

// This outref sorts before the three valid argument references. The producing
// transaction encodes it last, so ledger sorting changes the selected arguments.
pub const malformed_argument_reference =
  Input {
    output_reference: OutputReference {
      transaction_id: builtin.replicate_byte(32, 128),
      output_index: 0,
    },
    output: Output { ..ordinary_output, datum: InlineDatum(builtin.i_data(42)) },
  }

pub const reference_order_attack_outrefs =
  [
    argument_reference_outref_0,
    argument_reference_outref_1,
    argument_reference_outref_2,
    malformed_argument_reference.output_reference,
  ]

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
      builtin_redeemer: DirectArguments(builtin_arguments),
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

pub fn with_input_lists(
  proof: ProofFixture,
  body: ByteArray,
  ordinary_inputs: List<OutputReference>,
  reference_inputs: List<OutputReference>,
) -> ProofFixture {
  let ProofFixture { witness, .. } = proof
  with_body(
    ProofFixture {
      ..proof,
      witness: FailedTransactionWitness {
        ..witness,
        ordinary_inputs,
        reference_inputs,
      },
    },
    body,
  )
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
      witness: FailedTransactionWitness {
        ..witness,
        builtin_redeemer: DirectArguments(builtin_arguments),
      },
    },
    body,
  )
}

pub fn with_reference_arguments(
  proof: ProofFixture,
  body: ByteArray,
) -> ProofFixture {
  with_reference_redeemer(proof, body, successful_reference_redeemer)
}

pub fn with_reference_redeemer(
  proof: ProofFixture,
  body: ByteArray,
  builtin_redeemer: BuiltinRedeemer,
) -> ProofFixture {
  let ProofFixture { transaction, witness, .. } = proof
  with_body(
    ProofFixture {
      ..proof,
      transaction: Transaction {
        ..transaction,
        reference_inputs: argument_reference_inputs,
      },
      witness: FailedTransactionWitness {
        ..witness,
        builtin_redeemer,
        reference_inputs: argument_reference_outrefs,
      },
    },
    body,
  )
}

pub fn reference_argument_proof(
  testnet_body: ByteArray,
  mainnet_body: ByteArray,
) -> ProofFixture {
  with_reference_arguments(
    from_body(
      if config.network_tag == 0 {
        testnet_body
      } else {
        mainnet_body
      },
      MapEncoding,
      successful_arguments,
    ),
    if config.network_tag == 0 {
      testnet_body
    } else {
      mainnet_body
    },
  )
}

pub const reference_order_attack = {
    let body = if config.network_tag == 0 {
      bodies.reference_order_attack
    } else {
      bodies.reference_order_attack_mainnet
    }
    with_input_lists(
      with_reference_arguments(base, body),
      body,
      [ordinary_input],
      reference_order_attack_outrefs,
    )
  }

pub fn reference_redeemer_proof(
  builtin_redeemer: BuiltinRedeemer,
  testnet_body: ByteArray,
  mainnet_body: ByteArray,
) -> ProofFixture {
  let body = if config.network_tag == 0 {
    testnet_body
  } else {
    mainnet_body
  }
  with_reference_redeemer(
    from_body(body, MapEncoding, successful_arguments),
    body,
    builtin_redeemer,
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
