//// @hidden

use aiken/builtin
use aiken/collection/list
use aiken/crypto.{ScriptHash}
use aiken_design_patterns/failure_validation.{FailedTransactionWitness}
use cardano/address.{Address, Credential, Script, VerificationKey}
use cardano/assets.{PolicyId}
use cardano/certificate.{
  Certificate, DelegateBlockProduction, DelegateCredential,
  RegisterAndDelegateCredential, RegisterCredential, UnregisterCredential,
}
use cardano/transaction.{
  Datum, DatumHash, InlineDatum, Input, Mint, NoDatum, Output, OutputReference,
  Redeemer, Spend, Transaction, Withdraw,
}
use config
use env
use tests/failure_validation/fixtures.{ProofFixture}

const spending_mem = 50_000

const spending_cpu = 14_000_000

const max_mem = 17_500_000

const max_cpu = 10_000_000_000

pub type ProofMintRedeemer {
  collateral_return_input_index: Int,
  spending_reference_input_index: Int,
  witness: FailedTransactionWitness,
}

/// Both endpoints share one script hash. The withdrawal executes the
/// environment-selected builtin on arguments committed in the input's inline
/// datum, so spending requires that exact invocation to succeed.
validator builtin_probe {
  spend(
    _m_datum: Option<Data>,
    own_input_is_first: Bool,
    own_out_ref: OutputReference,
    tx: Transaction,
  ) {
    let Transaction { inputs, withdrawals, .. } = tx
    expect [first_input, second_input] = inputs
    // True selects input 0; False selects input 1.
    expect  
        Input {
          output_reference,
          output: Output {
            address: Address { payment_credential: Script(own_script_hash), .. },
            ..
          },
        }
      = if own_input_is_first {
      first_input
    } else {
      second_input
    }
    expect output_reference == own_out_ref

    // The ledger requires execution of the script named in the withdrawal map.
    // The paired withdrawal endpoint checks the complete redeemer collection.
    expect [Pair(Script(withdrawal_hash), _)] = withdrawals
    withdrawal_hash == own_script_hash
  }

  withdraw(_redeemer: Void, own_credential: Credential, tx: Transaction) {
    let Transaction { inputs, redeemers, .. } = tx
    // The ledger binds the sole withdrawal redeemer to this handler.
    expect [Pair(Spend(_), spending_redeemer), Pair(Withdraw(_), _)] = redeemers

    expect own_input_is_first: Bool = spending_redeemer
    expect [first_input, second_input] = inputs
    let  
        Input {
          output: Output {
            address: Address { payment_credential, .. },
            datum,
            ..
          },
          ..
        }
      = if own_input_is_first {
      first_input
    } else {
      second_input
    }
    // This Plutus credential requires a spending redeemer for the selected
    // input; the ledger binds it to the sole Spend entry above.
    expect payment_credential == own_credential

    expect InlineDatum(arguments) = datum
    env.apply_builtin(arguments)
  }

  publish(_redeemer: Redeemer, certificate: Certificate, _tx: Transaction) {
    // Permit registration without enabling delegation.
    expect RegisterCredential { .. } = certificate
    True
  }

  else(_) {
    fail
  }
}

/// The policy parameter commits to the shared spend/withdraw script. Its
/// environment must select the same builtin and argument preparation rules.
validator failure_proof(spend_withdraw_script_hash: ScriptHash) {
  mint(redeemer: ProofMintRedeemer, policy_id: PolicyId, tx: Transaction) {
    let Transaction { inputs, reference_inputs, mint, .. } = tx
    let  
        ProofMintRedeemer {
          collateral_return_input_index,
          spending_reference_input_index,
          witness,
        }
      = redeemer
    let builtin_arguments <- failure_validation.validate_mint(
      own_policy: policy_id,
      spend_withdraw_script_hash: spend_withdraw_script_hash,
      spending_cpu: spending_cpu,
      spending_mem: spending_mem,
      withdrawal_cpu: max_cpu - spending_cpu,
      withdrawal_mem: max_mem - spending_mem,
      network_tag: config.network_tag,
      inputs: inputs,
      collateral_return_input_index: collateral_return_input_index,
      reference_inputs: reference_inputs,
      spending_reference_input_index: spending_reference_input_index,
      mint: mint,
      witness: witness,
    )
    env.validate_builtin_arguments(builtin_arguments)
  }

  else(_) {
    fail
  }
}

const test_own_script_hash = builtin.replicate_byte(28, 2)

const test_other_script_hash = builtin.replicate_byte(28, 3)

// RFC 8032, section 7.1, test 1: an Ed25519 signature of the empty message.
const test_public_key =
  #"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"

const test_signature =
  #"e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"

const test_arguments =
  builtin.list_data(
    [
      builtin.b_data(test_public_key),
      builtin.b_data(#""),
      builtin.b_data(test_signature),
    ],
  )

const test_altered_message =
  builtin.list_data(
    [
      builtin.b_data(test_public_key),
      builtin.b_data(#"01"),
      builtin.b_data(test_signature),
    ],
  )

const test_altered_signature =
  builtin.list_data(
    [
      builtin.b_data(test_public_key),
      builtin.b_data(#""),
      builtin.b_data(builtin.replicate_byte(64, 0)),
    ],
  )

const test_first_reference =
  OutputReference {
    transaction_id: builtin.replicate_byte(32, 0),
    output_index: 0,
  }

const test_second_reference =
  OutputReference { ..test_first_reference, output_index: 1 }

const test_own_input =
  Input {
    output_reference: test_first_reference,
    output: Output {
      address: address.from_script(test_own_script_hash),
      value: assets.from_lovelace(20_000_000),
      datum: InlineDatum(test_arguments),
      reference_script: None,
    },
  }

const test_wallet_input =
  Input {
    output_reference: test_second_reference,
    output: Output {
      address: address.from_verification_key(builtin.replicate_byte(28, 4)),
      value: assets.from_lovelace(2_000_000),
      datum: NoDatum,
      reference_script: None,
    },
  }

const test_ignored_redeemer = builtin.constr_data(0, [])

const test_first_input_redeemer = builtin.constr_data(1, [])

const test_second_input_redeemer = builtin.constr_data(0, [])

fn test_transaction(own_input_is_first: Bool, datum: Datum) -> Transaction {
  let own_reference = if own_input_is_first {
    test_first_reference
  } else {
    test_second_reference
  }
  let own_input = Input {
    output_reference: own_reference,
    output: Output { ..test_own_input.output, datum },
  }
  let inputs = if own_input_is_first {
    [own_input, test_wallet_input]
  } else {
    [
      Input { ..test_wallet_input, output_reference: test_first_reference },
      own_input,
    ]
  }
  let spending_redeemer = if own_input_is_first {
    test_first_input_redeemer
  } else {
    test_second_input_redeemer
  }
  Transaction {
    ..transaction.placeholder,
    inputs,
    withdrawals: [Pair(Script(test_own_script_hash), 0)],
    redeemers: [
      Pair(Spend(own_reference), spending_redeemer),
      Pair(Withdraw(Script(test_own_script_hash)), test_ignored_redeemer),
    ],
  }
}

const test_input0 = test_transaction(True, InlineDatum(test_arguments))

const test_input1 = test_transaction(False, InlineDatum(test_arguments))

const test_bad_message =
  test_transaction(True, InlineDatum(test_altered_message))

const test_bad_signature =
  test_transaction(True, InlineDatum(test_altered_signature))

const test_non_list_datum =
  test_transaction(True, InlineDatum(builtin.i_data(42)))

const test_no_datum = test_transaction(True, NoDatum)

const test_hashed_datum =
  test_transaction(
    True,
    DatumHash(builtin.blake2b_256(builtin.serialise_data(test_arguments))),
  )

const test_too_few_arguments =
  test_transaction(
    True,
    InlineDatum(
      builtin.list_data([builtin.b_data(test_public_key), builtin.b_data(#"")]),
    ),
  )

const test_too_many_arguments =
  test_transaction(
    True,
    InlineDatum(
      builtin.list_data(
        [
          builtin.b_data(test_public_key),
          builtin.b_data(#""),
          builtin.b_data(test_signature),
          builtin.i_data(0),
        ],
      ),
    ),
  )

const test_wrong_key_type =
  test_transaction(
    True,
    InlineDatum(
      builtin.list_data(
        [builtin.i_data(0), builtin.b_data(#""), builtin.b_data(test_signature)],
      ),
    ),
  )

const test_wrong_message_type =
  test_transaction(
    True,
    InlineDatum(
      builtin.list_data(
        [
          builtin.b_data(test_public_key),
          builtin.i_data(0),
          builtin.b_data(test_signature),
        ],
      ),
    ),
  )

const test_wrong_signature_type =
  test_transaction(
    True,
    InlineDatum(
      builtin.list_data(
        [
          builtin.b_data(test_public_key),
          builtin.b_data(#""),
          builtin.i_data(0),
        ],
      ),
    ),
  )

const test_malformed_key =
  test_transaction(
    True,
    InlineDatum(
      builtin.list_data(
        [
          builtin.b_data(#""),
          builtin.b_data(#""),
          builtin.b_data(test_signature),
        ],
      ),
    ),
  )

const test_redeemer_substitution =
  Transaction {
    ..test_bad_message,
    redeemers: [
      Pair(Spend(test_first_reference), test_first_input_redeemer),
      Pair(Withdraw(Script(test_own_script_hash)), test_arguments),
    ],
  }

const test_other_input_substitution =
  Transaction {
    ..test_input1,
    inputs: [
      Input {
        output_reference: test_first_reference,
        output: Output {
          ..test_wallet_input.output,
          datum: InlineDatum(test_arguments),
        },
      },
      Input {
        output_reference: test_second_reference,
        output: Output {
          ..test_own_input.output,
          datum: InlineDatum(test_altered_message),
        },
      },
    ],
  }

const test_one_input = Transaction { ..test_input0, inputs: [test_own_input] }

const test_three_inputs =
  Transaction {
    ..test_input0,
    inputs: [
      test_own_input,
      test_wallet_input,
      Input {
        ..test_wallet_input,
        output_reference: OutputReference {
          ..test_first_reference,
          output_index: 2,
        },
      },
    ],
  }

const test_two_own_inputs =
  Transaction {
    ..test_input0,
    inputs: [
      test_own_input,
      Input { ..test_own_input, output_reference: test_second_reference },
    ],
  }

const test_key_input =
  Transaction {
    ..test_input0,
    inputs: [
      Input { ..test_wallet_input, output_reference: test_first_reference },
      test_wallet_input,
    ],
  }

const test_other_script_input =
  Transaction {
    ..test_input0,
    inputs: [
      Input {
        ..test_own_input,
        output: Output {
          ..test_own_input.output,
          address: address.from_script(test_other_script_hash),
        },
      },
      test_wallet_input,
    ],
  }

const test_missing_withdrawal =
  Transaction {
    ..test_input0,
    withdrawals: [],
    redeemers: [Pair(Spend(test_first_reference), test_first_input_redeemer)],
  }

const test_wrong_withdrawal =
  Transaction {
    ..test_input0,
    withdrawals: [Pair(Script(test_other_script_hash), 0)],
    redeemers: [
      Pair(Spend(test_first_reference), test_first_input_redeemer),
      Pair(Withdraw(Script(test_other_script_hash)), test_ignored_redeemer),
    ],
  }

const test_extra_withdrawal =
  Transaction {
    ..test_input0,
    withdrawals: [
      Pair(Script(test_own_script_hash), 0),
      Pair(Script(test_other_script_hash), 0),
    ],
    redeemers: [
      Pair(Spend(test_first_reference), test_first_input_redeemer),
      Pair(Withdraw(Script(test_own_script_hash)), test_ignored_redeemer),
      Pair(Withdraw(Script(test_other_script_hash)), test_ignored_redeemer),
    ],
  }

const test_key_withdrawal =
  Transaction {
    ..test_input0,
    withdrawals: [Pair(VerificationKey(test_own_script_hash), 0)],
    redeemers: [
      Pair(Spend(test_first_reference), test_first_input_redeemer),
      Pair(
        Withdraw(VerificationKey(test_own_script_hash)),
        test_ignored_redeemer,
      ),
    ],
  }

const test_no_redeemers = Transaction { ..test_input0, redeemers: [] }

const test_unrelated_redeemers =
  Transaction {
    ..test_input0,
    redeemers: [Pair(Mint(test_other_script_hash), builtin.i_data(42))],
  }

const test_malformed_spending_redeemer =
  Transaction {
    ..test_input0,
    redeemers: [
      Pair(Spend(test_first_reference), builtin.i_data(1)),
      Pair(Withdraw(Script(test_own_script_hash)), test_ignored_redeemer),
    ],
  }

const test_wrong_spending_flag =
  Transaction {
    ..test_input0,
    redeemers: [
      Pair(Spend(test_first_reference), test_second_input_redeemer),
      Pair(Withdraw(Script(test_own_script_hash)), test_ignored_redeemer),
    ],
  }

const test_missing_spending_redeemer =
  Transaction {
    ..test_input0,
    redeemers: [
      Pair(Withdraw(Script(test_own_script_hash)), test_ignored_redeemer),
    ],
  }

const test_wrong_spending_purpose =
  Transaction {
    ..test_input0,
    redeemers: [
      Pair(Mint(test_other_script_hash), test_first_input_redeemer),
      Pair(Withdraw(Script(test_own_script_hash)), test_ignored_redeemer),
    ],
  }

const test_extra_redeemer =
  Transaction {
    ..test_input0,
    redeemers: [
      Pair(Spend(test_first_reference), test_first_input_redeemer),
      Pair(Mint(test_other_script_hash), test_ignored_redeemer),
      Pair(Withdraw(Script(test_own_script_hash)), test_ignored_redeemer),
    ],
  }

const test_two_spending_redeemers =
  Transaction {
    ..test_two_own_inputs,
    redeemers: [
      Pair(Spend(test_first_reference), test_first_input_redeemer),
      Pair(Spend(test_second_reference), test_second_input_redeemer),
      Pair(Withdraw(Script(test_own_script_hash)), test_ignored_redeemer),
    ],
  }

test spend__input0() {
  builtin_probe.spend(
    Some(test_arguments),
    True,
    test_first_reference,
    test_input0,
  )
}

test spend__input1() {
  builtin_probe.spend(
    Some(test_arguments),
    False,
    test_second_reference,
    test_input1,
  )
}

test spend__ignores_empty_redeemer_collection() {
  builtin_probe.spend(
    Some(test_arguments),
    True,
    test_first_reference,
    test_no_redeemers,
  )
}

test spend__ignores_unrelated_redeemer_collection() {
  builtin_probe.spend(
    Some(test_arguments),
    True,
    test_first_reference,
    test_unrelated_redeemers,
  )
}

test spend__ignores_invalid_builtin_arguments() {
  builtin_probe.spend(
    Some(test_altered_message),
    True,
    test_first_reference,
    test_bad_message,
  )
}

test spend__ignores_non_list_datum() {
  builtin_probe.spend(
    Some(builtin.i_data(42)),
    True,
    test_first_reference,
    test_non_list_datum,
  )
}

test spend__rejects_wrong_flag_at_input0() fail {
  builtin_probe.spend(
    Some(test_arguments),
    False,
    test_first_reference,
    test_input0,
  )
}

test spend__rejects_wrong_flag_at_input1() fail {
  builtin_probe.spend(
    Some(test_arguments),
    True,
    test_second_reference,
    test_input1,
  )
}

test spend__rejects_other_input_at_same_script() fail {
  builtin_probe.spend(
    Some(test_arguments),
    False,
    test_first_reference,
    test_two_own_inputs,
  )
}

test spend__rejects_one_input() fail {
  builtin_probe.spend(
    Some(test_arguments),
    True,
    test_first_reference,
    test_one_input,
  )
}

test spend__rejects_three_inputs() fail {
  builtin_probe.spend(
    Some(test_arguments),
    True,
    test_first_reference,
    test_three_inputs,
  )
}

test spend__rejects_key_input() fail {
  builtin_probe.spend(
    Some(test_arguments),
    True,
    test_first_reference,
    test_key_input,
  )
}

test spend__rejects_missing_withdrawal() fail {
  builtin_probe.spend(
    Some(test_arguments),
    True,
    test_first_reference,
    test_missing_withdrawal,
  )
}

test spend__rejects_wrong_withdrawal() fail {
  builtin_probe.spend(
    Some(test_arguments),
    True,
    test_first_reference,
    test_wrong_withdrawal,
  )
}

test spend__rejects_extra_withdrawal() fail {
  builtin_probe.spend(
    Some(test_arguments),
    True,
    test_first_reference,
    test_extra_withdrawal,
  )
}

test spend__rejects_key_withdrawal() fail {
  builtin_probe.spend(
    Some(test_arguments),
    True,
    test_first_reference,
    test_key_withdrawal,
  )
}

test withdraw__input0() {
  builtin_probe.withdraw(Void, Script(test_own_script_hash), test_input0)
}

test withdraw__input1() {
  builtin_probe.withdraw(Void, Script(test_own_script_hash), test_input1)
}

test withdraw__rejects_bad_message() fail {
  builtin_probe.withdraw(Void, Script(test_own_script_hash), test_bad_message)
}

test withdraw__rejects_bad_signature() fail {
  builtin_probe.withdraw(Void, Script(test_own_script_hash), test_bad_signature)
}

test withdraw__rejects_non_list_datum() fail {
  builtin_probe.withdraw(
    Void,
    Script(test_own_script_hash),
    test_non_list_datum,
  )
}

test withdraw__rejects_no_datum() fail {
  builtin_probe.withdraw(Void, Script(test_own_script_hash), test_no_datum)
}

test withdraw__rejects_hashed_datum() fail {
  builtin_probe.withdraw(Void, Script(test_own_script_hash), test_hashed_datum)
}

test withdraw__rejects_too_few_arguments() fail {
  builtin_probe.withdraw(
    Void,
    Script(test_own_script_hash),
    test_too_few_arguments,
  )
}

test withdraw__rejects_too_many_arguments() fail {
  builtin_probe.withdraw(
    Void,
    Script(test_own_script_hash),
    test_too_many_arguments,
  )
}

test withdraw__rejects_wrong_key_type() fail {
  builtin_probe.withdraw(
    Void,
    Script(test_own_script_hash),
    test_wrong_key_type,
  )
}

test withdraw__rejects_wrong_message_type() fail {
  builtin_probe.withdraw(
    Void,
    Script(test_own_script_hash),
    test_wrong_message_type,
  )
}

test withdraw__rejects_wrong_signature_type() fail {
  builtin_probe.withdraw(
    Void,
    Script(test_own_script_hash),
    test_wrong_signature_type,
  )
}

test withdraw__rejects_malformed_key() fail {
  builtin_probe.withdraw(Void, Script(test_own_script_hash), test_malformed_key)
}

test withdraw__rejects_redeemer_substitution() fail {
  builtin_probe.withdraw(
    Void,
    Script(test_own_script_hash),
    test_redeemer_substitution,
  )
}

test withdraw__rejects_other_input_substitution() fail {
  builtin_probe.withdraw(
    Void,
    Script(test_own_script_hash),
    test_other_input_substitution,
  )
}

test withdraw__rejects_malformed_spending_redeemer() fail {
  builtin_probe.withdraw(
    Void,
    Script(test_own_script_hash),
    test_malformed_spending_redeemer,
  )
}

test withdraw__rejects_wrong_spending_flag() fail {
  builtin_probe.withdraw(
    Void,
    Script(test_own_script_hash),
    test_wrong_spending_flag,
  )
}

test withdraw__rejects_one_input() fail {
  builtin_probe.withdraw(Void, Script(test_own_script_hash), test_one_input)
}

test withdraw__rejects_three_inputs() fail {
  builtin_probe.withdraw(Void, Script(test_own_script_hash), test_three_inputs)
}

test withdraw__rejects_key_input() fail {
  builtin_probe.withdraw(Void, Script(test_own_script_hash), test_key_input)
}

test withdraw__rejects_other_script_input() fail {
  builtin_probe.withdraw(
    Void,
    Script(test_own_script_hash),
    test_other_script_input,
  )
}

test withdraw__rejects_missing_spending_redeemer() fail {
  builtin_probe.withdraw(
    Void,
    Script(test_own_script_hash),
    test_missing_spending_redeemer,
  )
}

test withdraw__rejects_wrong_spending_purpose() fail {
  builtin_probe.withdraw(
    Void,
    Script(test_own_script_hash),
    test_wrong_spending_purpose,
  )
}

test withdraw__rejects_extra_redeemer() fail {
  builtin_probe.withdraw(
    Void,
    Script(test_own_script_hash),
    test_extra_redeemer,
  )
}

test withdraw__rejects_two_spending_redeemers() fail {
  builtin_probe.withdraw(
    Void,
    Script(test_own_script_hash),
    test_two_spending_redeemers,
  )
}

test withdraw__rejects_missing_withdrawal() fail {
  builtin_probe.withdraw(
    Void,
    Script(test_own_script_hash),
    test_missing_withdrawal,
  )
}

test withdraw__rejects_extra_withdrawal() fail {
  builtin_probe.withdraw(
    Void,
    Script(test_own_script_hash),
    test_extra_withdrawal,
  )
}

test withdraw__rejects_key_credential() fail {
  builtin_probe.withdraw(
    Void,
    VerificationKey(test_own_script_hash),
    test_input0,
  )
}

const test_registration =
  RegisterCredential {
    credential: Script(test_own_script_hash),
    deposit: Never,
  }

const test_delegation =
  DelegateCredential {
    credential: Script(test_own_script_hash),
    delegate: DelegateBlockProduction {
      stake_pool: builtin.replicate_byte(28, 5),
    },
  }

const test_registration_and_delegation =
  RegisterAndDelegateCredential {
    credential: Script(test_own_script_hash),
    delegate: DelegateBlockProduction {
      stake_pool: builtin.replicate_byte(28, 5),
    },
    deposit: 2_000_000,
  }

const test_deregistration =
  UnregisterCredential {
    credential: Script(test_own_script_hash),
    refund: Never,
  }

test publish__allows_registration() {
  builtin_probe.publish(
    test_ignored_redeemer,
    test_registration,
    transaction.placeholder,
  )
}

test publish__rejects_delegation() fail {
  builtin_probe.publish(
    test_ignored_redeemer,
    test_delegation,
    transaction.placeholder,
  )
}

test publish__rejects_registration_and_delegation() fail {
  builtin_probe.publish(
    test_ignored_redeemer,
    test_registration_and_delegation,
    transaction.placeholder,
  )
}

test publish__rejects_deregistration() fail {
  builtin_probe.publish(
    test_ignored_redeemer,
    test_deregistration,
    transaction.placeholder,
  )
}

// All proof data is constructed in constants so entrypoint test budgets cover
// the mint handler, including its public asset-pair conversion and continuation.
fn test_mint_fixture(
  spend_tx: Transaction,
  own_input_is_first: Bool,
) -> (ProofMintRedeemer, Transaction) {
  let Transaction { inputs, .. } = spend_tx
  let Input { output, .. } = inputs
    |> list.expect_at(
        if own_input_is_first {
          0
        } else {
          1
        },
      )
  let proof = if own_input_is_first {
    fixtures.first_current_network
  } else {
    fixtures.second_current_network
  }
  let  
      ProofFixture {
        transaction,
        collateral_return_input_index,
        spending_reference_input_index,
        witness,
      }
    = fixtures.with_script_output(proof, output)
  (
    ProofMintRedeemer {
      collateral_return_input_index,
      spending_reference_input_index,
      witness,
    },
    transaction,
  )
}

const proof_accepts_builtin_false_at_input0 =
  test_mint_fixture(test_bad_message, True)

test mint__accepts_builtin_false_at_input0() {
  let (redeemer, tx) = proof_accepts_builtin_false_at_input0
  failure_proof.mint(fixtures.script_hash, redeemer, fixtures.policy_id, tx)
}

const proof_accepts_builtin_false_at_input1 =
  test_mint_fixture(test_other_input_substitution, False)

test mint__accepts_builtin_false_at_input1() {
  let (redeemer, tx) = proof_accepts_builtin_false_at_input1
  failure_proof.mint(fixtures.script_hash, redeemer, fixtures.policy_id, tx)
}

const proof_accepts_builtin_signature_failure =
  test_mint_fixture(test_bad_signature, True)

test mint__accepts_builtin_signature_failure() {
  let (redeemer, tx) = proof_accepts_builtin_signature_failure
  failure_proof.mint(fixtures.script_hash, redeemer, fixtures.policy_id, tx)
}

const proof_accepts_builtin_length_error =
  test_mint_fixture(test_malformed_key, True)

test mint__accepts_builtin_length_error() {
  let (redeemer, tx) = proof_accepts_builtin_length_error
  failure_proof.mint(fixtures.script_hash, redeemer, fixtures.policy_id, tx)
}

const proof_rejects_non_list_arguments =
  test_mint_fixture(test_non_list_datum, True)

test mint__rejects_non_list_arguments() fail {
  let (redeemer, tx) = proof_rejects_non_list_arguments
  failure_proof.mint(fixtures.script_hash, redeemer, fixtures.policy_id, tx)
}

const proof_rejects_no_datum = test_mint_fixture(test_no_datum, True)

test mint__rejects_no_datum() fail {
  let (redeemer, tx) = proof_rejects_no_datum
  failure_proof.mint(fixtures.script_hash, redeemer, fixtures.policy_id, tx)
}

const proof_rejects_hashed_datum = test_mint_fixture(test_hashed_datum, True)

test mint__rejects_hashed_datum() fail {
  let (redeemer, tx) = proof_rejects_hashed_datum
  failure_proof.mint(fixtures.script_hash, redeemer, fixtures.policy_id, tx)
}

const proof_rejects_missing_argument =
  test_mint_fixture(test_too_few_arguments, True)

test mint__rejects_missing_argument() fail {
  let (redeemer, tx) = proof_rejects_missing_argument
  failure_proof.mint(fixtures.script_hash, redeemer, fixtures.policy_id, tx)
}

const proof_rejects_extra_argument =
  test_mint_fixture(test_too_many_arguments, True)

test mint__rejects_extra_argument() fail {
  let (redeemer, tx) = proof_rejects_extra_argument
  failure_proof.mint(fixtures.script_hash, redeemer, fixtures.policy_id, tx)
}

const proof_rejects_wrong_key_type =
  test_mint_fixture(test_wrong_key_type, True)

test mint__rejects_wrong_key_type() fail {
  let (redeemer, tx) = proof_rejects_wrong_key_type
  failure_proof.mint(fixtures.script_hash, redeemer, fixtures.policy_id, tx)
}

const proof_rejects_wrong_message_type =
  test_mint_fixture(test_wrong_message_type, True)

test mint__rejects_wrong_message_type() fail {
  let (redeemer, tx) = proof_rejects_wrong_message_type
  failure_proof.mint(fixtures.script_hash, redeemer, fixtures.policy_id, tx)
}

const proof_rejects_wrong_signature_type =
  test_mint_fixture(test_wrong_signature_type, True)

test mint__rejects_wrong_signature_type() fail {
  let (redeemer, tx) = proof_rejects_wrong_signature_type
  failure_proof.mint(fixtures.script_hash, redeemer, fixtures.policy_id, tx)
}

test mint__rejects_mismatched_script_parameter() fail {
  let (redeemer, tx) = proof_accepts_builtin_false_at_input0
  failure_proof.mint(test_other_script_hash, redeemer, fixtures.policy_id, tx)
}
