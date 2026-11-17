//// Regression coverage for the governance configuration multisig.
////
//// These tests call the production handlers. Fixtures represent the fields
//// inspected by those handlers; witnesses and collateral are outside this
//// projection of the ledger transaction.
//// The lifespan_datum cases describe this governance contract's datum schema.

use aiken/builtin
use aiken/collection/dict
use aiken_design_patterns/governance_validation as gov
use cardano/address
use cardano/assets
use cardano/script_context.{ScriptContext, Withdrawing}
use cardano/transaction.{
  DatumHash, InlineDatum, Input, Mint, NoDatum, Output, OutputReference, Spend,
  Transaction, Withdraw,
}
use governance_validation as contract

const own_policy = builtin.replicate_byte(28, 16)

const other_policy = builtin.replicate_byte(28, 32)

const signer_a = builtin.replicate_byte(28, 1)

const signer_b = builtin.replicate_byte(28, 2)

const signer_c = builtin.replicate_byte(28, 3)

const outsider_a = builtin.replicate_byte(28, 4)

const authorized_signers = [signer_a, signer_b, signer_c]

const threshold = 2

const initial_lifespan = 3_024_000_000

const updated_lifespan = 3_456_000_000

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

const unrelated_output =
  Output {
    address: address.from_verification_key(outsider_a),
    value: assets.from_lovelace(10_000_000),
    datum: NoDatum,
    reference_script: None,
  }

const unrelated_input =
  Input {
    output_reference: OutputReference {
      transaction_id: builtin.replicate_byte(32, 0),
      output_index: 0,
    },
    output: unrelated_output,
  }

const nonce_input =
  Input { output_reference: bootstrap_nonce, output: unrelated_output }

const nft_mint =
  assets.from_asset(own_policy, gov.gov_action_lifespan_asset_name, 1)

const configuration_value =
  assets.from_lovelace(5_000_000)
    |> assets.add(own_policy, gov.gov_action_lifespan_asset_name, 1)

const configuration_output =
  Output {
    address: address.from_script(own_policy),
    value: configuration_value,
    datum: InlineDatum(builtin.i_data(initial_lifespan)),
    reference_script: None,
  }

const configuration_input =
  Input { output_reference: own_outref, output: configuration_output }

const continuation_output =
  Output {
    ..configuration_output,
    datum: InlineDatum(builtin.i_data(updated_lifespan)),
  }

const change_output =
  Output { ..unrelated_output, value: assets.from_lovelace(4_000_000) }

// Bootstrap requires no signatories; threshold bounds are checked on minting.
const bootstrap_tx =
  Transaction {
    ..transaction.placeholder,
    inputs: [nonce_input],
    outputs: [configuration_output, change_output],
    fee: 1_000_000,
    mint: nft_mint,
    redeemers: [Pair(Mint(own_policy), builtin.i_data(0))],
  }

// A valid two-of-three update using signers beyond the first list entry.
const update_tx =
  Transaction {
    ..transaction.placeholder,
    inputs: [unrelated_input, configuration_input],
    outputs: [
      continuation_output,
      Output { ..unrelated_output, value: assets.from_lovelace(9_000_000) },
    ],
    fee: 1_000_000,
    extra_signatories: [signer_b, signer_c],
    redeemers: [Pair(Spend(own_outref), builtin.i_data(0))],
  }

// These fixtures conserve ADA and native assets for the additional regression
// cases. The omitted witnesses and collateral belong to the ledger transaction,
// not this handler-level projection.
const balanced_bootstrap_tx =
  Transaction {
    ..bootstrap_tx,
    fee: 1_000_000,
    outputs: [configuration_output, change_output],
  }

const balanced_update_tx =
  Transaction {
    ..update_tx,
    inputs: [unrelated_input, configuration_input],
    fee: 1_000_000,
    outputs: [
      continuation_output,
      Output { ..unrelated_output, value: assets.from_lovelace(9_000_000) },
    ],
  }

fn mint(tx: Transaction) -> Bool {
  contract.governance_parameters.mint(
    bootstrap_nonce,
    authorized_signers,
    threshold,
    0,
    own_policy,
    tx,
  )
}

fn spend(tx: Transaction) -> Bool {
  contract.governance_parameters.spend(
    bootstrap_nonce,
    authorized_signers,
    threshold,
    Some(initial_lifespan),
    0,
    own_outref,
    tx,
  )
}

type OutputFixtures {
  bootstrap: Transaction,
  update: Transaction,
}

// Fixture construction stays in constants so budgets measure validation.
// Bootstrap spends 10 ADA and updates spend 15 ADA; each pays a 1 ADA fee.
fn output_fixtures(output: Output) -> OutputFixtures {
  let Output { value, .. } = output
  let output_lovelace = assets.lovelace_of(value)
  OutputFixtures {
    bootstrap: Transaction {
      ..bootstrap_tx,
      outputs: [
        output,
        Output {
          ..unrelated_output,
          value: assets.from_lovelace(9_000_000 - output_lovelace),
        },
      ],
    },
    update: Transaction {
      ..update_tx,
      outputs: [
        output,
        Output {
          ..unrelated_output,
          value: assets.from_lovelace(14_000_000 - output_lovelace),
        },
      ],
    },
  }
}

test mint__bootstraps_unsigned_at_threshold_bounds() {
  and {
    contract.governance_parameters.mint(
      bootstrap_nonce,
      authorized_signers,
      1,
      0,
      own_policy,
      bootstrap_tx,
    ),
    contract.governance_parameters.mint(
      bootstrap_nonce,
      authorized_signers,
      3,
      0,
      own_policy,
      bootstrap_tx,
    ),
  }
}

test spend__updates_with_exact_threshold() {
  spend(update_tx)
}

// The nonce must be spent, and its complete output reference must match.
const reference_nonce_tx =
  Transaction {
    ..bootstrap_tx,
    inputs: [unrelated_input],
    reference_inputs: [nonce_input],
  }

test mint__rejects_nonce_only_in_reference_inputs() fail {
  mint(reference_nonce_tx)
}

const wrong_nonce_index_tx =
  Transaction {
    ..bootstrap_tx,
    inputs: [
      Input {
        ..nonce_input,
        output_reference: OutputReference { ..bootstrap_nonce, output_index: 1 },
      },
    ],
  }

test mint__rejects_nonce_wrong_output_index() fail {
  mint(wrong_nonce_index_tx)
}

test mint__rejects_zero_threshold() fail {
  contract.governance_parameters.mint(
    bootstrap_nonce,
    authorized_signers,
    0,
    0,
    own_policy,
    bootstrap_tx,
  )
}

test mint__rejects_negative_threshold() fail {
  contract.governance_parameters.mint(
    bootstrap_nonce,
    authorized_signers,
    -1,
    0,
    own_policy,
    balanced_bootstrap_tx,
  )
}

test mint__rejects_threshold_above_signer_count() fail {
  contract.governance_parameters.mint(
    bootstrap_nonce,
    authorized_signers,
    4,
    0,
    own_policy,
    bootstrap_tx,
  )
}

test mint__rejects_nonadjacent_duplicate_signers() fail {
  contract.governance_parameters.mint(
    bootstrap_nonce,
    [signer_a, signer_b, signer_a],
    threshold,
    0,
    own_policy,
    bootstrap_tx,
  )
}

// An existing NFT can be consumed and burned without violating value
// conservation. Its bootstrap nonce has already been spent, so the policy
// rejects the burn at the nonce check.
const burn_tx =
  Transaction {
    ..update_tx,
    inputs: [configuration_input],
    outputs: [change_output],
    mint: assets.from_asset(own_policy, gov.gov_action_lifespan_asset_name, -1),
    redeemers: [
      Pair(Spend(own_outref), builtin.i_data(0)),
      Pair(Mint(own_policy), builtin.i_data(0)),
    ],
  }

test mint__rejects_nft_burn() fail {
  mint(burn_tx)
}

const multiple_mint_tx =
  Transaction {
    ..bootstrap_tx,
    outputs: [
      configuration_output,
      Output {
        ..change_output,
        value: assets.from_lovelace(4_000_000)
          |> assets.add(own_policy, gov.gov_action_lifespan_asset_name, 1),
      },
    ],
    mint: assets.from_asset(own_policy, gov.gov_action_lifespan_asset_name, 2),
  }

test mint__rejects_multiple_nfts() fail {
  mint(multiple_mint_tx)
}

// The extra token goes to change, isolating the minting restriction.
const extra_same_policy_mint_tx =
  Transaction {
    ..bootstrap_tx,
    mint: nft_mint |> assets.add(own_policy, "OTHER", 1),
    outputs: [
      configuration_output,
      Output {
        ..change_output,
        value: assets.from_lovelace(4_000_000)
          |> assets.add(own_policy, "OTHER", 1),
      },
    ],
  }

test mint__rejects_extra_same_policy_asset() fail {
  mint(extra_same_policy_mint_tx)
}

const extra_mint_tx =
  Transaction {
    ..bootstrap_tx,
    outputs: [
      configuration_output,
      Output {
        ..change_output,
        value: assets.from_lovelace(4_000_000)
          |> assets.add(other_policy, "OTHER", 1),
      },
    ],
    mint: nft_mint |> assets.add(other_policy, "OTHER", 1),
    redeemers: [
      Pair(Mint(own_policy), builtin.i_data(0)),
      Pair(Mint(other_policy), builtin.i_data(0)),
    ],
  }

test mint__rejects_extra_other_policy_mint() fail {
  mint(extra_mint_tx)
}

// Additional signatures are allowed; only configured signers count.
const extra_signatures_tx =
  Transaction {
    ..update_tx,
    extra_signatories: [signer_a, signer_b, signer_c, outsider_a],
  }

test spend__accepts_extra_signatures() {
  spend(extra_signatures_tx)
}

const insufficient_signatures_tx =
  Transaction { ..update_tx, extra_signatories: [signer_a, outsider_a] }

test spend__rejects_unrelated_signer_substitution() fail {
  spend(insufficient_signatures_tx)
}

const one_signature_tx =
  Transaction { ..update_tx, extra_signatories: [signer_a] }

test spend__accepts_threshold_one() {
  contract.governance_parameters.spend(
    bootstrap_nonce,
    authorized_signers,
    1,
    Some(initial_lifespan),
    0,
    own_outref,
    one_signature_tx,
  )
}

test spend__rejects_below_unanimous_threshold() fail {
  contract.governance_parameters.spend(
    bootstrap_nonce,
    authorized_signers,
    3,
    Some(initial_lifespan),
    0,
    own_outref,
    update_tx,
  )
}

const unanimous_update_tx =
  Transaction { ..balanced_update_tx, extra_signatories: authorized_signers }

test spend__accepts_unanimous_threshold() {
  contract.governance_parameters.spend(
    bootstrap_nonce,
    authorized_signers,
    3,
    Some(initial_lifespan),
    0,
    own_outref,
    unanimous_update_tx,
  )
}

// Phase 1 allows minting another token name when that token appears in an
// output. The minting policy must enforce the configuration token's identity.
const wrong_nft_name_output =
  Output {
    ..configuration_output,
    value: assets.from_lovelace(5_000_000) |> assets.add(own_policy, "OTHER", 1),
  }

const wrong_asset_name_tx =
  Transaction {
    ..bootstrap_tx,
    outputs: [wrong_nft_name_output, change_output],
    mint: assets.from_asset(own_policy, "OTHER", 1),
  }

test mint__rejects_wrong_asset_name() fail {
  mint(wrong_asset_name_tx)
}

// A selected output can omit the NFT while another output receives it. This
// preserves ledger value conservation and isolates the custody check.
const diverted_nft_output =
  Output {
    ..configuration_output,
    address: address.from_verification_key(outsider_a),
  }

const missing_nft_output =
  Output { ..configuration_output, value: assets.from_lovelace(4_000_000) }

const missing_nft_bootstrap_tx =
  Transaction {
    ..balanced_bootstrap_tx,
    outputs: [missing_nft_output, diverted_nft_output],
  }

const missing_nft_update_tx =
  Transaction {
    ..balanced_update_tx,
    outputs: [
      missing_nft_output,
      diverted_nft_output,
      Output { ..unrelated_output, value: assets.from_lovelace(5_000_000) },
    ],
  }

test mint__rejects_output_missing_nft() fail {
  mint(missing_nft_bootstrap_tx)
}

test spend__rejects_output_missing_nft() fail {
  spend(missing_nft_update_tx)
}

// Anyone can create an unauthenticated UTxO at the configuration script. The
// genuine configuration is a separate input supplying the continuation's NFT.
const authentic_configuration_input =
  Input {
    ..configuration_input,
    output_reference: OutputReference { ..own_outref, output_index: 1 },
  }

const missing_nft_input_tx =
  Transaction {
    ..balanced_update_tx,
    inputs: [
      Input { ..configuration_input, output: missing_nft_output },
      authentic_configuration_input,
    ],
    outputs: [
      continuation_output,
      Output { ..unrelated_output, value: assets.from_lovelace(3_000_000) },
    ],
  }

test spend__rejects_input_missing_nft() fail {
  spend(missing_nft_input_tx)
}

const wrong_nft_policy_output =
  Output {
    ..configuration_output,
    value: assets.from_lovelace(5_000_000)
      |> assets.add(other_policy, gov.gov_action_lifespan_asset_name, 1),
  }

const wrong_nft_policy_funding_input =
  Input {
    ..unrelated_input,
    output: Output {
      ..unrelated_output,
      value: assets.from_lovelace(5_000_000)
        |> assets.add(other_policy, gov.gov_action_lifespan_asset_name, 1),
    },
  }

const wrong_nft_policy_bootstrap_tx =
  Transaction {
    ..balanced_bootstrap_tx,
    inputs: [wrong_nft_policy_funding_input, nonce_input],
    outputs: [wrong_nft_policy_output, diverted_nft_output, change_output],
  }

const wrong_nft_policy_update_tx =
  Transaction {
    ..balanced_update_tx,
    inputs: [wrong_nft_policy_funding_input, configuration_input],
    outputs: [
      wrong_nft_policy_output,
      Output {
        ..diverted_nft_output,
        value: assets.from_lovelace(4_000_000)
          |> assets.add(own_policy, gov.gov_action_lifespan_asset_name, 1),
      },
    ],
  }

const wrong_nft_policy_input_tx =
  Transaction {
    ..balanced_update_tx,
    inputs: [
      Input { ..configuration_input, output: wrong_nft_policy_output },
      authentic_configuration_input,
    ],
    outputs: [
      continuation_output,
      Output {
        ..change_output,
        value: assets.from_lovelace(4_000_000)
          |> assets.add(other_policy, gov.gov_action_lifespan_asset_name, 1),
      },
    ],
  }

test mint__rejects_output_wrong_nft_policy() fail {
  mint(wrong_nft_policy_bootstrap_tx)
}

test spend__rejects_output_wrong_nft_policy() fail {
  spend(wrong_nft_policy_update_tx)
}

test spend__rejects_input_wrong_nft_policy() fail {
  spend(wrong_nft_policy_input_tx)
}

const extra_other_policy_asset_output =
  Output {
    ..configuration_output,
    value: configuration_value |> assets.add(other_policy, "OTHER", 1),
  }

const extra_other_policy_asset_outputs = {
    let OutputFixtures { bootstrap, update } = output_fixtures(
      extra_other_policy_asset_output,
    )
    let funding_output = Output {
      ..unrelated_output,
      value: assets.from_lovelace(10_000_000)
        |> assets.add(other_policy, "OTHER", 1),
    }
    OutputFixtures {
      bootstrap: Transaction {
        ..bootstrap,
        inputs: [Input { ..nonce_input, output: funding_output }],
      },
      update: Transaction {
        ..update,
        inputs: [
          Input { ..unrelated_input, output: funding_output },
          configuration_input,
        ],
      },
    }
  }

test mint__rejects_output_extra_other_policy_asset() fail {
  mint(extra_other_policy_asset_outputs.bootstrap)
}

test spend__rejects_output_extra_other_policy_asset() fail {
  spend(extra_other_policy_asset_outputs.update)
}

// The destination must be this payment script, with no reference script.
const wrong_script_outputs =
  output_fixtures(
    Output {
      ..configuration_output,
      address: address.from_script(other_policy),
    },
  )

test mint__rejects_output_wrong_script() fail {
  mint(wrong_script_outputs.bootstrap)
}

test spend__rejects_output_wrong_script() fail {
  spend(wrong_script_outputs.update)
}

const key_credential_outputs =
  output_fixtures(
    Output {
      ..configuration_output,
      address: address.from_verification_key(own_policy),
    },
  )

test mint__rejects_output_key_credential() fail {
  mint(key_credential_outputs.bootstrap)
}

test spend__rejects_output_key_credential() fail {
  spend(key_credential_outputs.update)
}

const reference_script_outputs =
  output_fixtures(
    Output { ..configuration_output, reference_script: Some(other_policy) },
  )

test mint__rejects_output_reference_script() fail {
  mint(reference_script_outputs.bootstrap)
}

test spend__rejects_output_reference_script() fail {
  spend(reference_script_outputs.update)
}

// Successful selections include unrelated inputs and an earlier output.
const bootstrap_at_one =
  Transaction {
    ..bootstrap_tx,
    inputs: [unrelated_input, nonce_input],
    outputs: [unrelated_output, configuration_output, change_output],
    redeemers: [Pair(Mint(own_policy), builtin.i_data(1))],
  }

const update_at_one =
  Transaction {
    ..update_tx,
    inputs: [unrelated_input, configuration_input],
    outputs: [
      Output { ..unrelated_output, value: assets.from_lovelace(9_000_000) },
      continuation_output,
    ],
    redeemers: [Pair(Spend(own_outref), builtin.i_data(1))],
  }

test mint__selects_nonzero_output_index() {
  contract.governance_parameters.mint(
    bootstrap_nonce,
    authorized_signers,
    threshold,
    1,
    own_policy,
    bootstrap_at_one,
  )
}

test spend__selects_nonzero_output_index() {
  contract.governance_parameters.spend(
    bootstrap_nonce,
    authorized_signers,
    threshold,
    Some(initial_lifespan),
    1,
    own_outref,
    update_at_one,
  )
}

// Both inputs come from one transaction; the script input is its second output.
const configuration_outref_at_one =
  OutputReference { ..own_outref, output_index: 1 }

const same_txid_update =
  Transaction {
    ..update_tx,
    inputs: [
      Input { ..unrelated_input, output_reference: own_outref },
      Input {
        ..configuration_input,
        output_reference: configuration_outref_at_one,
      },
    ],
    redeemers: [Pair(Spend(configuration_outref_at_one), builtin.i_data(0))],
  }

test spend__selects_correct_output_from_same_transaction() {
  contract.governance_parameters.spend(
    bootstrap_nonce,
    authorized_signers,
    threshold,
    Some(initial_lifespan),
    0,
    configuration_outref_at_one,
    same_txid_update,
  )
}

const wrong_selected_bootstrap_tx =
  Transaction {
    ..bootstrap_at_one,
    redeemers: [Pair(Mint(own_policy), builtin.i_data(0))],
  }

test mint__rejects_wrong_selected_output() fail {
  mint(wrong_selected_bootstrap_tx)
}

const wrong_selected_update_tx =
  Transaction {
    ..update_at_one,
    redeemers: [Pair(Spend(own_outref), builtin.i_data(0))],
  }

test spend__rejects_wrong_selected_output() fail {
  spend(wrong_selected_update_tx)
}

// These indexes are integer redeemer values, not ledger OutputReference
// indexes. Phase 1 permits them; the validator must check their output bounds.
test mint__rejects_negative_redeemer_output_index() fail {
  contract.governance_parameters.mint(
    bootstrap_nonce,
    authorized_signers,
    threshold,
    -1,
    own_policy,
    balanced_bootstrap_tx,
  )
}

test spend__rejects_negative_redeemer_output_index() fail {
  contract.governance_parameters.spend(
    bootstrap_nonce,
    authorized_signers,
    threshold,
    Some(initial_lifespan),
    -1,
    own_outref,
    balanced_update_tx,
  )
}

test mint__rejects_out_of_bounds_redeemer_output_index() fail {
  contract.governance_parameters.mint(
    bootstrap_nonce,
    authorized_signers,
    threshold,
    2,
    own_policy,
    balanced_bootstrap_tx,
  )
}

test spend__rejects_out_of_bounds_redeemer_output_index() fail {
  contract.governance_parameters.spend(
    bootstrap_nonce,
    authorized_signers,
    threshold,
    Some(initial_lifespan),
    2,
    own_outref,
    balanced_update_tx,
  )
}

// The NFT goes to a key address: 5 ADA in = 4 ADA out + 1 ADA fee.
// The quorum and spend redeemer are valid, so rejection isolates custody.
const diverted_configuration_tx =
  Transaction {
    ..update_tx,
    inputs: [configuration_input],
    outputs: [
      Output {
        ..diverted_nft_output,
        value: assets.from_lovelace(4_000_000)
          |> assets.add(own_policy, gov.gov_action_lifespan_asset_name, 1),
      },
    ],
    fee: 1_000_000,
    redeemers: [Pair(Spend(own_outref), builtin.i_data(0))],
  }

test spend__rejects_diverted_configuration_nft() fail {
  spend(diverted_configuration_tx)
}

// Governance datums must be inline integers. The hash witness is present.
const lifespan_datum_hash = {
    let data = builtin.i_data(initial_lifespan)
    let hash = builtin.blake2b_256(builtin.serialise_data(data))
    let OutputFixtures { bootstrap, update } = output_fixtures(
      Output { ..configuration_output, datum: DatumHash(hash) },
    )
    let datums = dict.singleton(hash, data)
    OutputFixtures {
      bootstrap: Transaction { ..bootstrap, datums },
      update: Transaction { ..update, datums },
    }
  }

test mint__lifespan_datum_rejects_hash() fail {
  mint(lifespan_datum_hash.bootstrap)
}

test spend__lifespan_datum_rejects_hash() fail {
  spend(lifespan_datum_hash.update)
}

const missing_datum_bootstrap_tx =
  Transaction {
    ..balanced_bootstrap_tx,
    outputs: [Output { ..configuration_output, datum: NoDatum }, change_output],
  }

const missing_datum_update_tx =
  Transaction {
    ..balanced_update_tx,
    outputs: [
      Output { ..continuation_output, datum: NoDatum },
      Output { ..unrelated_output, value: assets.from_lovelace(9_000_000) },
    ],
  }

test mint__lifespan_datum_rejects_missing_datum() fail {
  mint(missing_datum_bootstrap_tx)
}

test spend__lifespan_datum_rejects_missing_datum() fail {
  spend(missing_datum_update_tx)
}

const lifespan_datum_constructor =
  output_fixtures(
    Output {
      ..configuration_output,
      datum: InlineDatum(
        builtin.constr_data(0, [builtin.i_data(initial_lifespan)]),
      ),
    },
  )

test mint__lifespan_datum_rejects_constructor() fail {
  mint(lifespan_datum_constructor.bootstrap)
}

test spend__lifespan_datum_rejects_constructor() fail {
  spend(lifespan_datum_constructor.update)
}

// Lifespan values have no semantic range restriction.
const lifespan_datum_negative =
  output_fixtures(
    Output { ..configuration_output, datum: InlineDatum(builtin.i_data(-1)) },
  )

test mint__lifespan_datum_accepts_negative() {
  mint(lifespan_datum_negative.bootstrap)
}

test spend__lifespan_datum_accepts_negative() {
  spend(lifespan_datum_negative.update)
}

const zero_lifespan_output =
  Output { ..configuration_output, datum: InlineDatum(builtin.i_data(0)) }

const zero_lifespan_bootstrap_tx =
  Transaction {
    ..balanced_bootstrap_tx,
    outputs: [zero_lifespan_output, change_output],
  }

const zero_lifespan_update_tx =
  Transaction {
    ..balanced_update_tx,
    outputs: [
      zero_lifespan_output,
      Output { ..unrelated_output, value: assets.from_lovelace(9_000_000) },
    ],
  }

test mint__lifespan_datum_accepts_zero() {
  mint(zero_lifespan_bootstrap_tx)
}

test spend__lifespan_datum_accepts_zero() {
  spend(zero_lifespan_update_tx)
}

const unchanged_datum_tx = output_fixtures(configuration_output).update

test spend__lifespan_datum_allows_unchanged_value() {
  spend(unchanged_datum_tx)
}

// Accepted update flexibility must survive the multisig abstraction.
const increased_ada_outputs =
  output_fixtures(
    Output {
      ..continuation_output,
      value: assets.from_lovelace(8_000_000)
        |> assets.add(own_policy, gov.gov_action_lifespan_asset_name, 1),
    },
  )

const decreased_ada_outputs =
  output_fixtures(
    Output {
      ..continuation_output,
      value: assets.from_lovelace(3_000_000)
        |> assets.add(own_policy, gov.gov_action_lifespan_asset_name, 1),
    },
  )

test spend__allows_ada_increase() {
  spend(increased_ada_outputs.update)
}

test spend__allows_ada_decrease() {
  spend(decreased_ada_outputs.update)
}

const staked_outputs =
  output_fixtures(
    Output {
      ..continuation_output,
      address: address.from_script(own_policy)
        |> address.with_delegation_key(signer_c),
    },
  )

test spend__allows_changed_staking_credential() {
  spend(staked_outputs.update)
}

const unrelated_mint_output =
  Output {
    ..unrelated_output,
    value: assets.from_lovelace(9_000_000)
      |> assets.add(other_policy, "OTHER", 1),
  }

const unrelated_mint_tx =
  Transaction {
    ..update_tx,
    mint: assets.from_asset(other_policy, "OTHER", 1),
    outputs: [continuation_output, unrelated_mint_output],
    redeemers: [
      Pair(Spend(own_outref), builtin.i_data(0)),
      Pair(Mint(other_policy), builtin.i_data(0)),
    ],
  }

test spend__allows_unrelated_policy_mint() {
  spend(unrelated_mint_tx)
}

// A registered script credential can appear in a zero withdrawal without
// spending the configuration UTxO. Exercise the production fallback directly.
const unsupported_withdrawal_context =
  ScriptContext {
    transaction: Transaction {
      ..transaction.placeholder,
      inputs: [unrelated_input],
      outputs: [
        Output { ..unrelated_output, value: assets.from_lovelace(9_000_000) },
      ],
      fee: 1_000_000,
      withdrawals: [Pair(address.Script(own_policy), 0)],
      redeemers: [Pair(Withdraw(address.Script(own_policy)), builtin.i_data(0))],
    },
    redeemer: builtin.i_data(0),
    info: Withdrawing(address.Script(own_policy)),
  }

test else__rejects_withdrawal() fail {
  contract.governance_parameters.else(
    bootstrap_nonce,
    authorized_signers,
    threshold,
    unsupported_withdrawal_context,
  )
}
