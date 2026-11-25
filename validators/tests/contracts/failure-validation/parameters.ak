//// Bootstrap authorization and datum-schema coverage for the failure parameters
//// validator. Datum-schema fixtures carry a quorum of authorized signers.

use aiken/builtin
use aiken_design_patterns/failure_validation.{
  FailureParameters, failure_parameters_asset_name,
}
use cardano/address
use cardano/assets
use cardano/transaction.{
  InlineDatum, Input, Mint, NoDatum, Output, OutputReference, Spend, Transaction,
}
use failure_validation as contract

const own_policy = builtin.replicate_byte(28, 16)

const signer_a = builtin.replicate_byte(28, 1)

const signer_b = builtin.replicate_byte(28, 2)

const outsider = builtin.replicate_byte(28, 3)

const authorized_signers = [signer_a, signer_b]

const threshold = 2

const initial_parameters =
  FailureParameters { max_mem: 17_500_000, max_cpu: 10_000_000_000 }

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

const configuration_output =
  Output {
    address: address.from_script(own_policy),
    value: assets.from_lovelace(5_000_000)
      |> assets.add(own_policy, failure_parameters_asset_name, 1),
    datum: InlineDatum(initial_parameters),
    reference_script: None,
  }

type DatumFixtures {
  bootstrap: Transaction,
  update: Transaction,
}

// Construct balanced fixtures in constants so budgets measure validation only.
fn datum_fixtures(datum: Data) -> DatumFixtures {
  let produced_output = Output {
    ..configuration_output,
    datum: InlineDatum(datum),
  }
  DatumFixtures {
    bootstrap: Transaction {
      ..transaction.placeholder,
      inputs: [
        Input { output_reference: bootstrap_nonce, output: funding_output },
      ],
      outputs: [
        produced_output,
        Output { ..funding_output, value: assets.from_lovelace(4_000_000) },
      ],
      fee: 1_000_000,
      mint: assets.from_asset(own_policy, failure_parameters_asset_name, 1),
      extra_signatories: authorized_signers,
      redeemers: [Pair(Mint(own_policy), builtin.i_data(0))],
    },
    update: Transaction {
      ..transaction.placeholder,
      inputs: [
        Input { output_reference: own_outref, output: configuration_output },
      ],
      outputs: [
        Output {
          ..produced_output,
          value: assets.from_lovelace(4_000_000)
            |> assets.add(own_policy, failure_parameters_asset_name, 1),
        },
      ],
      fee: 1_000_000,
      extra_signatories: authorized_signers,
      redeemers: [Pair(Spend(own_outref), builtin.i_data(0))],
    },
  }
}

fn mint(tx: Transaction) -> Bool {
  contract.failure_parameters.mint(
    bootstrap_nonce,
    authorized_signers,
    threshold,
    0,
    own_policy,
    tx,
  )
}

fn spend(tx: Transaction) -> Bool {
  contract.failure_parameters.spend(
    bootstrap_nonce,
    authorized_signers,
    threshold,
    Some(initial_parameters),
    0,
    own_outref,
    tx,
  )
}

const ordinary_budgets = datum_fixtures(initial_parameters)

test mint__datum_accepts_integer_budgets() {
  mint(ordinary_budgets.bootstrap)
}

const bootstrap_with_extra_signer =
  Transaction {
    ..ordinary_budgets.bootstrap,
    extra_signatories: [signer_a, signer_b, outsider],
  }

test mint__accepts_quorum_with_extra_signer() {
  mint(bootstrap_with_extra_signer)
}

const bootstrap_without_signers =
  Transaction { ..ordinary_budgets.bootstrap, extra_signatories: [] }

test mint__rejects_nonce_without_required_signers() fail {
  mint(bootstrap_without_signers)
}

const bootstrap_with_one_signer =
  Transaction { ..ordinary_budgets.bootstrap, extra_signatories: [signer_a] }

test mint__rejects_below_threshold() fail {
  mint(bootstrap_with_one_signer)
}

const bootstrap_with_outsider =
  Transaction {
    ..ordinary_budgets.bootstrap,
    extra_signatories: [signer_a, outsider],
  }

test mint__rejects_outsider_substitution() fail {
  mint(bootstrap_with_outsider)
}

test spend__datum_accepts_unchanged_budgets() {
  spend(ordinary_budgets.update)
}

const non_record = datum_fixtures(builtin.i_data(42))

test mint__datum_rejects_non_record() fail {
  mint(non_record.bootstrap)
}

test spend__datum_rejects_non_record() fail {
  spend(non_record.update)
}

const wrong_constructor =
  datum_fixtures(
    builtin.constr_data(
      1,
      [builtin.i_data(17_500_000), builtin.i_data(10_000_000_000)],
    ),
  )

test mint__datum_rejects_wrong_constructor() fail {
  mint(wrong_constructor.bootstrap)
}

test spend__datum_rejects_wrong_constructor() fail {
  spend(wrong_constructor.update)
}

const missing_field =
  datum_fixtures(builtin.constr_data(0, [builtin.i_data(17_500_000)]))

test mint__datum_rejects_missing_field() fail {
  mint(missing_field.bootstrap)
}

test spend__datum_rejects_missing_field() fail {
  spend(missing_field.update)
}

const extra_field =
  datum_fixtures(
    builtin.constr_data(
      0,
      [
        builtin.i_data(17_500_000),
        builtin.i_data(10_000_000_000),
        builtin.i_data(1),
      ],
    ),
  )

test mint__datum_rejects_extra_field() fail {
  mint(extra_field.bootstrap)
}

test spend__datum_rejects_extra_field() fail {
  spend(extra_field.update)
}

const non_integer_memory =
  datum_fixtures(
    builtin.constr_data(
      0,
      [builtin.b_data(#"00"), builtin.i_data(10_000_000_000)],
    ),
  )

test mint__datum_rejects_non_integer_memory() fail {
  mint(non_integer_memory.bootstrap)
}

test spend__datum_rejects_non_integer_memory() fail {
  spend(non_integer_memory.update)
}

const non_integer_cpu =
  datum_fixtures(
    builtin.constr_data(0, [builtin.i_data(17_500_000), builtin.b_data(#"00")]),
  )

test mint__datum_rejects_non_integer_cpu() fail {
  mint(non_integer_cpu.bootstrap)
}

test spend__datum_rejects_non_integer_cpu() fail {
  spend(non_integer_cpu.update)
}
