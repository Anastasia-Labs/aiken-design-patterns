use aiken/builtin
use aiken/crypto.{ScriptHash}
use aiken_design_patterns/merkelized_validator.{
  ComputationRedeemer, ValidationRedeemer,
}
use aiken_design_patterns/utils.{sum_of_squares}
use cardano/address.{Credential}
use cardano/transaction.{OutputReference, Transaction}

pub type ExampleSpendRedeemer {
  withdraw_redeemer_index: Int,
  second_integer: Int,
}

/// Definition of a custom validator for spending transactions, utilizing both
/// `delegated_compute` and `delegated_validation`.
validator spending_example(
  summation_stake_validator: ScriptHash,
  forty_two_stake_validator: ScriptHash,
) {
  spend(
    m_x: Option<Int>,
    r: ExampleSpendRedeemer,
    _own_ref: OutputReference,
    tx: Transaction,
  ) {
    expect Some(x) = m_x
    let sum =
      [x, r.second_integer]
        |> merkelized_validator.delegated_compute(
            staking_validator: summation_stake_validator,
            redeemers: tx.redeemers,
            redeemer_index: r.withdraw_redeemer_index,
            input_data_coercer: fn(d: Data) -> List<Int> {
              expect ints: List<Int> = d
              ints
            },
            output_data_coercer: builtin.un_i_data,
          )
    merkelized_validator.delegated_validation(
      function_input: sum,
      staking_validator: forty_two_stake_validator,
      redeemers: tx.redeemers,
      redeemer_index: r.withdraw_redeemer_index,
      input_data_coercer: builtin.un_i_data,
    )
  }

  else(_) {
    fail
  }
}

/// Definition of a custom validator for withdrawal transactions. We are using
/// `ComputationRedeemer<List<Int>, Int>` to showcase how multiple inputs and/or
/// outputs can be incorporated.
///
/// Result of compiling this validator and acquiring its hash, should be used as
/// the `summation_stake_validator` parameter of the spending script above.
validator summation_staking_script {
  withdraw(
    redeemer: ComputationRedeemer<List<Int>, Int>,
    _own_credential: Credential,
    _tx: Transaction,
  ) {
    let ints <- merkelized_validator.computation_withdrawal_wrapper(redeemer)
    sum_of_squares(ints)
  }

  else(_) {
    fail
  }
}

/// Result of compiling this validator and acquiring its hash, should be used as
/// the `forty_two_stake_validator` parameter of the spending script above.
validator forty_two_staking_script {
  withdraw(
    redeemer: ValidationRedeemer<Int>,
    _own_credential: Credential,
    _tx: Transaction,
  ) {
    let num <- merkelized_validator.validation_withdrawal_wrapper(redeemer)
    num == 42
  }

  else(_) {
    fail
  }
}
