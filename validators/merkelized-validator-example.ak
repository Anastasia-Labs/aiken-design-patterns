use aiken/builtin
use aiken/crypto.{ScriptHash}
use aiken_design_patterns/merkelized_validator.{
  WithdrawRedeemer, WithdrawRedeemerIO,
}
use aiken_design_patterns/utils.{sum_of_squares}
use cardano/address.{Credential}
use cardano/transaction.{OutputReference, Transaction}

/// Definition of a custom validator for spending transactions, utilizing both
/// `delegated_compute` and `delegated_validation`.
validator spending_example(
  summation_stake_validator: ScriptHash,
  forty_two_stake_validator: ScriptHash,
) {
  spend(m_x: Option<Int>, y: Int, _own_ref: OutputReference, tx: Transaction) {
    expect Some(x) = m_x
    let sum =
      [x, y]
        |> merkelized_validator.delegated_compute(
            summation_stake_validator,
            fn(d: Data) -> List<Int> {
              expect ints: List<Int> = d
              ints
            },
            builtin.un_i_data,
            tx.redeemers,
          )
    merkelized_validator.delegated_validation(
      sum,
      forty_two_stake_validator,
      builtin.un_i_data,
      tx.redeemers,
    )
  }

  else(_) {
    fail
  }
}

/// Definition of a custom validator for withdrawal transactions. We are using
/// `WithdrawRedeemer<List<Int>, Int>` to showcase how multiple inputs and/or
/// outputs can be incorporated.
validator summation_staking_script {
  withdraw(
    redeemer: WithdrawRedeemerIO<List<Int>, Int>,
    _own_credential: Credential,
    _tx: Transaction,
  ) {
    merkelized_validator.withdraw_io(sum_of_squares, redeemer)
  }

  else(_) {
    fail
  }
}

validator forty_two_staking_script {
  withdraw(
    redeemer: WithdrawRedeemer<Int>,
    _own_credential: Credential,
    _tx: Transaction,
  ) {
    merkelized_validator.withdraw(fn(num: Int) { num == 42 }, redeemer)
  }

  else(_) {
    fail
  }
}
