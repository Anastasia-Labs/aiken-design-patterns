use aiken_design_patterns/stake_validator
use aiken_design_patterns/utils.{resolve_output_reference}
use cardano/address.{Address, Credential, Script}
use cardano/transaction.{Output, OutputReference, Redeemer, Transaction}

/// Example for a validator that requires a withdrawal from its script for each
/// spend. Note that depending on an external script is typically more
/// performant.
validator example {
  spend(_datum, _redeemer, own_out_ref: OutputReference, tx: Transaction) {
    let Output { address: own_addr, .. } =
      resolve_output_reference(tx.inputs, own_out_ref)

    expect Script(own_withdrawal) = own_addr.payment_credential

    stake_validator.spend(
      withdraw_script_hash: own_withdrawal,
      withdraw_redeemer_validator: fn(_r_data, qty) { qty == 0 },
      tx: tx,
    )
  }

  withdraw(redeemer: Redeemer, own_credential: Credential, tx: Transaction) {
    stake_validator.withdraw(
      withdrawal_logic: fn(_r, _own_validator, _tx) { True },
      redeemer: redeemer,
      stake_cred: own_credential,
      tx: tx,
    )
  }

  else(_) {
    fail
  }
}
