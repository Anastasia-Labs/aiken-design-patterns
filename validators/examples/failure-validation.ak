//// @hidden

use aiken/collection/list
use aiken/crypto.{ScriptHash}
use aiken_design_patterns/failure_validation.{FailedTransactionWitness}
use aiken_design_patterns/transaction_serialization.{RedeemerEncoding}
use cardano/address.{Address, Credential, Script}
use cardano/assets.{AssetName, Lovelace, PolicyId}
use cardano/certificate.{Certificate, RegisterCredential}
use cardano/transaction.{
  Datum, Output, OutputReference, Redeemer, Spend, Transaction, Withdraw,
}
use config

const spending_mem = 50_000

const spending_cpu = 14_000_000

const max_mem = 17_500_000

const max_cpu = 10_000_000_000

pub type ProofMintRedeemer {
  collateral_return_input_index: Int,
  spending_reference_input_index: Int,
  witness: ProofMintWitness,
}

// Output asset maps cross the redeemer boundary as public pairs and are
// converted into opaque Assets with the standard constructor below.
pub type ProofOutput {
  address: Address,
  value: Pairs<PolicyId, Pairs<AssetName, Int>>,
  datum: Datum,
  reference_script: Option<ScriptHash>,
}

pub type ProofMintWitness {
  outputs: List<ProofOutput>,
  fee: Lovelace,
  collateral_input: OutputReference,
  total_collateral: Lovelace,
  reference_inputs: List<OutputReference>,
  withdrawal_redeemer: Redeemer,
  redeemer_encoding: RedeemerEncoding,
  cost_model: ByteArray,
}

validator delegated_spend(core_script_hash: ScriptHash) {
  spend(
    _m_datum: Option<Data>,
    redeemer: ScriptHash,
    _own_out_ref: OutputReference,
    tx: Transaction,
  ) {
    let Transaction { withdrawals, redeemers, .. } = tx
    expect [Pair(Script(withdraw_script_hash), _)] = withdrawals
    // No need to check for the spend's output reference, or withdrawal script
    // hash, as there can't be any other spend redeemers, and withdrawal is
    // already validated via the withdrawals entry.
    expect [Pair(Spend(_), _), Pair(Withdraw(Script(_)), _)] = redeemers
    // Re-provision of the core script hash via the redeemer allows other
    // scripts to verify this spend logic would have passed given the correct
    // script hash.
    expect redeemer == core_script_hash
    expect withdraw_script_hash == core_script_hash
    True
  }

  else(_) {
    fail
  }
}

validator always_fails_withdrawal {
  publish(_redeemer: Redeemer, certificate: Certificate, _tx: Transaction) {
    // Disallowing any delegation prevents the reward address from accruing
    // rewards and therefore ensures withdrawal amount can't be any values
    // other than zero.
    // TODO: This will need revision once reward deposits CIP are implemented.
    when certificate is {
      RegisterCredential { .. } -> True
      _ -> False
    }
  }

  withdraw(_redeemer: Redeemer, _own_credential: Credential, _tx: Transaction) {
    False
  }

  else(_) {
    fail
  }
}

validator failure_proof(
  spending_script_hash: ScriptHash,
  withdrawal_script_hash: ScriptHash,
) {
  mint(redeemer: ProofMintRedeemer, policy_id: PolicyId, tx: Transaction) {
    let Transaction { inputs, reference_inputs, mint, .. } = tx
    let
        ProofMintRedeemer {
          collateral_return_input_index,
          spending_reference_input_index,
          witness,
        }
      = redeemer
    let
        ProofMintWitness {
          outputs,
          fee,
          collateral_input,
          total_collateral,
          reference_inputs: failed_reference_inputs,
          withdrawal_redeemer,
          redeemer_encoding,
          cost_model,
        }
      = witness
    let witness = FailedTransactionWitness {
      outputs: list.map(
        outputs,
        fn(output) {
          let ProofOutput { address, value, datum, reference_script } = output
          Output {
            address,
            value: assets.from_asset_list(value),
            datum,
            reference_script,
          }
        },
      ),
      fee,
      collateral_input,
      total_collateral,
      reference_inputs: failed_reference_inputs,
      withdrawal_redeemer,
      redeemer_encoding,
      cost_model,
    }
    let _withdrawal_redeemer <- failure_validation.validate_mint(
      own_policy: policy_id,
      spending_script_hash: spending_script_hash,
      withdrawal_script_hash: withdrawal_script_hash,
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
    // The withdrawal ignores its redeemer and always fails.
    True
  }

  else(_) {
    fail
  }
}
