//// # Failure validation
////
//// This pattern mints evidence that a withdrawal validator failed while
//// applying a builtin to arguments supplied in its redeemer. Accepted failure
//// includes a builtin crash, a `False` result, or exhaustion of the prescribed
//// withdrawal budget. The withdrawal checks argument preparation and executes
//// the builtin; the proof policy checks preparation without executing it.
////
//// ## Supported transaction shape
////
//// `validate_mint` reconstructs a Plutus V3 transaction with ordinary inputs in
//// ledger order, one collateral input, one zero withdrawal, ordinary outputs,
//// a fee, a script-data hash, collateral return, and total collateral. Reference
//// inputs are optional; their field is omitted when empty. The body has no
//// validity bounds, required signers, metadata hash, network-ID entry, minting,
//// certificates, governance actions, or treasury fields. Datum witnesses are
//// unsupported.
////
//// The complete redeemer collection contains only `Withdraw` at ledger index
//// zero. Its raw `Data` contains the builtin arguments. The caller supplies
//// the agreed withdrawal script hash and exact CPU and memory allowances.
//// Authenticating the complete collection excludes other phase-2 purposes;
//// any native scripts must already have succeeded in phase 1.
////
//// Ordinary outputs are supplied as their complete CBOR array. A structural
//// scan counts its elements and checks its boundaries without interpreting
//// output fields. Definite and indefinite containers and nonminimal headers
//// retain their original bytes, including embedded datums and reference
//// scripts. Ledger validation establishes the outputs' validity. The collateral
//// return is reconstructed from the actual consumed output with address and
//// value only, so its authenticated encoding has no datum or reference script.
////
//// ## Two-transaction proof
////
//// The producing transaction is accepted with `isValid = false` after phase-2
//// failure. Its collateral input is consumed and its collateral return is
//// created. Its ordinary inputs remain unspent and ordinary outputs are not
//// created. An outright rejected transaction supplies no failure evidence.
////
//// The proof transaction consumes the collateral return. Hashing the
//// reconstructed body must reproduce that input's transaction ID. Its output
//// index must equal the authenticated number of ordinary outputs: ordinary
//// outputs occupy indices zero through count minus one, and the collateral
//// return occupies index count. The existence of this exact output therefore
//// proves failure. No original input needs to remain available for minting.
////
//// Exactly one token is minted under the caller's policy, named with the failed
//// transaction's hash. Consuming its collateral return prevents repeated use
//// of the evidence. Minting under other policies is unrestricted by this helper.
////
//// ## Authenticating the invocation
////
//// Transaction-ID equality authenticates the body under the hash's collision
//// resistance. The reconstructed script-data hash authenticates the complete
//// redeemer collection, its pointer, arguments, exact execution budget, and
//// Plutus V3 language-view cost model. Redeemer Data uses the shared serializer's
//// definite collections and chunked long byte strings, preserving map-entry
//// order and duplicate keys. The witness must reproduce the committed bytes.
////
//// The continuation receives the authenticated arguments as raw `Data`. It
//// must check every preparation step performed by the agreed withdrawal script,
//// without executing the builtin. Returning `False` or failing rejects the
//// proof. For Ed25519 verification, checking exactly three byte strings excludes
//// extraction failures while allowing invalid signatures and length errors
//// raised by the builtin itself.
////
//// ## Execution budget
////
//// The example assigns the full configured transaction allowance to withdrawal:
//// 17,500,000 memory and 10,000,000,000 CPU. The helper authenticates the caller's
//// exact allowance but does not obtain protocol parameters or establish that it
//// equals the transaction maximum. Cost models and maximum allowances are
//// separate parameters, and the parameters applicable to the producing
//// transaction can differ from those applicable when proof is minted.
////
//// The proof establishes failure of the authenticated withdrawal invocation
//// under that allowance. It does not distinguish a builtin crash, `False`, or
//// budget exhaustion, nor establish where evaluation exhausted its budget.

use aiken/builtin
use aiken/cbor
use aiken/collection/dict
use aiken/collection/list
use aiken/crypto.{ScriptHash}
use aiken/primitive/bytearray
use aiken_design_patterns/failure_validation/outputs
use aiken_design_patterns/transaction_serialization.{
  RedeemerEncoding, hash_script_data, insert_redeemer_entry, serialise_budget,
  serialise_cbor_head, serialise_nonempty_list_field, serialise_plutus_data,
  serialise_redeemer_entries, serialise_tx_inputs, serialise_tx_output,
  serialise_withdrawals,
}
use cardano/address.{Script}
use cardano/assets.{Assets, Lovelace, PolicyId}
use cardano/transaction.{Input, OutputReference}

/// Producing-transaction data absent from the proof transaction's context.
/// `outputs_cbor` is the complete CBOR array at body key 1, excluding that key.
/// Both input lists retain their encoded ledger order. `builtin_arguments` is
/// the withdrawal redeemer. `cost_model` is the complete CBOR array for the
/// producing transaction's Plutus V3 language view. The withdrawal credential,
/// pointer and budget are derived from the helper's arguments.
pub type FailedTransactionWitness {
  outputs_cbor: ByteArray,
  fee: Lovelace,
  ordinary_inputs: List<OutputReference>,
  builtin_arguments: Data,
  collateral_input: OutputReference,
  total_collateral: Lovelace,
  reference_inputs: List<OutputReference>,
  redeemer_encoding: RedeemerEncoding,
  cost_model: ByteArray,
}

/// Authenticate a failed withdrawal and mint one proof NFT named by its hash.
///
/// Pass the mint handler's `own_policy` and actual transaction `inputs` and
/// `mint`. `collateral_return_input_index` selects an actual consumed input;
/// its transaction ID and output index authenticate the failure evidence.
/// `withdrawal_script_hash` identifies the agreed probe and its preparation
/// rules. `network_tag` restores address bits omitted from the Plutus context.
/// The body-hash check authenticates the reconstructed address bytes.
///
/// Use the final continuation to check argument preparation without executing
/// the builtin. It runs after the evidence and mint checks.
pub fn validate_mint(
  own_policy: PolicyId,
  withdrawal_script_hash: ScriptHash,
  withdrawal_cpu: Int,
  withdrawal_mem: Int,
  network_tag: Int,
  inputs: List<Input>,
  collateral_return_input_index: Int,
  mint: Assets,
  witness: FailedTransactionWitness,
  validate_builtin_arguments: fn(Data) -> Bool,
) -> Bool {
  let  
      Input {
        output_reference: OutputReference {
          transaction_id: failed_transaction_id,
          output_index: collateral_return_output_index,
        },
        output: collateral_return,
      }
    = inputs |> list.expect_at(collateral_return_input_index)

  expect [Pair(proof_name, quantity)] = mint
    |> assets.tokens(own_policy)
    |> dict.to_pairs
  expect quantity == 1
  expect proof_name == failed_transaction_id

  let  
      FailedTransactionWitness {
        outputs_cbor,
        fee,
        ordinary_inputs,
        builtin_arguments,
        collateral_input,
        total_collateral,
        reference_inputs,
        redeemer_encoding,
        cost_model,
      }
    = witness

  expect collateral_return_output_index == outputs.count(outputs_cbor)

  let serialised_collateral_return = serialise_tx_output(
    collateral_return,
    network_tag,
    False,
  )

  // The sole withdrawal has ledger index zero and is the only phase-2 purpose.
  let serialised_redeemers = []
    |> insert_redeemer_entry(
        3,
        0,
        serialise_plutus_data(builtin_arguments, True),
        serialise_budget(withdrawal_mem, withdrawal_cpu),
      )
    |> serialise_redeemer_entries(redeemer_encoding)
  let script_data_hash = hash_script_data(serialised_redeemers, cost_model, [])

  let reference_field_count, reference_field <- serialise_nonempty_list_field(
    18,
    reference_inputs,
    fn(refs) { serialise_tx_inputs(refs, fn(ref) { ref }) },
  )

  // Eight mandatory fields and the optional reference-input field, in key order.
  let body = serialise_cbor_head(5, 8 + reference_field_count)
    |> bytearray.concat(#"00")
    |> bytearray.concat(serialise_tx_inputs(ordinary_inputs, fn(ref) { ref }))
    |> bytearray.concat(#"01")
    |> bytearray.concat(outputs_cbor)
    |> bytearray.concat(#"02")
    |> bytearray.concat(cbor.serialise(fee))
    |> bytearray.concat(#"05")
    |> bytearray.concat(
        serialise_withdrawals(
          [Pair(Script(withdrawal_script_hash), 0)],
          network_tag,
        ),
      )
    |> bytearray.concat(#"0b")
    |> bytearray.concat(cbor.serialise(script_data_hash))
    |> bytearray.concat(#"0d")
    |> bytearray.concat(
        serialise_tx_inputs([collateral_input], fn(ref) { ref }),
      )
    |> bytearray.concat(#"10")
    |> bytearray.concat(serialised_collateral_return)
    |> bytearray.concat(#"11")
    |> bytearray.concat(cbor.serialise(total_collateral))
    |> bytearray.concat(reference_field)
  expect builtin.blake2b_256(body) == failed_transaction_id

  validate_builtin_arguments(builtin_arguments)
}
