//// # Failure validation
////
//// This pattern mints evidence that a withdrawal validator failed while
//// applying a builtin to arguments committed in a spending input's inline
//// datum. Accepted failure includes a builtin crash, a `False` result, or
//// exhaustion of the withdrawal's prescribed execution budget.
////
//// The spending and withdrawal endpoints share one script hash. The mint
//// authenticates the spending endpoint's acceptance conditions and the
//// withdrawal's invocation setup. Attribution to the withdrawal additionally
//// requires a sufficient spending allowance under the applicable cost model.
////
//// ## Supported transaction shape
////
//// `validate_mint` reconstructs a Plutus V3 transaction with exactly two
//// distinct ordinary inputs in ledger order, one collateral input, one zero
//// withdrawal, any number of reference inputs, ordinary outputs, a fee, a
//// script-data hash, collateral return, and total collateral. An empty
//// reference-input field is omitted. The body has no validity bounds, required
//// signers, metadata hash, network-ID entry, minting, certificates, governance
//// actions, or treasury fields. Datum witnesses are unsupported.
////
//// Ordinary outputs and collateral return are encoded with only address and
//// value. Hash equality authenticates the absence of datums and reference
//// scripts in the actual outputs; those members of supplied outputs are
//// ignored and are not authenticated.
////
//// The complete redeemer collection is `Spend`, followed by `Withdraw`.
//// The spending redeemer is a Boolean: `True` selects input 0 and `False`
//// selects input 1. Its ledger pointer uses that same input index. The sole
//// withdrawal is at the shared script hash, has ledger index 0, and uses
//// `Void` as its redeemer. No other phase-2 purpose is present.
////
//// The mint transaction supplies its actual input and reference-input lists.
//// The helper selects the collateral return from the former and the original
//// script UTxO from the latter, using separate indices. The script UTxO must
//// have the expected payment script hash and an inline datum. The witness
//// supplies only the other ordinary input's output reference. Comparing the
//// two references determines their ledger order, spending pointer, and Boolean
//// redeemer. The other input requires no resolved-output witness: any additional
//// Plutus spending purpose would require another authenticated redeemer, and
//// native-script validation must already have succeeded in phase 1.
////
//// ## Two-transaction proof
////
//// The producing transaction is accepted with `isValid = false` after phase-2
//// failure. Its collateral input is consumed and its collateral-return output
//// is created. Its ordinary inputs remain unspent and its ordinary outputs are
//// not created. Phase-1 validation must still succeed; an outright rejected
//// transaction provides no output to use as failure evidence.
////
//// A later proof-minting transaction consumes that collateral return and
//// references the original script UTxO. Hashing the reconstructed body must
//// reproduce the transaction ID in the selected collateral-return input's
//// output reference. The reconstructed script input is the same UTxO that
//// still exists as a reference input in the mint transaction. A successful
//// producing transaction would have consumed it. Its continued existence
//// therefore proves that the producing transaction failed, so the selected
//// input must be its collateral return. This inference requires the actual
//// current reference-input list and the exact reference used in reconstruction.
////
//// Exactly one token is minted under the caller's policy, named with the failed
//// transaction's hash. Consuming the collateral return prevents repeated use of
//// that evidence. Minting under other policies is unrestricted by this helper.
////
//// ## Authenticating the invocation
////
//// The shared script hash is a caller-supplied parameter identifying the agreed
//// spend/withdraw validator. A proof policy can commit to it as a parameter,
//// giving each builtin script its own policy instance. The helper checks the
//// actual original input's payment credential against this hash and uses the
//// same hash to reconstruct the withdrawal credential.
////
//// Transaction-body reconstruction reuses the governance-validation pattern's
//// CBOR machinery. The witnesses must reproduce the committed bytes under the
//// supported serialization profile. Transaction-ID equality authenticates the
//// body bytes under the hash's collision resistance. The reconstructed
//// script-data hash authenticates the complete redeemer collection, its ledger
//// pointers, redeemer data, exact execution budgets, and language-view cost model.
////
//// These checks establish that the known spending endpoint sees exactly two
//// inputs, its own input selected by the Boolean redeemer, and the sole
//// withdrawal at its own script hash. They also establish the withdrawal's
//// spending-purpose association, Boolean decoding, selected input identity,
//// and inline-datum availability.
////
//// The final continuation receives that actual inline datum as raw `Data`.
//// Its map-entry order, including duplicate keys, is retained by using the
//// resolved datum directly. The caller must validate the builtin argument
//// structure and every preparation step whose failure must be excluded. It
//// must use the preparation rules for the script identified by the parameter.
//// The continuation must not require the builtin itself to succeed. Returning
//// `False` or failing rejects the proof. For Ed25519 verification, checking
//// exactly three byte strings excludes extraction failures while allowing
//// invalid signatures and length errors raised by the builtin itself.
////
//// ## Execution-budget allocation
////
//// The helper takes separate expected CPU and memory counts for spending and
//// withdrawal and authenticates those exact allocations through the script-data
//// hash. The caller must choose a sufficient spending allowance for the known
//// script, supported transaction shape, applicable cost model, and execution
//// rules. The withdrawal receives the remainder of the transaction maximum:
////
//// ```text
//// withdrawal_cpu = maximum_transaction_cpu - fixed_spending_cpu
//// withdrawal_memory = maximum_transaction_memory - fixed_spending_memory
//// ```
////
//// The helper does not obtain protocol parameters, derive maximum allowances,
//// or prove spending-budget sufficiency. The example uses 50,000 memory and
//// 14,000,000 CPU for spending. Measurements under one cost model do not prove
//// sufficiency under other execution rules. A spending budget failure would
//// invalidate attribution to the withdrawal.
////
//// Cost models and maximum transaction allowances are separate protocol
//// parameters. The caller is responsible for the maxima applicable when the
//// producing transaction was accepted, which may differ from those in force
//// when the proof is minted. Supplying and authenticating those maxima is
//// outside this helper's scope.
////
//// With the script identity and invocation authenticated, the continuation's
//// preparation checks satisfied, and the spending allowance sufficient, the
//// proof establishes failure of the intended builtin invocation under the
//// prescribed withdrawal allowance. A builtin crash, `False` result, or
//// exhaustion of that allowance qualifies.

use aiken/builtin
use aiken/cbor
use aiken/collection/dict
use aiken/collection/list
use aiken/crypto.{ScriptHash}
use aiken/primitive/bytearray
use aiken_design_patterns/transaction_serialization.{
  RedeemerEncoding, hash_script_data, insert_redeemer_entry, serialise_budget,
  serialise_cbor_head, serialise_nonempty_list_field, serialise_plutus_data,
  serialise_redeemer_entries, serialise_tx_inputs, serialise_tx_output,
  serialise_tx_outputs, serialise_withdrawals,
}
use cardano/address.{Address, Script}
use cardano/assets.{Assets, Lovelace, PolicyId}
use cardano/transaction.{InlineDatum, Input, Output, OutputReference}
use cardano/transaction/output_reference

/// Producing-transaction data absent from the proof transaction's context.
/// `other_input` identifies the other ordinary input; the script input is
/// selected from the proof transaction's actual reference inputs.
/// `reference_inputs` preserves the producing transaction's encoded order and
/// can be empty. Output `datum` and `reference_script` members are ignored;
/// reconstruction encodes only address and value and authenticates that shape
/// in the actual body. Ignored witness members are not authenticated.
/// `cost_model` is the complete CBOR array for the producing transaction's
/// Plutus V3 language view; the reconstructed hash authenticates its bytes.
/// Budgets come from the helper's arguments. Both redeemers and the zero
/// withdrawal are derived from the input order and shared script hash.
pub type FailedTransactionWitness {
  outputs: List<Output>,
  fee: Lovelace,
  other_input: OutputReference,
  collateral_input: OutputReference,
  total_collateral: Lovelace,
  reference_inputs: List<OutputReference>,
  redeemer_encoding: RedeemerEncoding,
  cost_model: ByteArray,
}

/// Authenticate a failed transaction and mint one proof NFT named by its hash.
///
/// Pass `own_policy` from the mint handler, and pass the current transaction's
/// actual `inputs`, `reference_inputs`, and `mint`. Both indices refer to these
/// current context lists. The original script input is authenticated through
/// the selected reference input, whose payment credential must match
/// `spend_withdraw_script_hash` and whose datum must be inline.
///
/// The script-hash parameter must identify the agreed spend/withdraw validator.
/// The helper establishes its transaction-shape and invocation conditions.
/// Spending success additionally assumes its prescribed CPU and memory
/// allowances suffice under the applicable cost model and execution rules.
/// The caller supplies both purposes' budgets and is responsible for the
/// intended allocation of the transaction maximum. `network_tag` restores the
/// network bits omitted from Plutus addresses when reconstructing output and
/// reward-account bytes; the body-hash check authenticates those bytes.
///
/// Use the final continuation to check preparation of the builtin arguments in
/// the authenticated inline datum, without executing the builtin. It runs after
/// the complete proof and mint checks; returning `False` rejects the proof.
pub fn validate_mint(
  own_policy: PolicyId,
  spend_withdraw_script_hash: ScriptHash,
  spending_cpu: Int,
  spending_mem: Int,
  withdrawal_cpu: Int,
  withdrawal_mem: Int,
  network_tag: Int,
  inputs: List<Input>,
  collateral_return_input_index: Int,
  reference_inputs: List<Input>,
  spending_reference_input_index: Int,
  mint: Assets,
  witness: FailedTransactionWitness,
  validate_builtin_arguments: fn(Data) -> Bool,
) -> Bool {
  let  
      Input {
        output_reference: OutputReference {
          transaction_id: failed_transaction_id,
          ..
        },
        output: collateral_return,
      }
    = inputs |> list.expect_at(collateral_return_input_index)

  expect [Pair(proof_name, quantity)] = mint
    |> assets.tokens(own_policy)
    |> dict.to_pairs
  expect quantity == 1
  expect proof_name == failed_transaction_id

  expect  
      Input {
        output_reference: spending_input_reference,
        output: Output {
          address: Address {
            payment_credential: Script(actual_spending_script_hash),
            ..
          },
          datum: InlineDatum(builtin_arguments),
          ..
        },
      }
    = reference_inputs |> list.expect_at(spending_reference_input_index)
  expect actual_spending_script_hash == spend_withdraw_script_hash

  let  
      FailedTransactionWitness {
        outputs,
        fee,
        other_input,
        collateral_input,
        total_collateral,
        reference_inputs: failed_reference_inputs,
        redeemer_encoding,
        cost_model,
      }
    = witness

  // Ledger input order determines both the spending pointer and its Boolean.
  let own_input_is_first = when
    output_reference.compare(spending_input_reference, other_input)
  is {
    Less -> True
    Greater -> False
    Equal -> fail
  }
  let spending_index = if own_input_is_first {
    0
  } else {
    1
  }
  let failed_inputs = if own_input_is_first {
    [spending_input_reference, other_input]
  } else {
    [other_input, spending_input_reference]
  }

  let _output_count, serialised_outputs <- serialise_tx_outputs(
    outputs,
    network_tag,
    False,
  )
  let serialised_collateral_return = serialise_tx_output(
    collateral_return,
    network_tag,
    False,
  )

  // Authenticating the complete collection excludes any other phase-2 purpose.
  // The singleton withdrawal fixes its ledger index at zero.
  let serialised_redeemers = []
    |> insert_redeemer_entry(
        0,
        spending_index,
        serialise_plutus_data(own_input_is_first, True),
        serialise_budget(spending_mem, spending_cpu),
      )
    |> insert_redeemer_entry(
        3,
        0,
        serialise_plutus_data(Void, True),
        serialise_budget(withdrawal_mem, withdrawal_cpu),
      )
    |> serialise_redeemer_entries(redeemer_encoding)
  let script_data_hash = hash_script_data(serialised_redeemers, cost_model, [])

  let reference_field_count, reference_field <- serialise_nonempty_list_field(
    18,
    failed_reference_inputs,
    fn(refs) { serialise_tx_inputs(refs, fn(ref) { ref }) },
  )

  // Eight mandatory body fields and the optional reference-input field, in
  // canonical key order. Every field boundary is constructed from typed values.
  let body = serialise_cbor_head(5, 8 + reference_field_count)
    |> bytearray.concat(#"00")
    |> bytearray.concat(serialise_tx_inputs(failed_inputs, fn(ref) { ref }))
    |> bytearray.concat(#"01")
    |> bytearray.concat(serialised_outputs)
    |> bytearray.concat(#"02")
    |> bytearray.concat(cbor.serialise(fee))
    |> bytearray.concat(#"05")
    |> bytearray.concat(
        serialise_withdrawals(
          [Pair(Script(spend_withdraw_script_hash), 0)],
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
