//// # Failure validation
////
//// This pattern mints evidence that a small withdrawal
//// validator failed on a particular redeemer. The withdrawal isolates a single
//// builtin call. Accepted failure includes a crash, a `False` result, or
//// exhaustion of the withdrawal's prescribed execution budget.
////
//// The proof authenticates the failed transaction and checks the conditions
//// under which its spending validator is expected to succeed. Attribution to
//// the withdrawal relies on the configured spending allowance being sufficient.
////
//// ## Supported transaction shape
////
//// `validate_mint` reconstructs a Plutus V3 transaction with one ordinary
//// spending input, one collateral input, one zero withdrawal, any number of
//// reference inputs, ordinary outputs, a fee, a script-data hash, collateral
//// return, and total collateral. An empty reference-input field is omitted.
//// Both redeemer indices are zero. Ordinary outputs and
//// collateral return are encoded with only address and value. Hash equality
//// authenticates the absence of datums and reference scripts in the actual
//// outputs; those members of supplied outputs are ignored. Datum witnesses are
//// unsupported. The body has no validity bounds, required signers, metadata
//// hash, network-ID entry, minting, certificates, governance actions, or
//// treasury fields.
////
//// The mint transaction supplies its actual input and reference-input lists.
//// The helper selects the collateral return from the former and the original
//// spending UTxO from the latter, using separate indices. Thus the original
//// spending UTxO must remain unspent until the proof transaction is accepted.
////
//// Exactly one token is minted under the caller's policy, named with the failed
//// transaction's hash. Consuming the collateral return prevents repeated use of
//// that evidence, while the asset name distinguishes individual failed attempts.
//// Minting under other policies is unrestricted by this helper.
////
//// ## Two-transaction proof
////
//// The producing transaction has exactly two redeemers, in ledger order:
//// `Spend`, followed by `Withdraw`. It has exactly one withdrawal, whose script
//// credential identifies the intended builtin validator. The spending validator
//// is a known, small script that checks this shape and the withdrawal's identity.
////
//// The producing transaction is accepted with `isValid = false` after phase-2
//// failure. Its collateral inputs are consumed and its collateral-return output
//// is created. Its ordinary outputs are not created. Phase-1 validation must
//// still succeed; an outright rejected transaction provides no output to use as
//// failure evidence.
////
//// A later proof-minting transaction consumes that collateral return. The proof
//// selects an input by its index in the minting transaction's actual inputs,
//// then reconstructs the transaction that produced it. Hashing the reconstructed
//// body must reproduce the transaction ID in the selected input's output
//// reference. The reconstructed ordinary input is the same UTxO that still
//// exists as a reference input in the mint transaction. A successful producing
//// transaction would have consumed it. Its continued existence therefore proves
//// that the producing transaction failed, so the selected input must be its
//// collateral return. This inference requires the actual current reference-input
//// list and the exact output reference used in reconstruction.
////
//// ## Reconstructing authenticated evidence
////
//// Reconstruction follows the governance-validation module's transaction-body
//// and script-data-hash authentication, reusing its CBOR serialization machinery
//// wherever applicable. The witnesses must reproduce the committed bytes under
//// the supported serialization profile. Transaction-ID equality authenticates
//// those body bytes under the hash's collision resistance.
////
//// Reconstructing the script-data hash also authenticates the complete redeemer
//// collection, including its ledger pointers, redeemer data, execution budgets,
//// and the cost models in its language views. The proof must bind that hash into
//// the reconstructed body. Supplying two claimed redeemers without authenticating
//// the complete collection would not establish the required transaction shape.
//// The withdrawal redeemer retains its map-entry order at every depth, including
//// duplicate-key entries. This ensures the continuation sees the same Data
//// ordering as the failed execution.
////
//// The mint checks the two-redeemer shape, the sole withdrawal credential, and
//// the association of each redeemer with its intended purpose. For the example
//// spending validator, reconstruction uses the expected withdrawal script hash
//// directly as the spending redeemer. Hash equality authenticates that exact
//// redeemer value and its type. Together with the sole withdrawal and the known
//// spending-script instance, this establishes the spending validator's logical
//// acceptance conditions at proof minting.
////
//// The spending-script identity also requires authenticating the output that
//// the producing transaction attempted to spend. Its body contains that output's
//// reference; the address and other resolved output contents belong to the
//// referenced output's own producing transaction. For example, the proof-minting
//// transaction can include the original, still-unspent output as a reference
//// input, match its reference to the reconstructed spending purpose, and check
//// its actual payment script hash. Resolved output contents supplied as witness
//// data require their own authentication before they can establish script identity.
////
//// ## Withdrawal redeemer validation
////
//// The reconstructed withdrawal redeemer is available to the minting validator.
//// The withdrawal can accept raw `Data`, and the mint checks the structure and
//// any application-specific preconditions needed to make the observed failure
//// meaningful for the intended builtin operation.
////
//// Raw `Data` avoids an automatic custom-type decoding requirement at the
//// withdrawal boundary. Preparing arguments for a builtin can still involve
//// extraction or conversion operations. The mint's checks must rule out any
//// failures in that preparation which the application does not intend to count.
//// A crash or `False` result from the intended operation is valid failure
//// evidence. Exhaustion of the withdrawal's full prescribed allowance is also
//// an accepted outcome; the proof does not need to distinguish these causes.
////
//// The known withdrawal script must correctly execute the intended operation
//// under the supported execution rules. Its wrapper and handling of ordinary
//// results must agree with the failure conditions accepted by the mint.
////
//// ## Execution-budget allocation
////
//// Generation measures the spending validator's CPU and memory costs and
//// doubles the estimates to choose a fixed spending allowance. The mint requires
//// the producing transaction's spending redeemer to declare exactly that pair.
//// The withdrawal receives the remainder of the maximum transaction budget,
//// independently for each resource:
////
//// ```text
//// withdrawal_cpu = maximum_transaction_cpu - fixed_spending_cpu
//// withdrawal_memory = maximum_transaction_memory - fixed_spending_memory
//// ```
////
//// The helper takes the four expected CPU and memory counts as separate trusted
//// arguments and authenticates those exact allocations through the reconstructed
//// script-data hash. The caller is responsible for choosing them so their sums
//// consume the applicable transaction maximum for each resource. The helper
//// does not obtain protocol parameters or derive maximum allowances.
////
//// The doubled spending estimate is an accepted engineering compromise. The
//// design assumes it suffices for the authenticated spending script, supported
//// transaction shapes, and applicable cost model and execution rules. This
//// empirical margin does not establish a worst-case upper bound. A spending
//// failure within that allowance would invalidate attribution to the withdrawal.
////
//// Cost models describe the costs of operations. The maximum transaction CPU
//// and memory allowances are separate protocol parameters and cannot be recovered
//// from the cost-model array. The proof therefore needs trustworthy maximum
//// budgets applicable when the failed transaction was accepted. These may differ
//// from the limits in force when the proof is minted. The mechanism supplying
//// and authenticating those maxima is left unspecified by this design.
////
//// The ledger enforces the transaction-wide sum of declared execution budgets:
//// https://github.com/IntersectMBO/cardano-ledger/blob/master/eras/alonzo/impl/src/Cardano/Ledger/Alonzo/Rules/Utxo.hs
////
//// ## Resulting guarantee
////
//// With the intended scripts authenticated, the redeemer and transaction checks
//// satisfied, and the spending allowance sufficient, the collateral-return proof
//// establishes that the intended withdrawal failed on the authenticated redeemer
//// under the prescribed allocation. The withdrawal receives the maximum budget
//// remaining after the fixed spending allowance. Crashes, `False` results, and
//// exhaustion of that remaining budget all qualify as failure for this pattern.

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
use cardano/transaction.{Input, Output, OutputReference, Redeemer}

/// Producing-transaction data absent from the proof transaction's context.
/// `reference_inputs` preserves the producing transaction's encoded order and
/// can be empty. Output `datum` and `reference_script` members are ignored;
/// reconstruction encodes only address and value and authenticates that shape
/// in the actual body. Ignored witness members are not authenticated.
/// `cost_model` is the complete CBOR array for the producing transaction's
/// Plutus V3 language view; the reconstructed hash authenticates its bytes.
/// Map-entry order within withdrawal redeemer Data is preserved during serialization.
///
/// The ordinary spending input and collateral-return output come from the real
/// reference input and spending input selected by `validate_mint`. Budgets come
/// from its trusted arguments, and the withdrawal is fixed to zero at its
/// expected withdrawal-script hash. That hash also supplies the spending redeemer.
pub type FailedTransactionWitness {
  outputs: List<Output>,
  fee: Lovelace,
  collateral_input: OutputReference,
  total_collateral: Lovelace,
  reference_inputs: List<OutputReference>,
  withdrawal_redeemer: Redeemer,
  redeemer_encoding: RedeemerEncoding,
  cost_model: ByteArray,
}

/// Authenticate a failed transaction and mint one proof NFT named by its hash.
///
/// Pass `own_policy` from the mint handler, and pass the current transaction's
/// actual `inputs`, `reference_inputs`, and `mint`. Both indices refer to these
/// current context lists. The original spending input is authenticated through
/// the selected reference input, whose payment credential must match the trusted
/// `spending_script_hash`.
///
/// That hash must identify the agreed spending validator parameterized by
/// `withdrawal_script_hash`. The helper verifies its transaction-shape and
/// spending-redeemer conditions. Spending success additionally assumes its
/// prescribed CPU and memory allowances suffice under the applicable cost model
/// and execution rules. The caller supplies both scripts' expected budgets and
/// is responsible for the intended allocation of the transaction maximum.
/// `network_tag` is also trusted configuration: it restores the network bits
/// omitted from Plutus addresses when reconstructing output and reward-account
/// bytes. The body-hash check authenticates those reconstructed bytes.
///
/// Use the final continuation to validate the authenticated withdrawal redeemer's
/// structure and application-specific preconditions. It runs after the complete
/// proof and mint checks; returning `False` rejects the proof.
pub fn validate_mint(
  own_policy: PolicyId,
  spending_script_hash: ScriptHash,
  withdrawal_script_hash: ScriptHash,
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
  validate_withdrawal_redeemer: fn(Redeemer) -> Bool,
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
          ..
        },
      }
    = reference_inputs |> list.expect_at(spending_reference_input_index)
  expect actual_spending_script_hash == spending_script_hash

  let
      FailedTransactionWitness {
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

  // The singleton ordinary input and withdrawal fix both ledger indices at zero.
  // Authenticating this complete collection also excludes any other redeemer.
  let serialised_redeemers = []
    |> insert_redeemer_entry(
        0,
        0,
        serialise_plutus_data(withdrawal_script_hash, True),
        serialise_budget(spending_mem, spending_cpu),
      )
    |> insert_redeemer_entry(
        3,
        0,
        serialise_plutus_data(withdrawal_redeemer, True),
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
    |> bytearray.concat(
        serialise_tx_inputs([spending_input_reference], fn(ref) { ref }),
      )
    |> bytearray.concat(#"01")
    |> bytearray.concat(serialised_outputs)
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

  validate_withdrawal_redeemer(withdrawal_redeemer)
}
