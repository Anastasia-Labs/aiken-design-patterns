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
//// ledger order, one collateral input, one zero withdrawal, zero ordinary outputs,
//// a fee, a script-data hash, collateral return, and total collateral. Reference
//// inputs are optional; their field is omitted when empty. The body has no
//// validity bounds, required signers, metadata hash, network-ID entry, minting,
//// certificates, governance actions, or treasury fields. Datum witnesses are
//// unsupported.
////
//// Ordinary and reference inputs must be encoded in strictly ascending order
//// by transaction ID and then numeric output index, matching the order supplied
//// to Plutus V3 scripts. Both witness lists are checked before reconstruction.
////
//// The complete redeemer collection contains only `Withdraw` at ledger index
//// zero. Its `BuiltinRedeemer` is either `DirectArguments`, carrying builtin
//// arguments as `Data`, or `ReferenceArguments`, carrying indexes into the
//// ordered reference-input list. The caller supplies the agreed withdrawal
//// script hash and exact CPU and memory allowances. Authenticating the complete
//// collection excludes other phase-2 purposes; any native scripts must already
//// have succeeded in phase 1.
////
//// The mandatory ordinary-output field is encoded as the canonical empty CBOR
//// array, `80`. The collateral return is reconstructed from the actual consumed
//// output with address and value only, so its authenticated encoding has no
//// datum or reference script. Phase-1 validation establishes fee sufficiency,
//// value conservation and asset balance; the proof does not recheck them.
////
//// ## Two-transaction proof
////
//// The producing transaction is accepted with `isValid = false` after phase-2
//// failure. Its collateral input is consumed and its collateral return is
//// created. Its ordinary inputs remain unspent. An outright rejected transaction
//// supplies no failure evidence.
////
//// The proof transaction consumes the collateral return. Hashing the
//// reconstructed body must reproduce that input's transaction ID. Its output
//// index must be zero, the collateral-return index for a transaction with no
//// ordinary outputs. The existence of this exact output therefore proves
//// failure. In reference mode, each selected original reference input must
//// remain unspent and appear among the proof transaction's reference inputs;
//// proof-input ordering may differ. Direct mode does not need argument inputs
//// to remain available.
////
//// Exactly one token is minted under the caller's policy, named with the failed
//// transaction's hash. Consuming its collateral return prevents repeated use
//// of the evidence. Minting under other policies is unrestricted by this helper.
////
//// ## Authenticating the invocation
////
//// Transaction-ID equality authenticates the body under the hash's collision
//// resistance. The reconstructed script-data hash authenticates the complete
//// redeemer collection, its pointer, full `BuiltinRedeemer`, exact execution
//// budget, and Plutus V3 language-view cost model. Redeemer Data uses the shared
//// serializer's definite collections and chunked long byte strings, preserving
//// map-entry order and duplicate keys. The witness must reproduce the committed
//// bytes.
////
//// The continuation receives the collected builtin arguments as raw `Data`. It
//// must check every preparation step performed by the agreed withdrawal script,
//// without executing the builtin. Reference arguments are gathered in the
//// redeemer's index order from inline datums; indexes must be distinct and
//// in-range, and the configured environment checks the resulting arity and
//// types. Returning `False` or failing rejects the proof. For Ed25519
//// verification, checking exactly three byte strings excludes extraction
//// failures while allowing invalid signatures and length errors raised by the
//// builtin itself.
////
//// ## Execution budget
////
//// The `failure_proof` validator takes the multisig parameters NFT's policy ID
//// as a parameter. Its redeemer selects a reference input carrying exactly that
//// NFT with `failure_parameters_asset_name`, apart from ADA. The inline
//// `FailureParameters` datum supplies `max_mem` and `max_cpu` as the exact
//// withdrawal allowances passed to this helper. The multisig selects these
//// trusted values without numeric bounds or derivation from protocol parameters.
////
//// The proof references the live configuration when it mints. Its budgets must
//// match those committed by the producing transaction; an update can make
//// earlier evidence ineligible. The helper authenticates the caller's exact
//// allowance but does not establish that it equals the transaction maximum.
//// Cost models and maximum allowances are separate parameters, and the
//// parameters applicable to the producing transaction can differ from those
//// applicable when proof is minted.
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
use aiken_design_patterns/transaction_serialization.{
  RedeemerEncoding, hash_script_data, insert_redeemer_entry, serialise_budget,
  serialise_cbor_head, serialise_nonempty_list_field, serialise_plutus_data,
  serialise_redeemer_entries, serialise_tx_inputs, serialise_tx_output,
  serialise_withdrawals,
}
use cardano/address.{Script}
use cardano/assets.{AssetName, Assets, Lovelace, PolicyId}
use cardano/transaction.{InlineDatum, Input, Output, OutputReference}
use cardano/transaction/output_reference

/// Asset name of the singleton NFT carrying `FailureParameters`.
pub const failure_parameters_asset_name: AssetName = "FAILURE_PARAMETERS"

/// Maximum execution budgets selected by the configuration's trusted multisig.
/// The parameters validator checks this inline datum's schema without imposing
/// numeric bounds or deriving the values from protocol parameters.
pub type FailureParameters {
  max_mem: Int,
  max_cpu: Int,
}

/// How a builtin probe obtains the `Data` passed to the configured builtin.
/// Reference indexes select inline datums from the ordered reference-input list.
pub type BuiltinRedeemer {
  DirectArguments(Data)
  ReferenceArguments(List<Int>)
}

/// Producing-transaction data absent from the proof transaction's context.
/// Both input lists retain their encoded order and must be strictly ascending
/// by transaction ID, then numeric output index. `builtin_redeemer` is the
/// complete withdrawal redeemer. `cost_model` is the complete CBOR array for
/// the producing transaction's Plutus V3 language view. The withdrawal
/// credential, pointer and budget are derived from the helper's arguments.
pub type FailedTransactionWitness {
  fee: Lovelace,
  ordinary_inputs: List<OutputReference>,
  builtin_redeemer: BuiltinRedeemer,
  collateral_input: OutputReference,
  total_collateral: Lovelace,
  reference_inputs: List<OutputReference>,
  redeemer_encoding: RedeemerEncoding,
  cost_model: ByteArray,
}

/// Resolve the configured builtin's argument `Data` in a withdrawal context.
/// Direct arguments pass through unchanged. Reference arguments select inline
/// datums from the transaction's reference inputs in the redeemer's order.
/// Only the selected output datums are inspected.
pub fn resolve_builtin_arguments(
  builtin_redeemer: BuiltinRedeemer,
  reference_inputs: List<Input>,
) -> Data {
  resolve_builtin_arguments_with(
    builtin_redeemer,
    list.length(reference_inputs),
    fn(index) {
      let Input { output: Output { datum, .. }, .. } = reference_inputs
        |> list.expect_at(index)
      expect InlineDatum(arguments) = datum
      arguments
    },
  )
}

fn resolve_builtin_arguments_with(
  builtin_redeemer: BuiltinRedeemer,
  reference_input_count: Int,
  resolve_reference_input: fn(Int) -> Data,
) -> Data {
  when builtin_redeemer is {
    DirectArguments(arguments) -> arguments
    ReferenceArguments(indexes) ->
      builtin.list_data(
        collect_reference_arguments(
          indexes,
          reference_input_count,
          resolve_reference_input,
        ),
      )
  }
}

fn collect_reference_arguments(
  indexes: List<Int>,
  reference_input_count: Int,
  resolve_reference_input: fn(Int) -> Data,
) -> List<Data> {
  collect_reference_arguments_with_seen(
    indexes,
    reference_input_count,
    resolve_reference_input,
    [],
  )
}

fn collect_reference_arguments_with_seen(
  indexes: List<Int>,
  reference_input_count: Int,
  resolve_reference_input: fn(Int) -> Data,
  seen_indexes: List<Int>,
) -> List<Data> {
  when indexes is {
    [] -> []
    [index, ..tail] -> {
      expect index >= 0 && index < reference_input_count
      expect !list.has(seen_indexes, index)
      [
        resolve_reference_input(index),
        ..collect_reference_arguments_with_seen(
          tail,
          reference_input_count,
          resolve_reference_input,
          [index, ..seen_indexes],
        )
      ]
    }
  }
}

fn builtin_redeemer_data(builtin_redeemer: BuiltinRedeemer) -> Data {
  when builtin_redeemer is {
    DirectArguments(arguments) -> builtin.constr_data(0, [arguments])
    ReferenceArguments(indexes) ->
      builtin.constr_data(1, [builtin.list_data(reference_index_data(indexes))])
  }
}

fn reference_index_data(indexes: List<Int>) -> List<Data> {
  when indexes is {
    [] -> []
    [index, ..tail] -> [builtin.i_data(index), ..reference_index_data(tail)]
  }
}

fn resolve_proof_reference_argument(
  index: Int,
  failed_reference_inputs: List<OutputReference>,
  proof_reference_inputs: List<Input>,
) -> Data {
  let reference = failed_reference_inputs |> list.expect_at(index)
  let Input { output: Output { datum, .. }, .. } = proof_reference_inputs
    |> list.expect_find(fn(input) { input.output_reference == reference })
  expect InlineDatum(arguments) = datum
  arguments
}

fn expect_ordered_input_references(references: List<OutputReference>) -> Void {
  when references is {
    [] -> Void
    [left, ..tail] ->
      when tail is {
        [] -> Void
        [right, ..] -> {
          expect output_reference.compare(left, right) == Less
          expect_ordered_input_references(tail)
        }
      }
  }
}

/// Authenticate a failed withdrawal and mint one proof NFT named by its hash.
///
/// Pass the mint handler's `own_policy`, actual transaction `inputs`,
/// `reference_inputs`, and `mint`. `collateral_return_input_index` selects an
/// actual consumed input; its transaction ID and output index authenticate the
/// failure evidence. For reference arguments, selected failed-transaction
/// outrefs are matched against these proof-transaction reference inputs.
/// `withdrawal_script_hash` identifies the agreed probe and its preparation
/// rules. `network_tag` restores address bits omitted from the Plutus context.
/// The body-hash check authenticates the reconstructed address bytes.
///
/// Both input lists in `witness` must be strictly ascending by transaction ID
/// and then numeric output index.
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
  reference_inputs: List<Input>,
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

  expect collateral_return_output_index == 0

  expect [Pair(proof_name, quantity)] = mint
    |> assets.tokens(own_policy)
    |> dict.to_pairs
  expect quantity == 1
  expect proof_name == failed_transaction_id

  let  
      FailedTransactionWitness {
        fee,
        ordinary_inputs,
        builtin_redeemer,
        collateral_input,
        total_collateral,
        reference_inputs: failed_reference_inputs,
        redeemer_encoding,
        cost_model,
      }
    = witness

  // These checks may be unnecessary for V4/Dijkstra if the activated script
  // context preserves CBOR input order. Relax them only when the failed
  // transaction's execution rules guarantee that ordering.
  expect_ordered_input_references(ordinary_inputs)
  expect_ordered_input_references(failed_reference_inputs)

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
        serialise_plutus_data(builtin_redeemer_data(builtin_redeemer), True),
        serialise_budget(withdrawal_mem, withdrawal_cpu),
      )
    |> serialise_redeemer_entries(redeemer_encoding)
  let script_data_hash = hash_script_data(serialised_redeemers, cost_model, [])

  let reference_field_count, reference_field <- serialise_nonempty_list_field(
    18,
    failed_reference_inputs,
    fn(refs) { serialise_tx_inputs(refs, fn(ref) { ref }) },
  )

  // Eight mandatory fields and the optional reference-input field, in key order.
  let body = serialise_cbor_head(5, 8 + reference_field_count)
    |> bytearray.concat(#"00")
    |> bytearray.concat(serialise_tx_inputs(ordinary_inputs, fn(ref) { ref }))
    |> bytearray.concat(#"0180")
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

  let builtin_arguments = resolve_builtin_arguments_with(
    builtin_redeemer,
    list.length(failed_reference_inputs),
    fn(index) {
      resolve_proof_reference_argument(
        index,
        failed_reference_inputs,
        reference_inputs,
      )
    },
  )

  validate_builtin_arguments(builtin_arguments)
}
