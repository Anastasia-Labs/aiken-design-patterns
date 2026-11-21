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
//// `validate_mint` reconstructs a definite CBOR body map with exactly the
//// following fields, in ascending key order.
////
//// | Key | Producing transaction field |
//// | --- | --- |
//// | 0 | Nonempty ordinary input set, supplied by the witness |
//// | 1 | Zero ordinary outputs, encoded as the definite empty array `80` |
//// | 2 | Fee in lovelace, supplied by the witness |
//// | 5 | One withdrawal from the configured probe's script reward account, for the witness's exact `withdrawal_amount` in lovelace |
//// | 11 | Script-data hash for the single withdrawal redeemer and the Plutus V3 language view |
//// | 13 | Exactly one collateral input, supplied by the witness |
//// | 16 | Collateral return with its address, value, and optional inline datum |
//// | 17 | Total collateral in lovelace, supplied by the witness |
//// | 18 | Reference input set, present only when nonempty |
////
//// Each input set uses CBOR tag 258 around a definite array of
//// `[transaction_id, output_index]` pairs. Ordinary and reference inputs are
//// strictly ascending by transaction ID, then numeric output index. Both the
//// reward account and collateral-return address use the configured network tag.
//// The body omits validity bounds, certificates, the auxiliary-data hash,
//// mint, required signers, the network-ID field, and all governance and
//// treasury fields.
////
//// The complete redeemer collection contains only `Withdraw` at ledger index
//// zero. Its `BuiltinRedeemer` is either `DirectArguments`, carrying builtin
//// arguments as `Data`, or `ReferencedArguments`, carrying indexes into the
//// ordered reference-input list. The caller supplies the agreed withdrawal
//// script hash and exact CPU and memory allowances. Authenticating the complete
//// collection excludes other phase-2 purposes. The ledger validates the
//// necessary key witnesses and native scripts in phase 1.
////
//// The script-data hash commits to either the list or map redeemer encoding,
//// with no datum witnesses. Body field 16 uses the collateral return consumed
//// by the proof transaction. A datum-free return uses `[address, value]`.
//// An inline return uses the definite map
//// `{0: address, 1: value, 2: [1, tag24(datum_cbor)]}`, where CBOR tag 24
//// wraps the serialized Plutus Data as a byte string. The datum uses definite
//// collections and map keys sorted by encoded length, then bytes. Byte strings
//// over 64 bytes use 64-byte chunks with a shorter final chunk as needed.
//// Both forms exclude datum hashes and attached reference scripts. The value
//// is a coin or `[coin, multiasset]` with canonical asset maps.
//// With this body, value conservation requires ordinary input lovelace plus
//// the declared withdrawal to equal the fee. The ledger checks that balance.
////
//// ## Two-transaction proof
////
//// The producing transaction is accepted with `isValid = false` after phase-2
//// failure. The ledger applies only the collateral effects, consuming the
//// collateral input and creating its return. The withdrawal amount records
//// the request. An outright rejected transaction supplies no failure evidence.
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
//// A protocol can lock the return at a Plutus script with inline state. The
//// proof transaction supplies the protocol's spending redeemer and executes
//// its validator. Serializing the state is charged to the proof mint.
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
  ReferencedArguments(List<Int>)
}

/// Producing-transaction data absent from the proof transaction's context.
/// Both input lists retain their encoded order and must be strictly ascending
/// by transaction ID, then numeric output index. `builtin_redeemer` is the
/// complete withdrawal redeemer. `withdrawal_amount` is the lovelace declared
/// for the agreed probe in body field 5. `cost_model` is the complete CBOR array
/// for the producing transaction's Plutus V3 language view.
pub type FailedTransactionWitness {
  fee: Lovelace,
  ordinary_inputs: List<OutputReference>,
  builtin_redeemer: BuiltinRedeemer,
  withdrawal_amount: Lovelace,
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
  resolve_reference_input: fn(Int) -> Data,
) -> Data {
  when builtin_redeemer is {
    DirectArguments(arguments) -> arguments
    ReferencedArguments(indexes) ->
      builtin.list_data(
        collect_reference_arguments(indexes, [], resolve_reference_input),
      )
  }
}

fn collect_reference_arguments(
  indexes: List<Int>,
  seen_indexes: List<Int>,
  resolve_reference_input: fn(Int) -> Data,
) -> List<Data> {
  when indexes is {
    [] -> []
    [index, ..tail] -> {
      expect !list.has(seen_indexes, index)
      [
        resolve_reference_input(index),
        ..collect_reference_arguments(
          tail,
          [index, ..seen_indexes],
          resolve_reference_input,
        )
      ]
    }
  }
}

fn builtin_redeemer_data(builtin_redeemer: BuiltinRedeemer) -> Data {
  when builtin_redeemer is {
    DirectArguments(arguments) -> builtin.constr_data(0, [arguments])
    ReferencedArguments(indexes) ->
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
/// The body-hash check authenticates the return's address, value, and optional
/// inline datum.
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
        withdrawal_amount,
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
    encode_inline_datums: True,
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
          [Pair(Script(withdrawal_script_hash), withdrawal_amount)],
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
