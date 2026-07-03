use aiken/builtin
use aiken/cbor
use aiken/collection/list
use aiken/crypto.{ScriptHash, VerificationKeyHash}
use aiken/interval
use aiken/primitive/bytearray
use aiken_design_patterns/linked_list
use aiken_scott_utils/types.{Scott3}
use cardano/address.{Address, Inline, Script, VerificationKey}
use cardano/assets.{Lovelace, PolicyId, Value, AssetName}
use cardano/transaction.{
  Datum as CardanoDatum, DatumHash, InlineDatum, Input, NoDatum, Output,
  OutputReference, Transaction,
}

pub const root_key: linked_list.RootKey = "PROPOSALS_ROOT"

pub const node_key_prefix: linked_list.NodeKeyPrefix = "GOVV"

pub const node_key_prefix_length: linked_list.NodeKeyPrefixLength =
  bytearray.length(node_key_prefix)

/// This is dedicated to UTxOs outside the linked list namespace; the ones
/// minted after successful passage of a tied builtin cost change governance
/// proposal.
pub const update_auth_prefix: ByteArray = "AUTH"

pub const update_auth_prefix_length: Int = bytearray.length(update_auth_prefix)

pub type Empty =
  ByteArray

@list
pub type ApprovalCriteria {
  builtin_index: Int,
  initial_builtin_cost: Int,
  acceptance_builtin_cost: Int,
}

/// `required_script_for_final_burn` refers to a withdrawal script that must
/// successfully run in order to burn the final minted `AUTH` NFT.
pub type Proposal {
  proposer: VerificationKeyHash,
  mint_script_data_hash: ByteArray,
  minting_cost_model: ByteArray,
  approval_criteria: ApprovalCriteria,
  spend_cpu: Int,
  spend_mem: Int,
  mint_cpu: Int,
  mint_mem: Int,
  valid_until: Int,
  required_script_for_final_burn: ScriptHash,
}

pub type Datum =
  linked_list.Element<Empty, Proposal>

/// Linked list `Element` has two constructors, reserving indexes of 0 and 1.
/// Hardcoding index 2 for this datatype allows the "dangling" auth UTxOs not to
/// get mingled with element UTxO datums.
@tag(2)
pub type AuthenticatedParamsUpdate {
  script_data_hash: ByteArray,
  cost_model: ByteArray,
  spend_cpu: Int,
  spend_mem: Int,
  mint_cpu: Int,
  mint_mem: Int,
  required_script_for_final_burn: ScriptHash,
}

pub type SpendRedeemer {
  // Spend script delegates its logic to the minting script and performs no
  // other validations.
  DelegateToMint
}

pub type MintRedeemer {
  // Initializing the list for proposals.
  Init { nonce_input_index: Int, root_output_index: Int }
  // Inserting a new proposal node in the list. At mint we must validate that
  // the transaction's cost models has a value at the specified index which is
  // the same as `initial_builtin_cost` and different from the
  // `acceptance_builtin_cost`.
  AddProposal {
    anchor_output_index: Int,
    proposal_node_output_index: Int,
    current_params_ref_input_index: Int,
    ttl: Int,
    collateral_inputs: ByteArray,
    collateral_output: ByteArray,
    collateral_fee: ByteArray,
  }
  // Burning a proposal which its corresponding governance proposal has passed,
  // and minting a dedicated NFT outside list namespace which can later be burnt
  // to update the actual `params`.
  // This endpoint shows that the stored `burn_script_data_hash` includes a
  // cost model which the value at its specified index equals the indicated
  // `acceptance_builtin_cost`.
  MintAuthenticatedParamsUpdate
  // Burning an authenticated update token (which was minted after successful
  // passage of a specified governance proposal).
  ApplyPassedParamsUpdate
  // Retrieval of the proposal deposit by the proposer for proposals that their
  // corresponding governance proposal did not pass, and are past their validity
  // time.
  RemoveExpiredProposal
}

/// Validator for initializing the linked that all proposals will live within.
/// We use a linked list to disallow identical acceptance criteria for multiple
/// proposals. Node keys are derived from builtin index at cost model, its
/// current value, and its new value. So no two identical updates to the cost
/// models can coexist.
pub fn init(
  nonce_input_index: Int,
  root_output_index: Int,
  governance_list_nft_policy: PolicyId,
  tx: Transaction,
) -> Bool {
  let Transaction { inputs, outputs, mint, .. } = tx
  {
    let
      root_address,
      _root_lovelace,
      root_data,
    <-
      linked_list.init(
        nonce_validated: {
          expect Some(_) = inputs |> list.at(nonce_input_index)
          True
        },
        produced_element_output: outputs |> list.expect_at(root_output_index),
        tx_mint: mint,
      )

    // 1. The root UTxO must be produced at an address which its payment cred
    //    is a script with the same hash as the list NFT's.
    expect root_address.payment_credential == Script(governance_list_nft_policy)

    // 2. An empty bytearray is the expected root data.
    expect builtin.un_b_data(root_data) == #""

    // Done.
    True
  }
    |> linked_list.run_root_with(governance_list_nft_policy, root_key)
}

pub fn add_proposal(
  governance_list_nft_policy: PolicyId,
  redeemer: MintRedeemer,
  tx: Transaction,
  validate_params_utxo_and_get_required_deposit: fn(Input, Scott3<PolicyId, AssetName, Int, Bool>) -> Bool,
) -> Bool {
  let Transaction {
    inputs,
    outputs,
    mint,
    reference_inputs,
    extra_signatories,
    fee,
    validity_range,
    id,
    ..
  } = tx

  expect AddProposal {
    anchor_output_index,
    proposal_node_output_index,
    current_params_ref_input_index,
    ttl,
    collateral_inputs,
    collateral_output,
    collateral_fee,
  } = redeemer

  let
    extracted_required_deposit_policy,
    extracted_required_deposit_name,
    extracted_required_deposit_qty,
  <-
    validate_params_utxo_and_get_required_deposit(
      reference_inputs
        |> list.expect_at(current_params_ref_input_index),
    )

  {
    let
      _anchor_input,
      anchor_lovelace_change,
      _anchor_key,
      _anchor_data,
      proposal_lovelace,
      proposal_key,
      proposal_data,
      _link,
    <-
      linked_list.insert_ascending(
        outputs |> list.expect_at(anchor_output_index),
        outputs |> list.expect_at(proposal_node_output_index),
        inputs,
        mint,
      )
    // 1. Lovelace of the anchor element must be preserved.
    expect anchor_lovelace_change >= 0

    // 2. The deposited ADA must be greater than or equal to the required
    //    deposit/bond for making a proposal.
    expect proposal_lovelace >= extracted_proposal_required_deposit

    // 3. Key of the inserted node must be derived from the stored acceptance
    //    criteria.
    expect Proposal {
      proposer,
      mint_script_data_hash,
      minting_cost_model,
      approval_criteria,
      spend_cpu,
      spend_mem,
      mint_cpu,
      mint_mem,
      current_params,
      valid_until,
      ..
    } = proposal_data
    expect proposal_key == node_key(approval_criteria)

    // 4. The specified proposer must have signed the transaction.
    expect extra_signatories |> list.has(proposer)

    // 5. The approval criteria must be valid:
    //    - The builtin's index must be within range
    //    - The new cost must be different from the current value
    let ApprovalCriteria {
      builtin_index,
      initial_builtin_cost,
      acceptance_builtin_cost,
    } = approval_criteria
    let current_builtin_cost =
      minting_cost_model |> builtin_cost_at(builtin_index)
    expect current_builtin_cost != acceptance_builtin_cost
    expect current_builtin_cost == initial_builtin_cost

    // 6. The current set of parameters stored in the proposal datum must match
    //    the reference parameters.
    expect current_params == referenced_params_data

    // 7. The proposal's expiry data must lie in the future.
    expect validity_range |> interval.is_entirely_before(valid_until)

    // 8. Validate the specified script data match the hash.
    expect
      validate_script_data_hash(
        mint_script_data_hash,
        minting_cost_model,
        spend_cpu,
        spend_mem,
        mint_cpu,
        mint_mem,
        redeemer,
      )

    // 9. Validate `mint_script_data_hash` leads to the current transaction ID.
    expect
      id
        |> validate_tx_id_from_script_data_hash(
            mint_script_data_hash,
            inputs,
            reference_inputs,
            outputs,
            fee,
            ttl,
            mint,
            extra_signatories,
            collateral_inputs,
            collateral_output,
            collateral_fee,
          )

    // Done.
    True
  }
    |> linked_list.run_element_with(
        governance_list_nft_policy,
        root_key,
        node_key_prefix,
        node_key_prefix_length,
      )
}

pub fn node_key(approval_criteria: ApprovalCriteria) -> linked_list.NodeKey {
  cbor.serialise(approval_criteria) |> builtin.blake2b_224
}

/// Decodes a given CBOR byte array into an `Int`.
pub fn cbor_int_to_int(cbor_int: ByteArray) -> Int {
  let header = bytearray.at(cbor_int, 0)
  let major_type = header / 32
  let additional_info = header % 32

  expect major_type == 0 || major_type == 1

  let n, next_cursor <- cbor_int_payload(cbor_int, 0, additional_info)

  expect next_cursor == bytearray.length(cbor_int)

  let is_canonical =
    if additional_info == 24 {
      n >= 24
    } else if additional_info == 25 {
      n >= 256
    } else if additional_info == 26 {
      n >= 65536
    } else if additional_info == 27 {
      n >= 4294967296
    } else {
      True
    }

  expect is_canonical

  if major_type == 0 {
    n
  } else {
    -1 - n
  }
}

pub fn builtin_cost_at(cost_model: ByteArray, index: Int) -> Int {
  let length, cursor <- process_cost_model_header(cost_model)

  expect index >= 0
  expect index < length

  do_builtin_cost_at(cost_model, cursor, 0, index)
}

pub fn validate_script_data_hash(
  script_data_hash: ByteArray,
  cost_model: ByteArray,
  spend_cpu: Int,
  spend_mem: Int,
  mint_cpu: Int,
  mint_mem: Int,
  mint_redeemer: MintRedeemer,
) -> Bool {
  let spend_redeemer: SpendRedeemer = DelegateToMint

  let redeemers =
    #"a2"
      |> bytearray.concat(#"820000")
      |> bytearray.concat(
          serialise_list_of_two(
            cbor.serialise(spend_redeemer),
            serialise_budget(spend_mem, spend_cpu),
          ),
        )
      |> bytearray.concat(#"820100")
      |> bytearray.concat(
          serialise_list_of_two(
            cbor.serialise(mint_redeemer),
            serialise_budget(mint_mem, mint_cpu),
          ),
        )

  let language_views = #"a102" |> bytearray.concat(cost_model)

  builtin.blake2b_256(bytearray.concat(redeemers, language_views)) == script_data_hash
}

/// Transaction-body reconstruction is primarily referenced from Effectstream's
/// inverse-whirlpool implementation at:
/// https://github.com/effectstream/effectstream/blob/0b70d63a217676ce52748a2cd267f5cbed1109e4/packages/cardano-contracts/inverse-whirlpool/validators/whirl.ak#L261-L291
/// https://github.com/effectstream/effectstream/blob/0b70d63a217676ce52748a2cd267f5cbed1109e4/packages/cardano-contracts/inverse-whirlpool/lib/inverse_whirlpool/conversion.ak#L12-L126
pub fn validate_tx_id_from_script_data_hash(
  tx_id: ByteArray,
  script_data_hash: ByteArray,
  inputs: List<Input>,
  reference_inputs: List<Input>,
  outputs: List<Output>,
  fee: Lovelace,
  ttl: Int,
  mint: Value,
  extra_signatories: List<VerificationKeyHash>,
  collateral_inputs: ByteArray,
  collateral_output: ByteArray,
  collateral_fee: ByteArray,
) -> Bool {
  let tx_body =
    #"ab"
      |> bytearray.concat(#"00")
      |> bytearray.concat(serialise_tx_inputs(inputs))
      |> bytearray.concat(#"01")
      |> bytearray.concat(serialise_tx_outputs(outputs))
      |> bytearray.concat(#"02")
      |> bytearray.concat(cbor.serialise(fee))
      |> bytearray.concat(#"03")
      |> bytearray.concat(cbor.serialise(ttl))
      |> bytearray.concat(#"09")
      |> bytearray.concat(cbor.serialise(assets.to_dict(mint)))
      |> bytearray.concat(#"0b")
      |> bytearray.concat(cbor.serialise(script_data_hash))
      |> bytearray.concat(#"0d")
      |> bytearray.concat(collateral_inputs)
      |> bytearray.concat(#"0e")
      |> bytearray.concat(serialise_extra_signatories(extra_signatories))
      |> bytearray.concat(#"10")
      |> bytearray.concat(collateral_output)
      |> bytearray.concat(#"11")
      |> bytearray.concat(collateral_fee)
      |> bytearray.concat(#"12")
      |> bytearray.concat(serialise_tx_inputs(reference_inputs))

  builtin.blake2b_256(tx_body) == tx_id
}

// ## Internal Helpers

fn serialise_list_of_two(
  serialised_elem_0: ByteArray,
  serialised_elem_1: ByteArray,
) -> ByteArray {
  #"82"
    |> bytearray.concat(serialised_elem_0)
    |> bytearray.concat(serialised_elem_1)
}

fn serialise_budget(mem: Int, cpu: Int) -> ByteArray {
  serialise_list_of_two(cbor.serialise(mem), cbor.serialise(cpu))
}

fn serialise_tx_inputs(inputs: List<Input>) -> ByteArray {
  let
    length,
    body,
  <-
    list.foldr2(
      inputs,
      0,
      "",
      fn(input, length, body, return) {
        return(
          length + 1,
          bytearray.concat(
            serialise_output_reference(input.output_reference),
            body,
          ),
        )
      },
    )

  serialise_definite_list(length, body)
}

fn serialise_output_reference(ref: OutputReference) -> ByteArray {
  let OutputReference { transaction_id, output_index } = ref

  #"82"
    |> bytearray.concat(cbor.serialise(transaction_id))
    |> bytearray.concat(cbor.serialise(output_index))
}

fn serialise_tx_outputs(outputs: List<Output>) -> ByteArray {
  let
    length,
    body,
  <-
    list.foldr2(
      outputs,
      0,
      "",
      fn(output, length, body, return) {
        return(length + 1, bytearray.concat(serialise_tx_output(output), body))
      },
    )

  serialise_definite_list(length, body)
}

fn serialise_tx_output(output: Output) -> ByteArray {
  let Output { address, value, datum, .. } = output

  let datum_count, datum_bytes <- serialise_output_datum(datum)

  // Outputs with reference scripts are implicitly rejected: this reconstruction
  // omits tx-output field 3, so such transactions will not match their tx id.
  builtin.cons_bytearray(0x82 + datum_count, serialise_address(address))
    |> bytearray.concat(serialise_output_value(value))
    |> bytearray.concat(datum_bytes)
}

fn serialise_output_datum(
  datum: CardanoDatum,
  return: fn(Int, ByteArray) -> result,
) -> result {
  when datum is {
    NoDatum -> return(0, "")
    DatumHash(_) -> fail @"datum hashes cannot be recovered"
    InlineDatum(data) -> return(1, cbor.serialise(data))
  }
}

fn serialise_output_value(value: Value) -> ByteArray {
  let lovelace = value |> assets.lovelace_of |> cbor.serialise
  let non_ada = value |> assets.without_lovelace |> assets.to_dict
  let multi_asset = cbor.serialise(non_ada)

  if multi_asset == #"a0" {
    lovelace
  } else {
    #"82" |> bytearray.concat(lovelace) |> bytearray.concat(multi_asset)
  }
}

fn serialise_address(address: Address) -> ByteArray {
  let Address { payment_credential, stake_credential } = address

  let payment_header, payment_credential_bytes <-
    when payment_credential is {
      Script(credential) ->
        fn(return) { return(16, credential) }
      VerificationKey(credential) ->
        fn(return) { return(0, credential) }
    }

  let stake_header, stake_credential_bytes <-
    when stake_credential is {
      None ->
        fn(return) { return(96, "") }
      Some(Inline(VerificationKey(credential))) ->
        fn(return) { return(0, credential) }
      Some(Inline(Script(credential))) ->
        fn(return) { return(32, credential) }
      _ -> fail @"pointer stake credentials cannot be recovered"
    }

  builtin.cons_bytearray(
    payment_header + stake_header,
    bytearray.concat(payment_credential_bytes, stake_credential_bytes),
  )
    |> cbor.serialise
}

fn serialise_extra_signatories(
  extra_signatories: List<VerificationKeyHash>,
) -> ByteArray {
  let
    length,
    body,
  <-
    list.foldr2(
      extra_signatories,
      0,
      "",
      fn(signature, length, body, return) {
        return(length + 1, bytearray.concat(cbor.serialise(signature), body))
      },
    )

  serialise_definite_list(length, body)
}

fn serialise_definite_list(length: Int, body: ByteArray) -> ByteArray {
  // This reconstruction only supports short tx inputs, reference inputs,
  // outputs, and extra-signatory lists. Ledger-valid lists of 24 or more
  // entries are rejected instead of being reconstructed.
  if length < 24 {
    builtin.cons_bytearray(0x80 + length, body)
  } else {
    fail @"list too long"
  }
}

fn process_cost_model_header(
  cost_model: ByteArray,
  return: fn(Int, Int) -> result,
) -> result {
  let header = bytearray.at(cost_model, 0)

  if header >= 0x80 && header <= 0x97 {
    return(header - 0x80, 1)
  } else if header == 0x98 {
    return(bytearray.at(cost_model, 1), 2)
  } else if header == 0x99 {
    return(bytearray.slice(cost_model, 1, 2) |> bytearray.to_int_big_endian, 3)
  } else {
    fail @"invalid cost model array"
  }
}

fn cbor_int_payload(
  cost_model: ByteArray,
  cursor: Int,
  additional_info: Int,
  return: fn(Int, Int) -> result,
) -> result {
  if additional_info < 24 {
    return(additional_info, cursor + 1)
  } else if additional_info == 24 {
    return(bytearray.at(cost_model, cursor + 1), cursor + 2)
  } else if additional_info == 25 {
    return(
      bytearray.slice(cost_model, cursor + 1, cursor + 2)
        |> bytearray.to_int_big_endian,
      cursor + 3,
    )
  } else if additional_info == 26 {
    return(
      bytearray.slice(cost_model, cursor + 1, cursor + 4)
        |> bytearray.to_int_big_endian,
      cursor + 5,
    )
  } else if additional_info == 27 {
    return(
      bytearray.slice(cost_model, cursor + 1, cursor + 8)
        |> bytearray.to_int_big_endian,
      cursor + 9,
    )
  } else {
    fail @"invalid cbor integer"
  }
}

fn do_builtin_cost_at(
  cost_model: ByteArray,
  cursor: Int,
  current_index: Int,
  target_index: Int,
) -> Int {
  let header = bytearray.at(cost_model, cursor)
  let major_type = header / 32
  let additional_info = header % 32

  expect major_type == 0 || major_type == 1

  if current_index == target_index {
    // This intentionally accepts any CBOR integer encoding that decodes to the
    // selected cost, without re-checking canonical/minimal integer form. The
    // exact cost-model bytes are authenticated separately by script_data_hash.
    let n, _next_cursor <- cbor_int_payload(cost_model, cursor, additional_info)
    if major_type == 0 {
      n
    } else {
      -1 - n
    }
  } else {
    let next_cursor =
      if additional_info < 24 {
        cursor + 1
      } else if additional_info == 24 {
        cursor + 2
      } else if additional_info == 25 {
        cursor + 3
      } else if additional_info == 26 {
        cursor + 5
      } else if additional_info == 27 {
        cursor + 9
      } else {
        fail @"invalid cost model integer"
      }

    do_builtin_cost_at(cost_model, next_cursor, current_index + 1, target_index)
  }
}
