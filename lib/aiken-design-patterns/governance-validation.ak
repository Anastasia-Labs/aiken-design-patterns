use aiken/builtin
use aiken/cbor
use aiken/collection/dict
use aiken/collection/list
use aiken/crypto.{ScriptHash, VerificationKeyHash}
use aiken/interval
use aiken/primitive/bytearray
use aiken_design_patterns/linked_list
use aiken_design_patterns/linked_list/advanced as advanced_linked_list
use aiken_design_patterns/linked_list/internal.{
  validate_singular_authentic_input_helper,
}
use aiken_design_patterns/stake_validator
use cardano/address.{Address, Inline, Script, VerificationKey}
use cardano/assets.{Lovelace, PolicyId, Value}
use cardano/transaction.{
  DatumHash, InlineDatum, Input, NoDatum, Output, OutputReference, Transaction,
}

pub const root_key: linked_list.RootKey = "PROPOSALS_ROOT"

pub const node_key_prefix: linked_list.NodeKeyPrefix = "GOVV"

pub const node_key_prefix_length: linked_list.NodeKeyPrefixLength =
  bytearray.length(node_key_prefix)

/// This is dedicated to UTxOs outside the linked list namespace; the ones
/// minted after successful passage of a tied builtin cost change governance
/// proposal.
pub const pass_nft_prefix: ByteArray = "PASS"

pub const pass_nft_prefix_length: Int = bytearray.length(pass_nft_prefix)

pub type Empty =
  ByteArray

@list
pub type ApprovalCriteria {
  builtin_index: Int,
  initial_builtin_cost: Int,
  acceptance_builtin_cost: Int,
}

/// `required_script_for_final_burn` refers to a withdrawal script that must
/// successfully run in order to burn the final minted `PASS` NFT.
pub type Proposal {
  proposer: Address,
  mint_script_data_hash: ByteArray,
  spend_redeemer_index: Int,
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
pub type PassedProposal {
  proposer: Address,
  script_data_hash: ByteArray,
  anchor_spend_redeemer_index: Int,
  proposal_spend_redeemer_index: Int,
  cost_model: ByteArray,
  anchor_spend_cpu: Int,
  anchor_spend_mem: Int,
  proposal_spend_cpu: Int,
  proposal_spend_mem: Int,
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
  // `acceptance_builtin_cost`. `ttl` must be equal to the transaction's `ttl`
  // slot number. This is needed since the contract's endpoint requires the
  // deadline to be sometime in the future.
  AddProposal {
    anchor_output_index: Int,
    proposal_node_output_index: Int,
    ttl: Int,
    collateral_inputs: ByteArray,
    collateral_output: ByteArray,
    collateral_fee: ByteArray,
  }
  // Burning a proposal which its corresponding governance proposal has passed,
  // and minting a dedicated NFT outside list namespace which can later be burnt
  // so that the script declared at proposal can be executed.
  MintProposalPassNFT {
    anchor_input_outref: OutputReference,
    anchour_output_index: Int,
    passage_utxo_output_index: Int,
    collateral_inputs: ByteArray,
    collateral_output: ByteArray,
    collateral_fee: ByteArray,
  }
  // Burning a `PASS` token (which was minted after successful passage of a
  // specified governance proposal) while running the embedded withdrawal
  // script. Since this endpoint does not utilize mint helpers from the linked
  // list module, it is important to scan the inputs and ensure no other UTxOs
  // with the governance policy ID are spent.
  FinalizePassedProposal {
    proposer_output_index: Int,
    proposals_withdrawal_script_index: Int,
  }
  // Retrieval of the proposal deposit by the proposer for proposals that their
  // corresponding governance proposal did not pass, and are past their validity
  // time.
  RemoveExpiredProposal {
    anchor_input_outref: OutputReference,
    anchor_output_index: Int,
  }
}

/// Validator for initializing the linked that all proposals will live within.
/// We use a linked list to disallow identical acceptance criteria for multiple
/// proposals. Node keys are derived from builtin index at cost model, its
/// current value, and its new value. So no two identical updates to the cost
/// models can coexist.
pub fn init(
  nonce: OutputReference,
  nonce_input_index: Int,
  root_output_index: Int,
  governance_nft_policy: PolicyId,
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
          let input = inputs |> list.expect_at(nonce_input_index)
          input.output_reference == nonce
        },
        produced_element_output: outputs |> list.expect_at(root_output_index),
        tx_mint: mint,
      )

    // 1. The root UTxO must be produced at an address which its payment cred
    //    is a script with the same hash as the list NFT's.
    expect root_address.payment_credential == Script(governance_nft_policy)

    // 2. An empty bytearray is the expected root data.
    expect builtin.un_b_data(root_data) == #""

    // Done.
    True
  }
    |> linked_list.run_root_with(governance_nft_policy, root_key)
}

pub fn add_proposal(
  anchor_output_index: Int,
  proposal_node_output_index: Int,
  ttl: Int,
  collateral_inputs: ByteArray,
  collateral_output: ByteArray,
  collateral_fee: ByteArray,
  redeemer: MintRedeemer,
  governance_nft_policy: PolicyId,
  tx: Transaction,
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

  {
    let
      _anchor_input,
      anchor_lovelace_change,
      _anchor_key,
      _anchor_data,
      _proposal_node_lovelace,
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

    // 2. Key of the inserted node must be derived from the stored acceptance
    //    criteria.
    expect Proposal {
      proposer,
      mint_script_data_hash,
      spend_redeemer_index,
      minting_cost_model,
      approval_criteria,
      spend_cpu,
      spend_mem,
      mint_cpu,
      mint_mem,
      valid_until,
      ..
    } = proposal_data
    expect proposal_key == node_key(approval_criteria)

    // 3. The specified proposer must have consented to the transaction.
    expect proposer |> address_consented(extra_signatories)

    // 4. The approval criteria must be valid:
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

    // 5. The proposal's expiry date must lie in the future.
    expect validity_range |> interval.is_entirely_before(valid_until)

    // 6. Validate the specified script data matches the hash.
    expect
      validate_add_proposal_script_data_hash(
        mint_script_data_hash,
        minting_cost_model,
        spend_cpu,
        spend_mem,
        mint_cpu,
        mint_mem,
        spend_redeemer_index,
        redeemer,
      )

    // 7. Validate `mint_script_data_hash` leads to the current transaction ID.
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
        governance_nft_policy,
        root_key,
        node_key_prefix,
        node_key_prefix_length,
      )
}

pub fn mint_proposal_pass_nft(
  anchor_input_outref: OutputReference,
  anchour_output_index: Int,
  passage_utxo_output_index: Int,
  collateral_inputs: ByteArray,
  collateral_output: ByteArray,
  collateral_fee: ByteArray,
  redeemer: MintRedeemer,
  governance_nft_policy: PolicyId,
  tx: Transaction,
) -> Bool {
  let Transaction {
    inputs,
    outputs,
    mint,
    reference_inputs,
    extra_signatories,
    fee,
    id,
    ..
  } = tx

  let continued_anchor_output = outputs |> list.expect_at(anchour_output_index)

  expect Output {
    address: passage_utxo_address,
    value: passage_utxo_value,
    datum: InlineDatum(pass_datum_data),
    reference_script: None,
  } = outputs |> list.expect_at(passage_utxo_output_index)

  // 1. Produced passage UTxO must have a properly shaped datum attached.
  expect PassedProposal {
    proposer,
    script_data_hash,
    anchor_spend_redeemer_index,
    proposal_spend_redeemer_index,
    cost_model,
    anchor_spend_cpu,
    anchor_spend_mem,
    proposal_spend_cpu,
    proposal_spend_mem,
    mint_cpu,
    mint_mem,
    required_script_for_final_burn: passage_required_script_for_final_burn,
  } = pass_datum_data

  {
    let
      _anchor_input,
      anchor_element_lovelace_change,
      _anchor_key,
      root_data,
      cont_root_data,
      removing_node_input,
      removing_node_lovelace,
      removing_node_key,
      removing_node_data,
      _removing_node_link,
      other_list_asset_changes,
    <-
      advanced_linked_list.remove(
        anchor_input_outref,
        continued_anchor_output,
        inputs,
        mint,
      )

    let Input { output: Output { address: removing_node_address, .. }, .. } =
      removing_node_input

    // 2. The new `PASS` UTxO must go to the same address as its proposal UTxO.
    expect removing_node_address == passage_utxo_address

    // 3. ADA of the anchor must be preserved.
    expect anchor_element_lovelace_change >= 0

    // 4. Underlying data of the anchor must not change.
    expect root_data == cont_root_data

    // 5. There must be exactly one other mint under list policy (aside from the
    //    node's burn).
    expect [Pair(minted_pass_nft_name, 1)] =
      other_list_asset_changes |> dict.to_pairs

    // 6. The new UTxO must carry the `PASS` NFT, plus some ADA greater than or
    //    equal to the removing node's (no other tokens are allowed).
    expect
      passage_utxo_value
        |> assets.has_nft_strict(governance_nft_policy, minted_pass_nft_name)
    expect assets.lovelace_of(passage_utxo_value) >= removing_node_lovelace

    // 7. New NFT's asset name must be equal to the removed node's, but with the
    //    `PASS` prefix rather than the node key prefix.
    expect
      minted_pass_nft_name == bytearray.concat(
        pass_nft_prefix,
        removing_node_key,
      )

    // 8. The new builtin cost must match the initially stated approval
    //    criteria. The proposer, and the passage withdrawal script must also
    //    carry over to the new UTxO.
    expect Proposal {
      proposer: original_proposer,
      approval_criteria,
      required_script_for_final_burn,
      ..
    } = removing_node_data
    expect original_proposer == proposer
    let ApprovalCriteria { builtin_index, acceptance_builtin_cost, .. } =
      approval_criteria
    expect acceptance_builtin_cost == builtin_cost_at(cost_model, builtin_index)
    expect
      required_script_for_final_burn == passage_required_script_for_final_burn

    // 9. Validate the specified script data match the hash.
    expect
      validate_pass_script_data_hash(
        script_data_hash,
        cost_model,
        anchor_spend_cpu,
        anchor_spend_mem,
        proposal_spend_cpu,
        proposal_spend_mem,
        mint_cpu,
        mint_mem,
        anchor_spend_redeemer_index,
        proposal_spend_redeemer_index,
        redeemer,
      )

    // 10. Validate `script_data_hash` leads to the current transaction ID.
    expect
      id
        |> validate_tx_id_from_script_data_hash_without_ttl(
            script_data_hash,
            inputs,
            reference_inputs,
            outputs,
            fee,
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
        governance_nft_policy,
        root_key,
        node_key_prefix,
        node_key_prefix_length,
      )
}

pub fn finalize_passed_proposal(
  proposer_output_index: Int,
  proposals_withdrawal_script_index: Int,
  governance_nft_policy: PolicyId,
  tx: Transaction,
) -> Bool {
  let Transaction { inputs, outputs, mint, withdrawals, .. } = tx

  // 1. There must be exactly one input carrying an NFT under the governance
  //    list policy. It must be a strict singleton NFT UTxO with inline datum.
  let
    _pass_input,
    pass_utxo_lovelace,
    pass_nft_name,
    pass_datum_data,
  <- validate_singular_authentic_input_helper(inputs, governance_nft_policy)

  // 2. The NFT being finalized must be a `PASS` NFT.
  expect
    bytearray.take(pass_nft_name, pass_nft_prefix_length) == pass_nft_prefix

  // 3. The `PASS` NFT must be burnt, with no other minting or burning.
  let expected_mint =
    assets.from_asset(governance_nft_policy, pass_nft_name, -1)
  expect mint == expected_mint

  // 4. The `PASS` UTxO datum provides the proposer and the withdrawal script
  //    required for final burn.
  expect PassedProposal { proposer, required_script_for_final_burn, .. } =
    pass_datum_data

  // 5. The proposer must receive a pure ADA output carrying at least the
  //    finalized `PASS` UTxO's lovelace. No datum, no reference script.
  expect Output {
    address: proposer_output_address,
    value: proposer_output_value,
    datum: NoDatum,
    reference_script: None,
  } = outputs |> list.expect_at(proposer_output_index)

  let proposer_output_lovelace = assets.lovelace_of(proposer_output_value)
  expect proposer_output_address == proposer
  expect proposer_output_value == assets.from_lovelace(proposer_output_lovelace)
  expect proposer_output_lovelace >= pass_utxo_lovelace

  // 6. The withdrawal script embedded in the original proposal must execute.
  expect
    stake_validator.validate_withdraw_minimal(
      withdraw_script_hash: required_script_for_final_burn,
      withdrawals: withdrawals,
      withdrawal_index: proposals_withdrawal_script_index,
    )

  // Done.
  True
}

pub fn remove_expired_proposal(
  anchor_input_outref: OutputReference,
  anchor_output_index: Int,
  governance_nft_policy: PolicyId,
  tx: Transaction,
) -> Bool {
  let Transaction {
    inputs,
    outputs,
    mint,
    extra_signatories,
    validity_range,
    ..
  } = tx

  {
    let
      _anchor_input,
      anchor_element_lovelace_change,
      _anchor_key,
      _anchor_data,
      _removing_node_input,
      _removing_node_lovelace,
      _removing_node_key,
      removing_node_data,
      _removing_node_link,
    <-
      linked_list.remove(
        anchor_input_outref,
        outputs |> list.expect_at(anchor_output_index),
        inputs,
        mint,
      )

    // 1. Anchor element's ADA must be preserved.
    expect anchor_element_lovelace_change >= 0

    // 2. Only the original proposer can perform the burn/removal, after the
    //    declared expiration time.
    expect Proposal { proposer, valid_until, .. } = removing_node_data
    expect proposer |> address_consented(extra_signatories)
    expect validity_range |> interval.is_entirely_after(valid_until)

    // Done.
    True
  }
    |> linked_list.run_element_with(
        governance_nft_policy,
        root_key,
        node_key_prefix,
        node_key_prefix_length,
      )
}

fn address_consented(
  address: Address,
  extra_signatories: List<VerificationKeyHash>,
) -> Bool {
  when address is {
    Address {
      payment_credential: VerificationKey(payment_vkey),
      stake_credential: None,
    } -> extra_signatories |> list.has(payment_vkey)

    Address {
      payment_credential: VerificationKey(payment_vkey),
      stake_credential: Some(Inline(VerificationKey(stake_vkey))),
    } -> or {
        extra_signatories |> list.has(payment_vkey),
        extra_signatories |> list.has(stake_vkey),
      }

    _ -> fail @"unsupported proposer address credential"
  }
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

pub fn validate_add_proposal_script_data_hash(
  script_data_hash: ByteArray,
  cost_model: ByteArray,
  spend_cpu: Int,
  spend_mem: Int,
  mint_cpu: Int,
  mint_mem: Int,
  spend_redeemer_index: Int,
  mint_redeemer: MintRedeemer,
) -> Bool {
  let spend_redeemer: SpendRedeemer = DelegateToMint

  let redeemers =
    serialise_definite_list(
      2,
      serialise_redeemer_entry(
        0,
        spend_redeemer_index,
        serialise_plutus_data(spend_redeemer),
        serialise_budget(spend_mem, spend_cpu),
      )
        |> bytearray.concat(
            serialise_redeemer_entry(
              1,
              0,
              serialise_plutus_data(mint_redeemer),
              serialise_budget(mint_mem, mint_cpu),
            ),
          ),
    )

  let language_views = #"a102" |> bytearray.concat(cost_model)

  builtin.blake2b_256(bytearray.concat(redeemers, language_views)) == script_data_hash
}

pub fn validate_pass_script_data_hash(
  script_data_hash: ByteArray,
  cost_model: ByteArray,
  anchor_spend_cpu: Int,
  anchor_spend_mem: Int,
  proposal_spend_cpu: Int,
  proposal_spend_mem: Int,
  mint_cpu: Int,
  mint_mem: Int,
  anchor_spend_redeemer_index: Int,
  proposal_spend_redeemer_index: Int,
  mint_redeemer: MintRedeemer,
) -> Bool {
  let spend_redeemer: SpendRedeemer = DelegateToMint
  let spend_redeemer_data = serialise_plutus_data(spend_redeemer)
  let anchor_spend_budget = serialise_budget(anchor_spend_mem, anchor_spend_cpu)
  let proposal_spend_budget =
    serialise_budget(proposal_spend_mem, proposal_spend_cpu)

  let redeemers =
    serialise_definite_list(
      3,
      serialise_redeemer_entry(
        0,
        anchor_spend_redeemer_index,
        spend_redeemer_data,
        anchor_spend_budget,
      )
        |> bytearray.concat(
            serialise_redeemer_entry(
              0,
              proposal_spend_redeemer_index,
              spend_redeemer_data,
              proposal_spend_budget,
            ),
          )
        |> bytearray.concat(
            serialise_redeemer_entry(
              1,
              0,
              serialise_plutus_data(mint_redeemer),
              serialise_budget(mint_mem, mint_cpu),
            ),
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
  do_validate_tx_id_from_script_data_hash(
    tx_id,
    script_data_hash,
    inputs,
    reference_inputs,
    outputs,
    fee,
    #"ab",
    #"03" |> bytearray.concat(cbor.serialise(ttl)),
    mint,
    extra_signatories,
    collateral_inputs,
    collateral_output,
    collateral_fee,
  )
}

pub fn validate_tx_id_from_script_data_hash_without_ttl(
  tx_id: ByteArray,
  script_data_hash: ByteArray,
  inputs: List<Input>,
  reference_inputs: List<Input>,
  outputs: List<Output>,
  fee: Lovelace,
  mint: Value,
  extra_signatories: List<VerificationKeyHash>,
  collateral_inputs: ByteArray,
  collateral_output: ByteArray,
  collateral_fee: ByteArray,
) -> Bool {
  do_validate_tx_id_from_script_data_hash(
    tx_id,
    script_data_hash,
    inputs,
    reference_inputs,
    outputs,
    fee,
    #"aa",
    "",
    mint,
    extra_signatories,
    collateral_inputs,
    collateral_output,
    collateral_fee,
  )
}

fn do_validate_tx_id_from_script_data_hash(
  tx_id: ByteArray,
  script_data_hash: ByteArray,
  inputs: List<Input>,
  reference_inputs: List<Input>,
  outputs: List<Output>,
  fee: Lovelace,
  tx_body_map_header: ByteArray,
  ttl_entry: ByteArray,
  mint: Value,
  extra_signatories: List<VerificationKeyHash>,
  collateral_inputs: ByteArray,
  collateral_output: ByteArray,
  collateral_fee: ByteArray,
) -> Bool {
  let serialised_inputs = serialise_tx_inputs(inputs)
  let serialised_reference_inputs = serialise_tx_inputs(reference_inputs)
  let serialised_outputs = serialise_tx_outputs(outputs)
  let serialised_fee = cbor.serialise(fee)
  let serialised_mint = cbor.serialise(assets.to_dict(mint))
  let serialised_script_data_hash = cbor.serialise(script_data_hash)
  let serialised_extra_signatories =
    serialise_extra_signatories(extra_signatories)

  let tx_body =
    tx_body_map_header
      |> bytearray.concat(#"00")
      |> bytearray.concat(serialised_inputs)
      |> bytearray.concat(#"01")
      |> bytearray.concat(serialised_outputs)
      |> bytearray.concat(#"02")
      |> bytearray.concat(serialised_fee)
      |> bytearray.concat(ttl_entry)
      |> bytearray.concat(#"09")
      |> bytearray.concat(serialised_mint)
      |> bytearray.concat(#"0b")
      |> bytearray.concat(serialised_script_data_hash)
      |> bytearray.concat(#"0d")
      |> bytearray.concat(collateral_inputs)
      |> bytearray.concat(#"0e")
      |> bytearray.concat(serialised_extra_signatories)
      |> bytearray.concat(#"10")
      |> bytearray.concat(collateral_output)
      |> bytearray.concat(#"11")
      |> bytearray.concat(collateral_fee)
      |> bytearray.concat(#"12")
      |> bytearray.concat(serialised_reference_inputs)

  let reconstructed_tx_id = builtin.blake2b_256(tx_body)

  reconstructed_tx_id == tx_id
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

fn serialise_redeemer_entry(
  tag: Int,
  index: Int,
  redeemer_data: ByteArray,
  budget: ByteArray,
) -> ByteArray {
  #"84"
    |> bytearray.concat(cbor.serialise(tag))
    |> bytearray.concat(cbor.serialise(index))
    |> bytearray.concat(redeemer_data)
    |> bytearray.concat(budget)
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

  #"d90102" |> bytearray.concat(serialise_definite_list(length, body))
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
  let Output { address, value, datum, reference_script } = output

  when datum is {
    NoDatum -> {
      expect None = reference_script

      #"82"
        |> bytearray.concat(serialise_address(address))
        |> bytearray.concat(serialise_output_value(value))
    }
    DatumHash(_) -> fail @"datum hashes cannot be recovered"
    InlineDatum(data) -> {
      expect None = reference_script

      #"a3"
        |> bytearray.concat(#"00")
        |> bytearray.concat(serialise_address(address))
        |> bytearray.concat(#"01")
        |> bytearray.concat(serialise_output_value(value))
        |> bytearray.concat(
            serialise_inline_output_datum(serialise_plutus_data(data)),
          )
    }
  }
}

fn serialise_inline_output_datum(data: ByteArray) -> ByteArray {
  #"02"
    |> bytearray.concat(#"8201")
    |> bytearray.concat(#"d818")
    |> bytearray.concat(serialise_cbor_bytes(data))
}

fn serialise_plutus_data(data: Data) -> ByteArray {
  builtin.choose_data(
    data,
    serialise_plutus_constr_data(data),
    serialise_plutus_map_data(data),
    serialise_plutus_list_data(data),
    cbor.serialise(builtin.un_i_data(data)),
    serialise_plutus_bytearray(builtin.un_b_data(data)),
  )
}

fn serialise_plutus_constr_data(data: Data) -> ByteArray {
  let Pair(constructor, fields) = builtin.un_constr_data(data)
  let serialised_fields = serialise_plutus_data_list(fields)

  if constructor < 7 {
    serialise_cbor_tag(121 + constructor)
      |> bytearray.concat(serialised_fields)
  } else if constructor < 128 {
    serialise_cbor_tag(1280 + constructor - 7)
      |> bytearray.concat(serialised_fields)
  } else {
    serialise_cbor_tag(102)
      |> bytearray.concat(
          serialise_definite_list(
            2,
            cbor.serialise(constructor)
              |> bytearray.concat(serialised_fields),
          ),
        )
  }
}

fn serialise_plutus_list_data(data: Data) -> ByteArray {
  serialise_plutus_data_list(builtin.un_list_data(data))
}

fn serialise_plutus_map_data(data: Data) -> ByteArray {
  let
    length,
    body,
  <-
    list.foldr2(
      builtin.un_map_data(data),
      0,
      "",
      fn(pair, length, body, return) {
        return(
          length + 1,
          serialise_plutus_data(pair.1st)
            |> bytearray.concat(serialise_plutus_data(pair.2nd))
            |> bytearray.concat(body),
        )
      },
    )

  serialise_cbor_head(5, length) |> bytearray.concat(body)
}

fn serialise_plutus_data_list(items: List<Data>) -> ByteArray {
  let
    length,
    body,
  <-
    list.foldr2(
      items,
      0,
      "",
      fn(item, length, body, return) {
        return(
          length + 1,
          serialise_plutus_data(item) |> bytearray.concat(body),
        )
      },
    )

  // Plutus data constructors in this module only carry short field lists.
  builtin.cons_bytearray(0x80 + length, body)
}

fn serialise_plutus_bytearray(bytes: ByteArray) -> ByteArray {
  let length = bytearray.length(bytes)

  if length <= 64 {
    serialise_cbor_bytes(bytes)
  } else {
    #"5f"
      |> bytearray.concat(serialise_plutus_bytearray_chunks(bytes, 0, length))
      |> bytearray.concat(#"ff")
  }
}

fn serialise_plutus_bytearray_chunks(
  bytes: ByteArray,
  cursor: Int,
  length: Int,
) -> ByteArray {
  if cursor >= length {
    ""
  } else {
    let chunk_length =
      if length - cursor > 64 {
        64
      } else {
        length - cursor
      }

    serialise_cbor_bytes(builtin.slice_bytearray(cursor, chunk_length, bytes))
      |> bytearray.concat(
          serialise_plutus_bytearray_chunks(
            bytes,
            cursor + chunk_length,
            length,
          ),
        )
  }
}

fn serialise_cbor_bytes(bytes: ByteArray) -> ByteArray {
  serialise_cbor_head(2, bytearray.length(bytes)) |> bytearray.concat(bytes)
}

fn serialise_cbor_tag(tag: Int) -> ByteArray {
  serialise_cbor_head(6, tag)
}

fn serialise_cbor_head(major_type: Int, argument: Int) -> ByteArray {
  let major = major_type * 32

  if argument < 24 {
    builtin.cons_bytearray(major + argument, #"")
  } else if argument <= 255 {
    builtin.cons_bytearray(
      major + 24,
      bytearray.from_int_big_endian(argument, 1),
    )
  } else if argument <= 65535 {
    builtin.cons_bytearray(
      major + 25,
      bytearray.from_int_big_endian(argument, 2),
    )
  } else if argument <= 4294967295 {
    builtin.cons_bytearray(
      major + 26,
      bytearray.from_int_big_endian(argument, 4),
    )
  } else {
    builtin.cons_bytearray(
      major + 27,
      bytearray.from_int_big_endian(argument, 8),
    )
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

  #"d90102" |> bytearray.concat(serialise_definite_list(length, body))
}

fn serialise_definite_list(length: Int, body: ByteArray) -> ByteArray {
  // Callers use this only for short CBOR arrays.
  builtin.cons_bytearray(0x80 + length, body)
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
