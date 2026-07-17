//// @hidden
//// # Minimal CIP-113 lifecycle
////
//// This deployable example combines the linked-list, parameter-validation,
//// and withdraw-zero patterns into a deliberately small CIP-113 lifecycle.
//// It supports an immutable policy registry, issuer-controlled minting and
//// burning, holder-authorized transfers, registry-selected transfer rules,
//// and a shared custody address.
////
//// Instantiate the validators in this order to avoid hash cycles:
////
//// 1. Derive `cip113_protocol_parameters` from `bootstrap_nonce`.
//// 2. Derive `cip113_programmable_logic_global` from that policy ID.
//// 3. Derive `cip113_programmable_logic_base` from the global script hash.
//// 4. Derive `cip113_registry` and each `cip113_issuance` policy.
//// 5. In one transaction, mint the parameters NFT and initialize the registry.
////
//// The immutable parameters datum is the indirection point that lets the
//// global and issuance validators discover the registry and shared-custody
//// hashes without embedding those later-derived hashes in their own scripts.

use aiken/cbor
use aiken/collection/dict
use aiken/collection/list
use aiken/collection/pairs
use aiken/crypto.{Blake2b_224, Hash, ScriptHash, VerificationKeyHash}
use aiken/primitive/bytearray
use aiken_design_patterns/linked_list
use aiken_design_patterns/parameter_validation.{ParameterizedRedeemer}
use aiken_design_patterns/stake_validator
use cardano/address.{Address, Credential, Inline, Script, VerificationKey}
use cardano/assets.{PolicyId, Value}
use cardano/transaction.{
  InlineDatum, Input, Output, OutputReference, Transaction,
}

/// The singleton NFT authenticating the immutable protocol-parameters UTxO.
pub const protocol_parameters_token_name = "CIP113_PARAMETERS"

/// Registry roots use the empty asset name.
pub const registry_root_key = #""

/// Four bytes leave exactly 28 bytes for a policy ID in each node NFT name.
pub const registry_node_key_prefix = "CIP1"

pub const registry_node_key_prefix_length =
  bytearray.length(registry_node_key_prefix)

pub const registered_policy_key_length = 32 - registry_node_key_prefix_length

/// Immutable values shared by every validator in this protocol instance.
pub type ProtocolParameters {
  registry_policy: PolicyId,
  global_validator: ScriptHash,
  shared_custody_validator: ScriptHash,
}

pub type ProtocolParametersMintRedeemer {
  BootstrapProtocol { parameters_output_index: Int }
}

pub type RegistryRootState {
  RegistryRoot
}

/// A policy's permanent registry-selected authorities and transfer rule.
pub type RegistryEntry {
  issuance_authority: Credential,
  transfer_validator: ScriptHash,
}

pub type RegistryDatum =
  linked_list.Element<RegistryRootState, RegistryEntry>

pub type RegistryMintRedeemer {
  InitializeRegistry {
    root_output_index: Int,
    protocol_parameters_output_index: Int,
  }
  RegisterPolicy {
    continued_anchor_output_index: Int,
    new_node_output_index: Int,
  }
}

pub type RegistrySpendRedeemer {
  PermitRegistryInsertion { input_index: Int }
}

/// The resolved parameter is hashed before it is applied to the issuance
/// template. This gives the template one fixed-width on-chain parameter while
/// still binding both the protocol instance and its issuance authority.
pub type IssuanceParameters {
  protocol_parameters_policy: PolicyId,
  issuance_authority: Credential,
}

pub type IssuanceRedeemer {
  IssueOrBurn {
    protocol_parameters_reference_input_index: Int,
    registry_node_reference_input_index: Int,
  }
}

pub type ProgrammableLogicBaseRedeemer {
  ValidateProgrammableTransfer {
    global_redeemer_index: Int,
    global_withdrawal_index: Int,
  }
}

/// This educational subset validates one registered policy per invocation.
pub type ProgrammableLogicGlobalRedeemer {
  Transfer {
    subject_policy: PolicyId,
    protocol_parameters_reference_input_index: Int,
    registry_node_reference_input_index: Int,
    transfer_redeemer_index: Int,
    transfer_withdrawal_index: Int,
  }
}

pub type PermissionedTransferRedeemer {
  PermissionedTransfer
}

fn expect_only_subject_policy(value: Value, subject_policy: PolicyId) -> Void {
  // Input and output values always contain ADA first. Matching exactly one
  // remaining policy also proves that the subject token set is non-empty.
  expect [Pair(_, _), Pair(actual_policy, _)] = assets.to_pairs(value)
  expect actual_policy == subject_policy
}

fn expect_input_consumed(
  inputs: List<Input>,
  required_reference: OutputReference,
) -> Void {
  list.expect_any(
    inputs,
    fn(input) {
      let Input { output_reference, .. } = input
      output_reference == required_reference
    },
  )
}

fn expect_zero_withdrawal(
  withdrawals: Pairs<Credential, Int>,
  credential: Credential,
) -> Void {
  expect pairs.expect_get_first(withdrawals, credential) == 0
}

/// Key credentials authorize through an extra signatory. Script credentials
/// authorize by executing their staking script with a zero-ADA withdrawal.
fn expect_credential_authorized(
  credential: Credential,
  extra_signatories: List<VerificationKeyHash>,
  withdrawals: Pairs<Credential, Int>,
) -> Void {
  when credential is {
    VerificationKey(key_hash) -> list.expect_has(extra_signatories, key_hash)
    Script(_) -> expect_zero_withdrawal(withdrawals, credential)
  }
}

fn read_protocol_parameters(
  reference_inputs: List<Input>,
  reference_input_index: Int,
  protocol_parameters_policy: PolicyId,
) -> ProtocolParameters {
  let Input { output, .. } =
    list.expect_at(reference_inputs, reference_input_index)

  read_protocol_parameters_output(output, protocol_parameters_policy)
}

fn read_protocol_parameters_output(
  output: Output,
  protocol_parameters_policy: PolicyId,
) -> ProtocolParameters {
  expect Output {
    address: Address {
      payment_credential: Script(parameters_validator),
      stake_credential: None,
    },
    value,
    datum: InlineDatum(parameters_data),
    ..
  } = output

  expect parameters_validator == protocol_parameters_policy
  expect
    assets.has_nft_strict(
      value,
      protocol_parameters_policy,
      protocol_parameters_token_name,
    )
  expect parameters: ProtocolParameters = parameters_data
  parameters
}

fn read_registry_entry(
  reference_inputs: List<Input>,
  reference_input_index: Int,
  registry_policy: PolicyId,
  subject_policy: PolicyId,
) -> RegistryEntry {
  let Input { output, .. } =
    list.expect_at(reference_inputs, reference_input_index)

  {
    let
      node_address,
      _node_lovelace,
      node_key,
      node_data,
      _node_link,
    <- linked_list.get_node_element_info(output)

    expect Address {
      payment_credential: Script(registry_validator),
      stake_credential: None,
    } = node_address
    expect registry_validator == registry_policy
    expect node_key == subject_policy
    expect entry: RegistryEntry = node_data
    entry
  }
    |> linked_list.run_node_with(
        registry_policy,
        registry_node_key_prefix,
        registry_node_key_prefix_length,
      )
}

fn expect_valid_custody_inputs(
  inputs: List<Input>,
  shared_custody_validator: ScriptHash,
  subject_policy: PolicyId,
  extra_signatories: List<VerificationKeyHash>,
  withdrawals: Pairs<Credential, Int>,
  custody_input_required: Bool,
) -> Void {
  let shared_custody_credential: Credential = Script(shared_custody_validator)
  let custody_input_found =
    list.foldl(
      inputs,
      False,
      fn(input, custody_input_found) {
        let Input { output: Output { address, value, .. }, .. } = input
        let Address { payment_credential, stake_credential } = address

        if payment_credential == shared_custody_credential {
          expect Some(Inline(owner)) = stake_credential
          expect_only_subject_policy(value, subject_policy)
          expect_credential_authorized(owner, extra_signatories, withdrawals)
          True
        } else {
          expect assets.tokens(value, subject_policy) |> dict.is_empty
          custody_input_found
        }
      },
    )

  expect or {
      !custody_input_required,
      custody_input_found,
    }
}

fn expect_valid_custody_outputs(
  outputs: List<Output>,
  shared_custody_validator: ScriptHash,
  subject_policy: PolicyId,
) -> Void {
  let shared_custody_credential: Credential = Script(shared_custody_validator)

  list.foldl(
    outputs,
    Void,
    fn(output, _) {
      let Output { address, value, .. } = output
      let Address { payment_credential, stake_credential } = address

      if payment_credential == shared_custody_credential {
        expect Some(Inline(_owner)) = stake_credential
        expect_only_subject_policy(value, subject_policy)
      } else {
        expect assets.tokens(value, subject_policy) |> dict.is_empty
      }
    },
  )
}

/// One-shot protocol bootstrap and the permanently locked parameters UTxO.
validator cip113_protocol_parameters(bootstrap_nonce: OutputReference) {
  mint(
    redeemer: ProtocolParametersMintRedeemer,
    own_policy: PolicyId,
    tx: Transaction,
  ) {
    let BootstrapProtocol { parameters_output_index } = redeemer
    let Transaction { inputs, outputs, mint, .. } = tx

    expect
      assets.tokens(mint, own_policy) == dict.singleton(
        protocol_parameters_token_name,
        1,
      )
    expect_input_consumed(inputs, bootstrap_nonce)

    let parameters_output = list.expect_at(outputs, parameters_output_index)
    let ProtocolParameters { registry_policy, .. } =
      read_protocol_parameters_output(parameters_output, own_policy)

    // Bootstrap is atomic: the registry's empty root is minted in the
    // same transaction under the policy committed to this datum.
    assets.quantity_of(mint, registry_policy, registry_root_key) == 1
  }

  // The authenticated parameters output is immutable after bootstrap.
  spend(
    _datum: Option<ProtocolParameters>,
    _redeemer: Data,
    _own_out_ref: OutputReference,
    _tx: Transaction,
  ) {
    False
  }

  else(_) {
    fail
  }
}

/// Ascending registry of issuance policy IDs.
validator cip113_registry(
  bootstrap_nonce: OutputReference,
  protocol_parameters_policy: PolicyId,
  issuance_template_prefix: ByteArray,
) {
  mint(redeemer: RegistryMintRedeemer, own_policy: PolicyId, tx: Transaction) {
    when redeemer is {
      InitializeRegistry { root_output_index, protocol_parameters_output_index } -> {
        let Transaction { inputs, outputs, mint, .. } = tx

        expect
          assets.quantity_of(
            mint,
            protocol_parameters_policy,
            protocol_parameters_token_name,
          ) == 1
        expect_input_consumed(inputs, bootstrap_nonce)

        let root_output = list.expect_at(outputs, root_output_index)
        let parameters_output =
          list.expect_at(outputs, protocol_parameters_output_index)

        let ProtocolParameters { registry_policy, .. } =
          read_protocol_parameters_output(
            parameters_output,
            protocol_parameters_policy,
          )
        expect registry_policy == own_policy

        {
          let
            root_address,
            _root_lovelace,
            root_data,
          <-
            linked_list.init(
              nonce_validated: True,
              produced_element_output: root_output,
              tx_mint: mint,
            )

          expect Address {
            payment_credential: Script(registry_validator),
            stake_credential: None,
          } = root_address
          expect registry_validator == own_policy

          let expected_root_data: Data = RegistryRoot
          root_data == expected_root_data
        }
          |> linked_list.run_root_with(own_policy, registry_root_key)
      }

      RegisterPolicy { continued_anchor_output_index, new_node_output_index } -> {
        let Transaction {
          inputs,
          outputs,
          mint,
          extra_signatories,
          withdrawals,
          ..
        } = tx
        let continued_anchor_output =
          list.expect_at(outputs, continued_anchor_output_index)
        let new_node_output = list.expect_at(outputs, new_node_output_index)
        let Output { address: new_node_address, .. } = new_node_output

        {
          let
            _anchor_input,
            anchor_lovelace_change,
            _maybe_anchor_key,
            _anchor_data,
            _new_node_lovelace,
            new_node_key,
            new_node_data,
            _new_node_link,
          <-
            linked_list.insert_ascending(
              continued_anchor_element_output: continued_anchor_output,
              new_node_output: new_node_output,
              inputs: inputs,
              tx_mint: mint,
            )

          expect bytearray.length(new_node_key) == registered_policy_key_length
          expect anchor_lovelace_change >= 0
          expect Address {
            payment_credential: Script(registry_validator),
            stake_credential: None,
          } = new_node_address
          expect registry_validator == own_policy

          expect entry: RegistryEntry = new_node_data
          let RegistryEntry { issuance_authority, .. } = entry
          expect_credential_authorized(
            issuance_authority,
            extra_signatories,
            withdrawals,
          )

          let issuance_parameters =
            IssuanceParameters {
              protocol_parameters_policy,
              issuance_authority,
            }
          let expected_issuance_policy =
            parameter_validation.apply_param(
              version: 3,
              prefix: issuance_template_prefix,
              param: cbor.serialise(issuance_parameters),
            )

          // Only an instance of this file's issuance template can become a
          // registry key, so registered policies cannot bypass shared custody.
          new_node_key == expected_issuance_policy
        }
          |> linked_list.run_element_with(
              own_policy,
              registry_root_key,
              registry_node_key_prefix,
              registry_node_key_prefix_length,
            )
      }
    }
  }

  spend(
    _datum: Option<RegistryDatum>,
    redeemer: RegistrySpendRedeemer,
    own_out_ref: OutputReference,
    tx: Transaction,
  ) {
    let PermitRegistryInsertion { input_index } = redeemer
    let Transaction { inputs, mint, .. } = tx
    expect Input {
      output: Output {
        address: Address { payment_credential: Script(registry_validator), .. },
        ..
      },
      output_reference,
    } = list.expect_at(inputs, input_index)

    expect output_reference == own_out_ref
    linked_list.spend_for_adding_or_removing_an_element(
      registry_validator,
      mint,
    )
  }

  else(_) {
    fail
  }
}

/// Lightweight custody endpoint. Every shared-custody input delegates once to
/// the global validator through the same indexed zero withdrawal.
validator cip113_programmable_logic_base(global_validator: ScriptHash) {
  spend(
    _datum: Option<Data>,
    redeemer: ProgrammableLogicBaseRedeemer,
    _own_out_ref: OutputReference,
    tx: Transaction,
  ) {
    let ValidateProgrammableTransfer {
      global_redeemer_index,
      global_withdrawal_index,
    } = redeemer
    let Transaction { redeemers, withdrawals, .. } = tx
    let
      _global_redeemer,
      amount,
    <-
      stake_validator.validate_withdraw_with_amount(
        withdraw_script_hash: global_validator,
        redeemers: redeemers,
        withdraw_redeemer_index: global_redeemer_index,
        withdrawals: withdrawals,
        withdrawal_index: global_withdrawal_index,
      )

    amount == 0
  }

  else(_) {
    fail
  }
}

/// Transaction-level coordinator for a transfer of one registered policy.
validator cip113_programmable_logic_global(
  protocol_parameters_policy: PolicyId,
) {
  withdraw(
    redeemer: ProgrammableLogicGlobalRedeemer,
    own_credential: Credential,
    tx: Transaction,
  ) {
    let Transfer {
      subject_policy,
      protocol_parameters_reference_input_index,
      registry_node_reference_input_index,
      transfer_redeemer_index,
      transfer_withdrawal_index,
    } = redeemer
    let Transaction {
      inputs,
      reference_inputs,
      outputs,
      extra_signatories,
      withdrawals,
      redeemers,
      ..
    } = tx
    let ProtocolParameters {
      registry_policy,
      global_validator,
      shared_custody_validator,
    } =
      read_protocol_parameters(
        reference_inputs,
        protocol_parameters_reference_input_index,
        protocol_parameters_policy,
      )
    expect own_credential == Script(global_validator)

    let RegistryEntry { transfer_validator, .. } =
      read_registry_entry(
        reference_inputs,
        registry_node_reference_input_index,
        registry_policy,
        subject_policy,
      )
    expect transfer_validator != global_validator

    let
      _transfer_redeemer,
      amount,
    <-
      stake_validator.validate_withdraw_with_amount(
        withdraw_script_hash: transfer_validator,
        redeemers: redeemers,
        withdraw_redeemer_index: transfer_redeemer_index,
        withdrawals: withdrawals,
        withdrawal_index: transfer_withdrawal_index,
      )
    expect amount == 0

    // A transfer must consume at least one shared-custody input. Every such
    // input is checked for one policy and holder authorization. Exhaustively
    // confining the policy to custody lets ledger value conservation enforce
    // the corresponding input, mint, and output balance.
    expect_valid_custody_inputs(
      inputs: inputs,
      shared_custody_validator: shared_custody_validator,
      subject_policy: subject_policy,
      extra_signatories: extra_signatories,
      withdrawals: withdrawals,
      custody_input_required: True,
    )
    expect_valid_custody_outputs(
      outputs,
      shared_custody_validator,
      subject_policy,
    )

    True
  }

  else(_) {
    fail
  }
}

/// Approved issuance template. The registry derives an expected policy ID from
/// its golden prefix and the resolved `IssuanceParameters` value.
validator cip113_issuance(
  hashed_parameters: Hash<Blake2b_224, IssuanceParameters>,
) {
  mint(
    outer_redeemer: ParameterizedRedeemer<IssuanceParameters, IssuanceRedeemer>,
    own_policy: PolicyId,
    tx: Transaction,
  ) {
    let
      parameters,
      redeemer,
    <-
      parameter_validation.wrapper(
        hashed_parameter: hashed_parameters,
        parameter_serialiser: fn(p: IssuanceParameters) { cbor.serialise(p) },
        outer_redeemer: outer_redeemer,
      )

    let IssueOrBurn {
      protocol_parameters_reference_input_index,
      registry_node_reference_input_index,
    } = redeemer
    let IssuanceParameters { protocol_parameters_policy, issuance_authority } =
      parameters
    let Transaction {
      inputs,
      reference_inputs,
      outputs,
      extra_signatories,
      withdrawals,
      ..
    } = tx
    expect_credential_authorized(
      issuance_authority,
      extra_signatories,
      withdrawals,
    )

    let ProtocolParameters { registry_policy, shared_custody_validator, .. } =
      read_protocol_parameters(
        reference_inputs,
        protocol_parameters_reference_input_index,
        protocol_parameters_policy,
      )
    let RegistryEntry { issuance_authority: registered_issuance_authority, .. } =
      read_registry_entry(
        reference_inputs,
        registry_node_reference_input_index,
        registry_policy,
        own_policy,
      )

    expect registered_issuance_authority == issuance_authority
    expect_valid_custody_inputs(
      inputs: inputs,
      shared_custody_validator: shared_custody_validator,
      subject_policy: own_policy,
      extra_signatories: extra_signatories,
      withdrawals: withdrawals,
      custody_input_required: False,
    )
    expect_valid_custody_outputs(outputs, shared_custody_validator, own_policy)

    True
  }

  else(_) {
    fail
  }
}

/// Example token-specific rule selected by a `RegistryEntry`.
validator cip113_permissioned_transfer(required_signer: VerificationKeyHash) {
  withdraw(
    redeemer: PermissionedTransferRedeemer,
    own_credential: Credential,
    tx: Transaction,
  ) {
    let PermissionedTransfer = redeemer
    let Transaction { extra_signatories, withdrawals, .. } = tx
    list.expect_has(extra_signatories, required_signer)
    expect_zero_withdrawal(withdrawals, own_credential)
    True
  }

  else(_) {
    fail
  }
}
