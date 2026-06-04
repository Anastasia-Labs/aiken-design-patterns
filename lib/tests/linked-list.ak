use aiken/builtin
use aiken/crypto.{ScriptHash, blake2b_224, sha2_256}
use aiken/fuzz
use aiken/primitive/bytearray.{from_int_big_endian}
use aiken_design_patterns/linked_list.{
  Element, ElementEval, GenericElement, Node, Root, append_unordered, deinit,
  fold_from_root, get_element_info, get_node_element_info, get_root_element_info,
  init, insert_ascending, insert_descending, prepend_unordered, remove,
  run_element_with, run_node_with, run_root_with,
  spend_for_adding_or_removing_an_element, spend_for_updating_elements_data,
}
use aiken_design_patterns/linked_list/nested.{
  Ascending, Descending, ListOrdering, Unordered,
}
use aiken_design_patterns/utils
use cardano/address.{Address, Script, VerificationKey}
use cardano/assets.{PolicyId, Value}
use cardano/fuzz as cardano_fuzz
use cardano/transaction.{InlineDatum, Input, Output, OutputReference}

const min_lovelace = 2_000_000

const test_root_key = #""

const test_node_key_prefix = #"00"

const test_node_key_prefix_length = bytearray.length(test_node_key_prefix)

const b_data = builtin.b_data(#"00")

type InitArgs {
  inputs: List<Input>,
  nonce_out_ref: OutputReference,
  script_hash: ScriptHash,
  script_output: Output,
}

type DeinitArgs {
  script_hash: ScriptHash,
  root_input: Input,
  inputs: List<Input>,
}

type InsertDirection {
  InsertAscending
  InsertDescending
}

type InitMutation {
  InitNoMutation
  InitBadAssetName
  InitBadNonce
  InitBadPolicy
  InitBadValidator
  InitBadMint
  InitExtraMint
}

type DeinitMutation {
  DeinitNoMutation
  DeinitBadPolicy
  DeinitBadValidator
  DeinitBadMint
  DeinitExtraMint
}

type InsertMutation {
  InsertNoMutation
  InsertBadPolicy
  InsertBadContinuedAnchorDestination
  InsertBadNodeDestination
  InsertBadContinuedAnchorLink
  InsertBadNodeLink
  InsertBadValidator
  InsertBadMint
  InsertExtraMint
}

type RemoveMutation {
  RemoveNoMutation
  RemoveBadPolicy
  RemoveBadAnchorOutRef
  RemoveBadContinuedAnchorDestination
  RemoveBadContinuedAnchorLink
  RemoveBadValidator
  RemoveBadMint
  RemoveExtraMint
  RemoveAnchorBurnt
}

type FoldMutation {
  FoldNoMutation
  FoldBadPolicy
  FoldBadAnchorOutRef
  FoldBadContinuedRootDestination
  FoldBadContinuedRootLink
  FoldBadValidator
  FoldBadMint
  FoldExtraMint
  FoldAnchorBurnt
}

type UpdateRootMutation {
  UpdateRootNoMutation
  UpdateRootBadLink
  UpdateRootMintedListAsset
  UpdateRootBadInputIndex
  UpdateRootBadOutputIndex
}

type InsertOrderedArgs {
  direction: InsertDirection,
  script_hash: ScriptHash,
  expected_anchor_input: Input,
  inputs: List<Input>,
  continued_anchor_output: Output,
  node_output: Output,
  mint_value: Value,
}

fn two_elements_fuzzer(
  node_key_prefix: ByteArray,
  anchor_is_root: Bool,
  node_has_link: Bool,
  key_ordering: ListOrdering,
) -> Fuzzer<(ScriptHash, Input, Input)> {
  let node_key_prefix_length = bytearray.length(node_key_prefix)
  let node_key_length = 32 - node_key_prefix_length
  let script_hash <- fuzz.and_then(cardano_fuzz.policy_id())
  let base_node_key_value <- fuzz.and_then(fuzz.int_between(0, 1000))
  let base_node_key =
    base_node_key_value
      |> from_int_big_endian(node_key_length)
  let next_node_key =
    from_int_big_endian(base_node_key_value + 1, node_key_length)
  let last_node_key =
    from_int_big_endian(base_node_key_value + 2, node_key_length)
  let random_node_key_a <- fuzz.and_then(fuzz.bytearray_fixed(node_key_length))
  let random_node_key_b <- fuzz.and_then(fuzz.bytearray_fixed(node_key_length))
  let (anchor_node_key, target_node_key, successor_node_key) =
    when key_ordering is {
      Ascending -> (base_node_key, next_node_key, last_node_key)
      Descending -> (last_node_key, next_node_key, base_node_key)
      Unordered -> (base_node_key, random_node_key_a, random_node_key_b)
    }
  let anchor_asset_name =
    if anchor_is_root {
      test_root_key
    } else {
      node_key_prefix |> bytearray.concat(anchor_node_key)
    }
  let target_node_asset_name =
    node_key_prefix
      |> bytearray.concat(target_node_key)
  let lovelace_value = assets.from_lovelace(min_lovelace)
  let anchor_nft = assets.from_asset(script_hash, anchor_asset_name, 1)
  let target_node_nft =
    assets.from_asset(script_hash, target_node_asset_name, 1)
  let anchor_value = assets.merge(lovelace_value, anchor_nft)
  let target_node_value = assets.merge(lovelace_value, target_node_nft)
  let out_ref_0 <- fuzz.and_then(cardano_fuzz.output_reference())
  let out_ref_1 <- fuzz.and_then(cardano_fuzz.output_reference())
  fuzz.constant(
    (
      script_hash,
      Input {
        output_reference: out_ref_0,
        output: Output {
          address: Address {
            payment_credential: Script(script_hash),
            stake_credential: None,
          },
          value: anchor_value,
          datum: InlineDatum(
            Element {
              data: if anchor_is_root {
                Root(b_data)
              } else {
                Node(b_data)
              },
              link: Some(target_node_key),
            },
          ),
          reference_script: None,
        },
      },
      Input {
        output: Output {
          address: Address {
            payment_credential: Script(script_hash),
            stake_credential: None,
          },
          value: target_node_value,
          datum: InlineDatum(
            Element {
              data: Node(b_data),
              link: if node_has_link {
                Some(successor_node_key)
              } else {
                None
              },
            },
          ),
          reference_script: None,
        },
        output_reference: out_ref_1,
      },
    ),
  )
}

fn node_values_fuzzer() -> Fuzzer<(ScriptHash, Input, Input)> {
  two_elements_fuzzer(test_node_key_prefix, True, True, Unordered)
}

fn alter_output_address(output: Output) -> Output {
  expect Script(script_hash) = output.address.payment_credential
  let altered_address: Address =
    Address {
      payment_credential: VerificationKey(script_hash),
      stake_credential: None,
    }
  Output { ..output, address: altered_address }
}

fn alter_output_link(output: Output) -> Output {
  expect InlineDatum(datum_data) = output.datum
  expect Element { data, link }: GenericElement = datum_data
  let altered_datum =
    InlineDatum(
      Element(
        data,
        when link is {
          None ->
            Some(#"00000000000000000000000000000000000000000000000000000000")
          Some(_) -> None
        },
      ),
    )
  Output { ..output, datum: altered_datum }
}

fn add_extra_mint(mint_value: Value, policy_id: PolicyId) -> Value {
  let extra_token_name = #"deadbeef"
  assets.merge(mint_value, assets.from_asset(policy_id, extra_token_name, 1))
}

fn extra_list_input_fuzzer(script_hash: ScriptHash) -> Fuzzer<Input> {
  let extra_node_key <-
    fuzz.and_then(fuzz.bytearray_between(1, 32 - test_node_key_prefix_length))
  let extra_link_node_key <-
    fuzz.and_then(fuzz.bytearray_between(1, 32 - test_node_key_prefix_length))
  let has_link <- fuzz.and_then(fuzz.bool())
  let output_reference <- fuzz.and_then(cardano_fuzz.output_reference())
  let asset_name = test_node_key_prefix |> bytearray.concat(extra_node_key)
  let value =
    assets.merge(
      assets.from_lovelace(min_lovelace),
      assets.from_asset(script_hash, asset_name, 1),
    )
  fuzz.constant(
    Input {
      output_reference,
      output: Output {
        address: Address {
          payment_credential: Script(script_hash),
          stake_credential: None,
        },
        value,
        datum: InlineDatum(
          Element {
            data: Node(b_data),
            link: if has_link {
              Some(extra_link_node_key)
            } else {
              None
            },
          },
        ),
        reference_script: None,
      },
    },
  )
}

fn extra_list_inputs_fuzzer(script_hash: ScriptHash) -> Fuzzer<List<Input>> {
  fuzz.list_between(extra_list_input_fuzzer(script_hash), 1, 10)
}

fn eval_runner(eval: ElementEval<Bool>, policy_id: PolicyId) -> Bool {
  eval
    |> run_element_with(
        policy_id,
        test_root_key,
        test_node_key_prefix,
        test_node_key_prefix_length,
      )
}

fn expect_structural_lovelace_change(
  anchor_lovelace_change: Int,
  node_lovelace: Int,
  result: Bool,
) -> Bool {
  expect anchor_lovelace_change == 0
  expect node_lovelace == min_lovelace
  result
}

fn init_fuzzer(root_datum: Bool, link: Option<ByteArray>) -> Fuzzer<InitArgs> {
  let inputs <- fuzz.and_then(utils.user_inputs_fuzzer())
  let nonce_out_ref =
    builtin.head_list(inputs)
      |> fn(i: Input) -> OutputReference { i.output_reference }
  let (script_hash, script_output) <-
    fuzz.and_then(
      utils.authentic_script_output_with_given_asset_name_fuzzer(
        test_root_key,
        InlineDatum(
          Element {
            data: if root_datum {
              Root(b_data)
            } else {
              Node(b_data)
            },
            link,
          },
        ),
      ),
    )
  fuzz.constant(InitArgs { inputs, nonce_out_ref, script_hash, script_output })
}

fn deinit_fuzzer(
  root_datum: Bool,
  link: Option<ByteArray>,
) -> Fuzzer<DeinitArgs> {
  let InitArgs { nonce_out_ref, script_hash, script_output, .. } <-
    fuzz.and_then(init_fuzzer(root_datum, link))
  let root_input =
    Input { output_reference: nonce_out_ref, output: script_output }
  let inputs <-
    fuzz.and_then(
      utils.inputs_with_expected_inputs_fuzzer(script_hash, [root_input]),
    )
  fuzz.constant(DeinitArgs { script_hash, root_input, inputs })
}

fn deinit_with_extra_list_inputs_fuzzer(
  root_datum: Bool,
  link: Option<ByteArray>,
) -> Fuzzer<DeinitArgs> {
  let InitArgs { nonce_out_ref, script_hash, script_output, .. } <-
    fuzz.and_then(init_fuzzer(root_datum, link))
  let root_input =
    Input { output_reference: nonce_out_ref, output: script_output }
  let extra_inputs <- fuzz.and_then(extra_list_inputs_fuzzer(script_hash))
  let inputs <-
    fuzz.and_then(
      utils.inputs_with_expected_inputs_fuzzer(
        script_hash,
        [root_input, ..extra_inputs],
      ),
    )
  fuzz.constant(DeinitArgs { script_hash, root_input, inputs })
}

fn run_init_case(init_values: InitArgs, mutation: InitMutation) -> Bool {
  let InitArgs { inputs, nonce_out_ref, script_hash, script_output } =
    init_values
  let used_nonce_out_ref =
    when mutation is {
      InitBadNonce ->
        OutputReference {
          ..nonce_out_ref,
          transaction_id: sha2_256(nonce_out_ref.transaction_id),
        }
      _ -> nonce_out_ref
    }
  let root_key =
    when mutation is {
      InitBadAssetName -> "ROOT"
      _ -> test_root_key
    }
  let policy_id =
    when mutation is {
      InitBadPolicy -> blake2b_224(script_hash)
      _ -> script_hash
    }
  let mint_value =
    when mutation is {
      InitBadMint -> assets.zero
      InitExtraMint ->
        assets.from_asset(script_hash, test_root_key, 1)
          |> add_extra_mint(script_hash)
      _ -> assets.from_asset(script_hash, test_root_key, 1)
    }
  let callback_result =
    when mutation is {
      InitBadValidator -> False
      _ -> True
    }

  {
    let
      root_address,
      root_lovelace,
      _root_data,
    <-
      init(
        utils.utxo_is_spent(inputs, used_nonce_out_ref),
        script_output,
        mint_value,
      )
    expect root_address == script_output.address
    expect root_lovelace == min_lovelace
    callback_result
  }
    |> run_root_with(policy_id, root_key)
}

fn run_deinit_case(
  deinit_values: DeinitArgs,
  mutation: DeinitMutation,
  check_root_input: Bool,
) -> Bool {
  let DeinitArgs { script_hash, root_input, inputs } = deinit_values
  let policy_id =
    when mutation is {
      DeinitBadPolicy -> blake2b_224(script_hash)
      _ -> script_hash
    }
  let mint_value =
    when mutation is {
      DeinitBadMint -> assets.zero
      DeinitExtraMint ->
        assets.from_asset(script_hash, test_root_key, -1)
          |> add_extra_mint(script_hash)
      _ -> assets.from_asset(script_hash, test_root_key, -1)
    }
  let callback_result =
    when mutation is {
      DeinitBadValidator -> False
      _ -> True
    }

  {
    let
      actual_root_input,
      root_lovelace,
      _root_data,
    <- deinit(inputs, mint_value)
    when check_root_input is {
      True -> {
        expect actual_root_input.output_reference == root_input.output_reference
        expect actual_root_input.output.address == root_input.output.address
        expect root_lovelace == min_lovelace
        callback_result
      }
      False -> {
        expect root_lovelace == min_lovelace
        callback_result
      }
    }
  }
    |> run_root_with(policy_id, test_root_key)
}

test success__init(init_values via init_fuzzer(True, None)) {
  run_init_case(init_values, InitNoMutation)
}

test fail__init__bad_datum(init_values via init_fuzzer(False, None)) fail {
  run_init_case(init_values, InitNoMutation)
}

test fail__init__bad_asset_name(init_values via init_fuzzer(True, None)) fail {
  run_init_case(init_values, InitBadAssetName)
}

test fail__init__bad_nonce(init_values via init_fuzzer(True, None)) fail {
  run_init_case(init_values, InitBadNonce)
}

test fail__init__bad_first_link(
  init_values via init_fuzzer(True, Some(test_root_key)),
) fail {
  run_init_case(init_values, InitNoMutation)
}

test fail__init__bad_nft_symbol(init_values via init_fuzzer(True, None)) fail {
  run_init_case(init_values, InitBadPolicy)
}

test fail__init__bad_root_data_validator(
  init_values via init_fuzzer(True, None),
) fail {
  run_init_case(init_values, InitBadValidator)
}

test fail__init__bad_mint(init_values via init_fuzzer(True, None)) fail {
  run_init_case(init_values, InitBadMint)
}

test fail__init__extra_mint(init_values via init_fuzzer(True, None)) fail {
  run_init_case(init_values, InitExtraMint)
}

test success__deinit(deinit_values via deinit_fuzzer(True, None)) {
  run_deinit_case(deinit_values, DeinitNoMutation, True)
}

test fail__deinit__bad_datum(deinit_values via deinit_fuzzer(False, None)) fail {
  run_deinit_case(deinit_values, DeinitNoMutation, False)
}

test fail__deinit__bad_link(
  deinit_values via deinit_fuzzer(
    True,
    Some(#"0000000000000000000000000000000000000000000000000000000000000000"),
  ),
) fail {
  run_deinit_case(deinit_values, DeinitNoMutation, False)
}

test fail__deinit__bad_nft_symbol(
  deinit_values via deinit_fuzzer(True, None),
) fail {
  run_deinit_case(deinit_values, DeinitBadPolicy, False)
}

test fail__deinit__bad_root_data_validator(
  deinit_values via deinit_fuzzer(True, None),
) fail {
  run_deinit_case(deinit_values, DeinitBadValidator, False)
}

test fail__deinit__bad_mint(deinit_values via deinit_fuzzer(True, None)) fail {
  run_deinit_case(deinit_values, DeinitBadMint, False)
}

test fail__deinit__extra_mint(deinit_values via deinit_fuzzer(True, None)) fail {
  run_deinit_case(deinit_values, DeinitExtraMint, False)
}

test fail__deinit__extra_nft_policy_input(
  deinit_values via deinit_with_extra_list_inputs_fuzzer(True, None),
) fail {
  run_deinit_case(deinit_values, DeinitNoMutation, False)
}

fn continued_anchor_and_new_node_fixture(
  anchor_is_root: Bool,
  args: (ScriptHash, Input, Input),
) -> Fuzzer<(ScriptHash, Input, List<Input>, Output, Output, Value)> {
  // Invariant: spent and continued anchors are derived independently.
  let (script_hash, continued_anchor_template_input, node_input) = args
  expect InlineDatum(node_datum_data) = node_input.output.datum
  expect Element { link: nodes_link, .. }: GenericElement = node_datum_data
  let anchor_element: GenericElement =
    Element(
      if anchor_is_root {
        Root(b_data)
      } else {
        Node(b_data)
      },
      nodes_link,
    )
  let anchor_output: Output =
    Output {
      ..continued_anchor_template_input.output,
      datum: InlineDatum(anchor_element),
    }
  let anchor_input: Input =
    Input { ..continued_anchor_template_input, output: anchor_output }
  let inputs <-
    fuzz.and_then(
      utils.inputs_with_expected_inputs_fuzzer(script_hash, [anchor_input]),
    )
  fuzz.constant(
    (
      script_hash,
      anchor_input,
      inputs,
      continued_anchor_template_input.output,
      node_input.output,
      node_input.output.value |> assets.without_lovelace,
    ),
  )
}

fn insert_ordered_fuzzer() -> Fuzzer<InsertOrderedArgs> {
  let anchor_is_root <- fuzz.and_then(fuzz.bool())
  let node_has_link <- fuzz.and_then(fuzz.bool())
  let is_ascending <- fuzz.and_then(fuzz.bool())
  let direction =
    if is_ascending {
      InsertAscending
    } else {
      InsertDescending
    }
  let args <-
    fuzz.and_then(
      two_elements_fuzzer(
        test_node_key_prefix,
        anchor_is_root,
        node_has_link,
        if is_ascending {
          Ascending
        } else {
          Descending
        },
      ),
    )
  let (
    script_hash,
    anchor_input,
    inputs,
    continued_anchor_output,
    node_output,
    mint_value,
  ) <-
    fuzz.and_then(continued_anchor_and_new_node_fixture(anchor_is_root, args))
  fuzz.constant(
    InsertOrderedArgs {
      direction,
      script_hash,
      expected_anchor_input: anchor_input,
      inputs,
      continued_anchor_output,
      node_output,
      mint_value,
    },
  )
}

fn insert_ordered_with_extra_list_inputs_fuzzer() -> Fuzzer<InsertOrderedArgs> {
  let InsertOrderedArgs {
    direction,
    script_hash,
    expected_anchor_input,
    inputs: _inputs,
    continued_anchor_output,
    node_output,
    mint_value,
  } <- fuzz.and_then(insert_ordered_fuzzer())
  let extra_inputs <- fuzz.and_then(extra_list_inputs_fuzzer(script_hash))
  let inputs <-
    fuzz.and_then(
      utils.inputs_with_expected_inputs_fuzzer(
        script_hash,
        [expected_anchor_input, ..extra_inputs],
      ),
    )
  fuzz.constant(
    InsertOrderedArgs {
      direction,
      script_hash,
      expected_anchor_input,
      inputs,
      continued_anchor_output,
      node_output,
      mint_value,
    },
  )
}

fn insert_descending_between_root_and_first_node_fuzzer() -> Fuzzer<
  (ScriptHash, Input, List<Input>, Output, Output, Value),
> {
  let script_hash = #"00000000000000000000000000000000000000000000000000000000"
  let existing_first_node_key =
    #"000000000000000000000000000000000000000000000000000000"
  let inserted_node_key =
    #"000000000000000000000000000000000000000000000000000001"
  let root_input =
    Input {
      output_reference: OutputReference {
        transaction_id: #"0000000000000000000000000000000000000000000000000000000000000000",
        output_index: 0,
      },
      output: Output {
        address: Address {
          payment_credential: Script(script_hash),
          stake_credential: None,
        },
        value: assets.from_lovelace(min_lovelace)
          |> assets.merge(assets.from_asset(script_hash, test_root_key, 1)),
        datum: InlineDatum(
          Element { data: Root(b_data), link: Some(existing_first_node_key) },
        ),
        reference_script: None,
      },
    }
  let cont_root_output =
    Output {
      address: Address {
        payment_credential: Script(script_hash),
        stake_credential: None,
      },
      value: assets.from_lovelace(min_lovelace)
        |> assets.merge(assets.from_asset(script_hash, test_root_key, 1)),
      datum: InlineDatum(
        Element { data: Root(b_data), link: Some(inserted_node_key) },
      ),
      reference_script: None,
    }
  let node_output =
    Output {
      address: Address {
        payment_credential: Script(script_hash),
        stake_credential: None,
      },
      value: assets.from_lovelace(min_lovelace)
        |> assets.merge(
            assets.from_asset(
              script_hash,
              test_node_key_prefix |> bytearray.concat(inserted_node_key),
              1,
            ),
          ),
      datum: InlineDatum(
        Element { data: Node(b_data), link: Some(existing_first_node_key) },
      ),
      reference_script: None,
    }
  let mint_value =
    assets.from_asset(
      script_hash,
      test_node_key_prefix |> bytearray.concat(inserted_node_key),
      1,
    )
  let inputs <-
    fuzz.and_then(
      utils.inputs_with_expected_inputs_fuzzer(script_hash, [root_input]),
    )
  fuzz.constant(
    (script_hash, root_input, inputs, cont_root_output, node_output, mint_value),
  )
}

fn insert_policy_id(
  script_hash: ScriptHash,
  mutation: InsertMutation,
) -> PolicyId {
  when mutation is {
    InsertBadPolicy -> blake2b_224(script_hash)
    _ -> script_hash
  }
}

fn insert_continued_anchor_output(
  continued_anchor_output: Output,
  mutation: InsertMutation,
) -> Output {
  when mutation is {
    InsertBadContinuedAnchorDestination ->
      alter_output_address(continued_anchor_output)
    InsertBadContinuedAnchorLink -> alter_output_link(continued_anchor_output)
    _ -> continued_anchor_output
  }
}

fn insert_node_output(node_output: Output, mutation: InsertMutation) -> Output {
  when mutation is {
    InsertBadNodeDestination -> alter_output_address(node_output)
    InsertBadNodeLink -> alter_output_link(node_output)
    _ -> node_output
  }
}

fn insert_mint_value(
  mint_value: Value,
  script_hash: ScriptHash,
  mutation: InsertMutation,
) -> Value {
  when mutation is {
    InsertBadMint -> assets.zero
    InsertExtraMint -> mint_value |> add_extra_mint(script_hash)
    _ -> mint_value
  }
}

fn insert_callback_result(mutation: InsertMutation) -> Bool {
  when mutation is {
    InsertBadValidator -> False
    _ -> True
  }
}

fn run_ordered_insert_case(
  insert_ordered_args: InsertOrderedArgs,
  mutation: InsertMutation,
  check_anchor_input: Bool,
) -> Bool {
  let InsertOrderedArgs {
    direction,
    script_hash,
    expected_anchor_input,
    inputs,
    continued_anchor_output,
    node_output,
    mint_value,
  } = insert_ordered_args
  let insert_fn =
    when direction is {
      InsertAscending -> insert_ascending
      InsertDescending -> insert_descending
    }
  {
    let
      anchor_input,
      anchor_lovelace_change,
      _m_anchor_key,
      _anchor_data,
      new_node_lovelace,
      _new_key,
      _new_node_data,
      _new_node_link,
    <-
      insert_fn(
        insert_continued_anchor_output(continued_anchor_output, mutation),
        insert_node_output(node_output, mutation),
        inputs,
        insert_mint_value(mint_value, script_hash, mutation),
      )
    when check_anchor_input is {
      True -> {
        expect
          anchor_input.output_reference == expected_anchor_input.output_reference
        expect
          anchor_input.output.address == expected_anchor_input.output.address
        expect_structural_lovelace_change(
          anchor_lovelace_change,
          new_node_lovelace,
          insert_callback_result(mutation),
        )
      }
      False ->
        expect_structural_lovelace_change(
          anchor_lovelace_change,
          new_node_lovelace,
          insert_callback_result(mutation),
        )
    }
  }
    |> eval_runner(insert_policy_id(script_hash, mutation))
}

fn run_descending_between_root_and_first_node_case(
  args: (ScriptHash, Input, List<Input>, Output, Output, Value),
) -> Bool {
  let (
    script_hash,
    root_input,
    inputs,
    cont_root_output,
    node_output,
    mint_value,
  ) = args
  run_ordered_insert_case(
    InsertOrderedArgs {
      direction: InsertDescending,
      script_hash,
      expected_anchor_input: root_input,
      inputs,
      continued_anchor_output: cont_root_output,
      node_output,
      mint_value,
    },
    InsertNoMutation,
    True,
  )
}

fn run_append_case(
  append_args: (ScriptHash, Input, List<Input>, Output, Output, Value),
  mutation: InsertMutation,
  check_anchor_input: Bool,
) -> Bool {
  let (
    script_hash,
    expected_anchor_input,
    inputs,
    continued_anchor_output,
    node_output,
    mint_value,
  ) = append_args
  {
    let
      anchor_input,
      anchor_lovelace_change,
      _m_anchor_key,
      _anchor_data,
      new_node_lovelace,
      _new_key,
      _new_node_data,
    <-
      append_unordered(
        insert_continued_anchor_output(continued_anchor_output, mutation),
        insert_node_output(node_output, mutation),
        inputs,
        insert_mint_value(mint_value, script_hash, mutation),
      )
    when check_anchor_input is {
      True -> {
        expect
          anchor_input.output_reference == expected_anchor_input.output_reference
        expect_structural_lovelace_change(
          anchor_lovelace_change,
          new_node_lovelace,
          insert_callback_result(mutation),
        )
      }
      False ->
        expect_structural_lovelace_change(
          anchor_lovelace_change,
          new_node_lovelace,
          insert_callback_result(mutation),
        )
    }
  }
    |> eval_runner(insert_policy_id(script_hash, mutation))
}

fn run_prepend_case(
  prepend_args: (ScriptHash, Input, List<Input>, Output, Output, Value),
  mutation: InsertMutation,
  check_root_input: Bool,
) -> Bool {
  let (
    script_hash,
    root_input,
    inputs,
    cont_root_output,
    node_output,
    mint_value,
  ) = prepend_args
  {
    let
      scanned_root_input,
      root_lovelace_change,
      _root_data,
      new_node_lovelace,
      _new_key,
      _new_node_data,
      _new_node_link,
    <-
      prepend_unordered(
        insert_continued_anchor_output(cont_root_output, mutation),
        insert_node_output(node_output, mutation),
        inputs,
        insert_mint_value(mint_value, script_hash, mutation),
      )
    when check_root_input is {
      True -> {
        expect
          scanned_root_input.output_reference == root_input.output_reference
        expect_structural_lovelace_change(
          root_lovelace_change,
          new_node_lovelace,
          insert_callback_result(mutation),
        )
      }
      False ->
        expect_structural_lovelace_change(
          root_lovelace_change,
          new_node_lovelace,
          insert_callback_result(mutation),
        )
    }
  }
    |> eval_runner(insert_policy_id(script_hash, mutation))
}

test success__insert_descending__between_root_and_first_node(
  args via insert_descending_between_root_and_first_node_fuzzer(),
) {
  run_descending_between_root_and_first_node_case(args)
}

test success__insert_ordered(insert_ordered_args via insert_ordered_fuzzer()) {
  run_ordered_insert_case(insert_ordered_args, InsertNoMutation, True)
}

test fail__insert_ordered__bad_nft_symbol(
  insert_ordered_args via insert_ordered_fuzzer(),
) fail {
  run_ordered_insert_case(insert_ordered_args, InsertBadPolicy, False)
}

test fail__insert_ordered__bad_continued_anchor_destination(
  insert_ordered_args via insert_ordered_fuzzer(),
) fail {
  run_ordered_insert_case(
    insert_ordered_args,
    InsertBadContinuedAnchorDestination,
    False,
  )
}

test fail__insert_ordered__bad_node_destination(
  insert_ordered_args via insert_ordered_fuzzer(),
) fail {
  run_ordered_insert_case(insert_ordered_args, InsertBadNodeDestination, False)
}

test fail__insert_ordered__bad_continued_anchor_link(
  insert_ordered_args via insert_ordered_fuzzer(),
) fail {
  run_ordered_insert_case(
    insert_ordered_args,
    InsertBadContinuedAnchorLink,
    False,
  )
}

test fail__insert_ordered__bad_node_link(
  insert_ordered_args via insert_ordered_fuzzer(),
) fail {
  run_ordered_insert_case(insert_ordered_args, InsertBadNodeLink, False)
}

test fail__insert_ordered__bad_additional_validator(
  insert_ordered_args via insert_ordered_fuzzer(),
) fail {
  run_ordered_insert_case(insert_ordered_args, InsertBadValidator, False)
}

test fail__insert_ordered__bad_mint(
  insert_ordered_args via insert_ordered_fuzzer(),
) fail {
  run_ordered_insert_case(insert_ordered_args, InsertBadMint, False)
}

test fail__insert_ordered__extra_mint(
  insert_ordered_args via insert_ordered_fuzzer(),
) fail {
  run_ordered_insert_case(insert_ordered_args, InsertExtraMint, False)
}

test fail__insert_ordered__extra_nft_policy_input(
  insert_ordered_args via insert_ordered_with_extra_list_inputs_fuzzer(),
) fail {
  run_ordered_insert_case(insert_ordered_args, InsertNoMutation, False)
}

fn append_unordered_fuzzer(
  node_has_link: Bool,
) -> Fuzzer<(ScriptHash, Input, List<Input>, Output, Output, Value)> {
  let anchor_is_root <- fuzz.and_then(fuzz.bool())
  let args <-
    fuzz.and_then(
      two_elements_fuzzer(
        test_node_key_prefix,
        anchor_is_root,
        node_has_link,
        Unordered,
      ),
    )
  continued_anchor_and_new_node_fixture(anchor_is_root, args)
}

fn append_unordered_with_extra_list_inputs_fuzzer(
  node_has_link: Bool,
) -> Fuzzer<(ScriptHash, Input, List<Input>, Output, Output, Value)> {
  let (
    script_hash,
    anchor_input,
    _inputs,
    continued_anchor_output,
    node_output,
    mint_value,
  ) <- fuzz.and_then(append_unordered_fuzzer(node_has_link))
  let extra_inputs <- fuzz.and_then(extra_list_inputs_fuzzer(script_hash))
  let inputs <-
    fuzz.and_then(
      utils.inputs_with_expected_inputs_fuzzer(
        script_hash,
        [anchor_input, ..extra_inputs],
      ),
    )
  fuzz.constant(
    (
      script_hash,
      anchor_input,
      inputs,
      continued_anchor_output,
      node_output,
      mint_value,
    ),
  )
}

test success__append_unordered(
  append_unordered_args via append_unordered_fuzzer(False),
) {
  run_append_case(append_unordered_args, InsertNoMutation, True)
}

test fail__append_unordered__node_has_link(
  append_unordered_args via append_unordered_fuzzer(True),
) fail {
  run_append_case(append_unordered_args, InsertNoMutation, False)
}

test fail__append_unordered__bad_nft_symbol(
  append_unordered_args via append_unordered_fuzzer(False),
) fail {
  run_append_case(append_unordered_args, InsertBadPolicy, False)
}

test fail__append_unordered__bad_continued_anchor_destination(
  append_unordered_args via append_unordered_fuzzer(False),
) fail {
  run_append_case(
    append_unordered_args,
    InsertBadContinuedAnchorDestination,
    False,
  )
}

test fail__append_unordered__bad_node_destination(
  append_unordered_args via append_unordered_fuzzer(False),
) fail {
  run_append_case(append_unordered_args, InsertBadNodeDestination, False)
}

test fail__append_unordered__bad_continued_anchor_link(
  append_unordered_args via append_unordered_fuzzer(False),
) fail {
  run_append_case(append_unordered_args, InsertBadContinuedAnchorLink, False)
}

test fail__append_unordered__bad_node_link(
  append_unordered_args via append_unordered_fuzzer(False),
) fail {
  run_append_case(append_unordered_args, InsertBadNodeLink, False)
}

test fail__append_unordered__bad_mint(
  append_unordered_args via append_unordered_fuzzer(False),
) fail {
  run_append_case(append_unordered_args, InsertBadMint, False)
}

test fail__append_unordered__extra_mint(
  append_unordered_args via append_unordered_fuzzer(False),
) fail {
  run_append_case(append_unordered_args, InsertExtraMint, False)
}

test fail__append_unordered__extra_nft_policy_input(
  append_unordered_args via append_unordered_with_extra_list_inputs_fuzzer(
    False,
  ),
) fail {
  run_append_case(append_unordered_args, InsertNoMutation, False)
}

fn prepend_unordered_fuzzer(
  anchor_is_root: Bool,
) -> Fuzzer<(ScriptHash, Input, List<Input>, Output, Output, Value)> {
  let node_has_link <- fuzz.and_then(fuzz.bool())
  let args <-
    fuzz.and_then(
      two_elements_fuzzer(
        test_node_key_prefix,
        anchor_is_root,
        node_has_link,
        Unordered,
      ),
    )
  continued_anchor_and_new_node_fixture(anchor_is_root, args)
}

fn prepend_unordered_with_extra_list_inputs_fuzzer(
  anchor_is_root: Bool,
) -> Fuzzer<(ScriptHash, Input, List<Input>, Output, Output, Value)> {
  let (
    script_hash,
    anchor_input,
    _inputs,
    continued_anchor_output,
    node_output,
    mint_value,
  ) <- fuzz.and_then(prepend_unordered_fuzzer(anchor_is_root))
  let extra_inputs <- fuzz.and_then(extra_list_inputs_fuzzer(script_hash))
  let inputs <-
    fuzz.and_then(
      utils.inputs_with_expected_inputs_fuzzer(
        script_hash,
        [anchor_input, ..extra_inputs],
      ),
    )
  fuzz.constant(
    (
      script_hash,
      anchor_input,
      inputs,
      continued_anchor_output,
      node_output,
      mint_value,
    ),
  )
}

test success__prepend_unordered(
  prepend_unordered_args via prepend_unordered_fuzzer(True),
) {
  run_prepend_case(prepend_unordered_args, InsertNoMutation, True)
}

test fail__prepend_unordered__non_root_anchor(
  prepend_unordered_args via prepend_unordered_fuzzer(False),
) fail {
  run_prepend_case(prepend_unordered_args, InsertNoMutation, False)
}

test fail__prepend_unordered__bad_nft_symbol(
  prepend_unordered_args via prepend_unordered_fuzzer(True),
) fail {
  run_prepend_case(prepend_unordered_args, InsertBadPolicy, False)
}

test fail__prepend_unordered__bad_continued_root_destination(
  prepend_unordered_args via prepend_unordered_fuzzer(True),
) fail {
  run_prepend_case(
    prepend_unordered_args,
    InsertBadContinuedAnchorDestination,
    False,
  )
}

test fail__prepend_unordered__bad_node_destination(
  prepend_unordered_args via prepend_unordered_fuzzer(True),
) fail {
  run_prepend_case(prepend_unordered_args, InsertBadNodeDestination, False)
}

test fail__prepend_unordered__bad_continued_root_link(
  prepend_unordered_args via prepend_unordered_fuzzer(True),
) fail {
  run_prepend_case(prepend_unordered_args, InsertBadContinuedAnchorLink, False)
}

test fail__prepend_unordered__bad_node_link(
  prepend_unordered_args via prepend_unordered_fuzzer(True),
) fail {
  run_prepend_case(prepend_unordered_args, InsertBadNodeLink, False)
}

test fail__prepend_unordered__bad_mint(
  prepend_unordered_args via prepend_unordered_fuzzer(True),
) fail {
  run_prepend_case(prepend_unordered_args, InsertBadMint, False)
}

test fail__prepend_unordered__extra_mint(
  prepend_unordered_args via prepend_unordered_fuzzer(True),
) fail {
  run_prepend_case(prepend_unordered_args, InsertExtraMint, False)
}

test fail__prepend_unordered__extra_nft_policy_input(
  prepend_unordered_args via prepend_unordered_with_extra_list_inputs_fuzzer(
    True,
  ),
) fail {
  run_prepend_case(prepend_unordered_args, InsertNoMutation, False)
}

fn remove_fuzzer() -> Fuzzer<
  (ScriptHash, Input, Input, List<Input>, Output, Value),
> {
  let anchor_is_root <- fuzz.and_then(fuzz.bool())
  anchor_and_linked_node_fuzzer(anchor_is_root)
}

fn remove_with_extra_list_inputs_fuzzer() -> Fuzzer<
  (ScriptHash, Input, Input, List<Input>, Output, Value),
> {
  let (
    script_hash,
    expected_anchor_input,
    expected_removing_node_input,
    _inputs,
    continued_anchor_output,
    mint_value,
  ) <- fuzz.and_then(remove_fuzzer())
  let extra_inputs <- fuzz.and_then(extra_list_inputs_fuzzer(script_hash))
  let inputs <-
    fuzz.and_then(
      utils.inputs_with_expected_inputs_fuzzer(
        script_hash,
        [expected_anchor_input, expected_removing_node_input, ..extra_inputs],
      ),
    )
  fuzz.constant(
    (
      script_hash,
      expected_anchor_input,
      expected_removing_node_input,
      inputs,
      continued_anchor_output,
      mint_value,
    ),
  )
}

fn remove_policy_id(
  script_hash: ScriptHash,
  mutation: RemoveMutation,
) -> PolicyId {
  when mutation is {
    RemoveBadPolicy -> blake2b_224(script_hash)
    _ -> script_hash
  }
}

fn remove_anchor_out_ref(
  anchor_out_ref: OutputReference,
  mutation: RemoveMutation,
) -> OutputReference {
  when mutation is {
    RemoveBadAnchorOutRef ->
      OutputReference {
        ..anchor_out_ref,
        output_index: anchor_out_ref.output_index + 513,
      }
    _ -> anchor_out_ref
  }
}

fn remove_continued_anchor_output(
  continued_anchor_output: Output,
  mutation: RemoveMutation,
) -> Output {
  when mutation is {
    RemoveBadContinuedAnchorDestination ->
      alter_output_address(continued_anchor_output)
    RemoveBadContinuedAnchorLink -> alter_output_link(continued_anchor_output)
    _ -> continued_anchor_output
  }
}

fn remove_mint_value(
  mint_value: Value,
  continued_anchor_output: Output,
  script_hash: ScriptHash,
  mutation: RemoveMutation,
) -> Value {
  when mutation is {
    RemoveBadMint -> assets.zero
    RemoveExtraMint -> mint_value |> add_extra_mint(script_hash)
    RemoveAnchorBurnt ->
      continued_anchor_output.value
        |> assets.without_lovelace
        |> assets.negate
    _ -> mint_value
  }
}

fn remove_callback_result(mutation: RemoveMutation) -> Bool {
  when mutation is {
    RemoveBadValidator -> False
    _ -> True
  }
}

fn run_remove_case(
  remove_args: (ScriptHash, Input, Input, List<Input>, Output, Value),
  mutation: RemoveMutation,
  check_inputs: Bool,
) -> Bool {
  let (
    script_hash,
    expected_anchor_input,
    expected_removing_node_input,
    inputs,
    continued_anchor_output,
    mint_value,
  ) = remove_args
  {
    let
      anchor_input,
      anchor_lovelace_change,
      _m_anchor_key,
      _anchor_data,
      removing_node_input,
      removing_node_lovelace,
      _removing_key,
      _removing_node_data,
      _removing_node_link,
    <-
      remove(
        remove_anchor_out_ref(expected_anchor_input.output_reference, mutation),
        remove_continued_anchor_output(continued_anchor_output, mutation),
        inputs,
        remove_mint_value(
          mint_value,
          continued_anchor_output,
          script_hash,
          mutation,
        ),
      )
    when check_inputs is {
      True -> {
        expect
          anchor_input.output_reference == expected_anchor_input.output_reference
        expect
          removing_node_input.output_reference == expected_removing_node_input.output_reference
        expect_structural_lovelace_change(
          anchor_lovelace_change,
          removing_node_lovelace,
          remove_callback_result(mutation),
        )
      }
      False ->
        expect_structural_lovelace_change(
          anchor_lovelace_change,
          removing_node_lovelace,
          remove_callback_result(mutation),
        )
    }
  }
    |> eval_runner(remove_policy_id(script_hash, mutation))
}

test success__remove(remove_args via remove_fuzzer()) {
  run_remove_case(remove_args, RemoveNoMutation, True)
}

test fail__remove__bad_nft_symbol(remove_args via remove_fuzzer()) fail {
  run_remove_case(remove_args, RemoveBadPolicy, False)
}

test fail__remove__bad_anchor_outref(remove_args via remove_fuzzer()) fail {
  run_remove_case(remove_args, RemoveBadAnchorOutRef, False)
}

test fail__remove__bad_continued_anchor_destination(
  remove_args via remove_fuzzer(),
) fail {
  run_remove_case(remove_args, RemoveBadContinuedAnchorDestination, False)
}

test fail__remove__bad_continued_anchor_link(
  remove_args via remove_fuzzer(),
) fail {
  run_remove_case(remove_args, RemoveBadContinuedAnchorLink, False)
}

test fail__remove__bad_additional_validator(
  remove_args via remove_fuzzer(),
) fail {
  run_remove_case(remove_args, RemoveBadValidator, False)
}

test fail__remove__bad_mint(remove_args via remove_fuzzer()) fail {
  run_remove_case(remove_args, RemoveBadMint, False)
}

test fail__remove__extra_mint(remove_args via remove_fuzzer()) fail {
  run_remove_case(remove_args, RemoveExtraMint, False)
}

test fail__remove__anchor_burnt(remove_args via remove_fuzzer()) fail {
  run_remove_case(remove_args, RemoveAnchorBurnt, False)
}

test fail__remove__extra_nft_policy_input(
  remove_args via remove_with_extra_list_inputs_fuzzer(),
) fail {
  run_remove_case(remove_args, RemoveNoMutation, False)
}

fn anchor_and_linked_node_fuzzer(
  anchor_is_root: Bool,
) -> Fuzzer<(ScriptHash, Input, Input, List<Input>, Output, Value)> {
  let node_has_link <- fuzz.and_then(fuzz.bool())
  let (script_hash, anchor_input, linked_node_input) <-
    fuzz.and_then(
      two_elements_fuzzer(
        test_node_key_prefix,
        anchor_is_root,
        node_has_link,
        Unordered,
      ),
    )
  expect InlineDatum(node_datum_data) = linked_node_input.output.datum
  expect Element { link: nodes_link, .. }: GenericElement = node_datum_data
  let continued_anchor_element: GenericElement =
    Element(
      if anchor_is_root {
        Root(b_data)
      } else {
        Node(b_data)
      },
      nodes_link,
    )
  let continued_anchor_output: Output =
    Output {
      ..anchor_input.output,
      datum: InlineDatum(continued_anchor_element),
    }
  let inputs <-
    fuzz.and_then(
      utils.inputs_with_expected_inputs_fuzzer(
        script_hash,
        [anchor_input, linked_node_input],
      ),
    )
  fuzz.constant(
    (
      script_hash,
      anchor_input,
      linked_node_input,
      inputs,
      continued_anchor_output,
      linked_node_input.output.value |> assets.without_lovelace |> assets.negate,
    ),
  )
}

fn fold_from_root_fuzzer(
  anchor_is_root: Bool,
) -> Fuzzer<(ScriptHash, Input, Input, List<Input>, Output, Value)> {
  anchor_and_linked_node_fuzzer(anchor_is_root)
}

fn fold_from_root_with_extra_list_inputs_fuzzer(
  anchor_is_root: Bool,
) -> Fuzzer<(ScriptHash, Input, Input, List<Input>, Output, Value)> {
  let (
    script_hash,
    root_input,
    node_input,
    _inputs,
    cont_root_output,
    mint_value,
  ) <- fuzz.and_then(fold_from_root_fuzzer(anchor_is_root))
  let extra_inputs <- fuzz.and_then(extra_list_inputs_fuzzer(script_hash))
  let inputs <-
    fuzz.and_then(
      utils.inputs_with_expected_inputs_fuzzer(
        script_hash,
        [root_input, node_input, ..extra_inputs],
      ),
    )
  fuzz.constant(
    (script_hash, root_input, node_input, inputs, cont_root_output, mint_value),
  )
}

fn fold_policy_id(script_hash: ScriptHash, mutation: FoldMutation) -> PolicyId {
  when mutation is {
    FoldBadPolicy -> blake2b_224(script_hash)
    _ -> script_hash
  }
}

fn fold_anchor_out_ref(
  root_out_ref: OutputReference,
  mutation: FoldMutation,
) -> OutputReference {
  when mutation is {
    FoldBadAnchorOutRef ->
      OutputReference {
        ..root_out_ref,
        output_index: root_out_ref.output_index + 513,
      }
    _ -> root_out_ref
  }
}

fn fold_continued_root_output(
  continued_root_output: Output,
  mutation: FoldMutation,
) -> Output {
  when mutation is {
    FoldBadContinuedRootDestination ->
      alter_output_address(continued_root_output)
    FoldBadContinuedRootLink -> alter_output_link(continued_root_output)
    _ -> continued_root_output
  }
}

fn fold_mint_value(
  mint_value: Value,
  continued_root_output: Output,
  script_hash: ScriptHash,
  mutation: FoldMutation,
) -> Value {
  when mutation is {
    FoldBadMint -> assets.zero
    FoldExtraMint -> mint_value |> add_extra_mint(script_hash)
    FoldAnchorBurnt ->
      continued_root_output.value
        |> assets.without_lovelace
        |> assets.negate
    _ -> mint_value
  }
}

fn fold_callback_result(mutation: FoldMutation) -> Bool {
  when mutation is {
    FoldBadValidator -> False
    _ -> True
  }
}

fn run_fold_case(
  fold_args: (ScriptHash, Input, Input, List<Input>, Output, Value),
  mutation: FoldMutation,
  check_inputs: Bool,
) -> Bool {
  let (
    script_hash,
    root_input,
    node_input,
    inputs,
    cont_root_output,
    mint_value,
  ) = fold_args
  {
    let
      anchor_root_input,
      root_lovelace_change,
      _root_data,
      folding_node_input,
      folding_node_lovelace,
      _folding_node_key,
      _folding_node_data,
      _folding_node_link,
      _cont_root_data,
    <-
      fold_from_root(
        fold_anchor_out_ref(root_input.output_reference, mutation),
        fold_continued_root_output(cont_root_output, mutation),
        inputs,
        fold_mint_value(mint_value, cont_root_output, script_hash, mutation),
      )
    when check_inputs is {
      True -> {
        expect anchor_root_input.output_reference == root_input.output_reference
        expect
          folding_node_input.output_reference == node_input.output_reference
        expect_structural_lovelace_change(
          root_lovelace_change,
          folding_node_lovelace,
          fold_callback_result(mutation),
        )
      }
      False ->
        expect_structural_lovelace_change(
          root_lovelace_change,
          folding_node_lovelace,
          fold_callback_result(mutation),
        )
    }
  }
    |> eval_runner(fold_policy_id(script_hash, mutation))
}

test success__fold_from_root(fold_args via fold_from_root_fuzzer(True)) {
  run_fold_case(fold_args, FoldNoMutation, True)
}

test fail__fold_from_root__bad_nft_symbol(
  fold_args via fold_from_root_fuzzer(True),
) fail {
  run_fold_case(fold_args, FoldBadPolicy, False)
}

test fail__fold_from_root__bad_anchor_outref(
  fold_args via fold_from_root_fuzzer(True),
) fail {
  run_fold_case(fold_args, FoldBadAnchorOutRef, False)
}

test fail__fold_from_root__bad_continued_root_destination(
  fold_args via fold_from_root_fuzzer(True),
) fail {
  run_fold_case(fold_args, FoldBadContinuedRootDestination, False)
}

test fail__fold_from_root__bad_continued_root_link(
  fold_args via fold_from_root_fuzzer(True),
) fail {
  run_fold_case(fold_args, FoldBadContinuedRootLink, False)
}

test fail__fold_from_root__bad_additional_validator(
  fold_args via fold_from_root_fuzzer(True),
) fail {
  run_fold_case(fold_args, FoldBadValidator, False)
}

test fail__fold_from_root__bad_mint(
  fold_args via fold_from_root_fuzzer(True),
) fail {
  run_fold_case(fold_args, FoldBadMint, False)
}

test fail__fold_from_root__extra_mint(
  fold_args via fold_from_root_fuzzer(True),
) fail {
  run_fold_case(fold_args, FoldExtraMint, False)
}

test fail__fold_from_root__bad_anchor(
  fold_args via fold_from_root_fuzzer(False),
) fail {
  run_fold_case(fold_args, FoldNoMutation, False)
}

test fail__fold_from_root__anchor_burnt(
  fold_args via fold_from_root_fuzzer(True),
) fail {
  run_fold_case(fold_args, FoldAnchorBurnt, False)
}

test fail__fold_from_root__extra_nft_policy_input(
  fold_args via fold_from_root_with_extra_list_inputs_fuzzer(True),
) fail {
  run_fold_case(fold_args, FoldNoMutation, False)
}

test success__spend_for_adding_or_removing_an_element(
  init_values via init_fuzzer(True, None),
) {
  let InitArgs { script_hash, .. } = init_values
  spend_for_adding_or_removing_an_element(
    script_hash,
    assets.from_asset(script_hash, test_root_key, 1),
  )
}

test fail__spend_for_adding_or_removing_an_element__wrong_policy(
  init_values via init_fuzzer(True, None),
) fail {
  let InitArgs { script_hash, .. } = init_values
  spend_for_adding_or_removing_an_element(
    script_hash,
    assets.from_asset(blake2b_224(script_hash), test_root_key, 1),
  )
}

fn run_root_update_case(
  init_values: InitArgs,
  mutation: UpdateRootMutation,
) -> Bool {
  let InitArgs { nonce_out_ref, script_hash, script_output, .. } = init_values
  let root_input =
    Input { output_reference: nonce_out_ref, output: script_output }
  let updated_data = builtin.b_data(#"01")
  let continued_output =
    Output {
      ..script_output,
      datum: InlineDatum(Element { data: Root(updated_data), link: None }),
    }
  let input_index =
    when mutation is {
      UpdateRootBadInputIndex -> 1
      _ -> 0
    }
  let output_index =
    when mutation is {
      UpdateRootBadOutputIndex -> 1
      _ -> 0
    }
  let outputs =
    when mutation is {
      UpdateRootBadLink -> [alter_output_link(continued_output)]
      UpdateRootBadOutputIndex ->
        [continued_output, alter_output_link(continued_output)]
      _ -> [continued_output]
    }
  let mint_value =
    when mutation is {
      UpdateRootMintedListAsset ->
        assets.from_asset(script_hash, test_root_key, 1)
      _ -> assets.zero
    }

  {
    let
      element_address,
      lovelace_change,
      m_node_key,
      input_data,
      output_data,
      link,
    <-
      spend_for_updating_elements_data(
        input_index,
        output_index,
        nonce_out_ref,
        [root_input],
        outputs,
        mint_value,
      )
    when mutation is {
      UpdateRootNoMutation -> {
        expect element_address == script_output.address
        expect lovelace_change == 0
        expect m_node_key == None
        expect input_data == b_data
        expect output_data == updated_data
        expect link == None
        True
      }
      _ -> True
    }
  }
    |> eval_runner(script_hash)
}

test success__spend_for_updating_elements_data__root(
  init_values via init_fuzzer(True, None),
) {
  run_root_update_case(init_values, UpdateRootNoMutation)
}

test success__spend_for_updating_elements_data__node(
  node_values via node_values_fuzzer(),
) {
  let (script_hash, _root_input, node_input) = node_values
  expect InlineDatum(node_datum_data) = node_input.output.datum
  expect Element { link: node_link, .. }: GenericElement = node_datum_data
  let updated_data = builtin.b_data(#"02")
  let continued_output =
    Output {
      ..node_input.output,
      datum: InlineDatum(Element { data: Node(updated_data), link: node_link }),
    }

  {
    let
      element_address,
      lovelace_change,
      m_node_key,
      input_data,
      output_data,
      link,
    <-
      spend_for_updating_elements_data(
        0,
        0,
        node_input.output_reference,
        [node_input],
        [continued_output],
        assets.zero,
      )
    expect Some(_) = m_node_key
    expect and {
        element_address == node_input.output.address,
        lovelace_change == 0,
        input_data == b_data,
        output_data == updated_data,
        link == node_link,
      }
    True
  }
    |> eval_runner(script_hash)
}

test fail__spend_for_updating_elements_data__bad_link(
  init_values via init_fuzzer(True, None),
) fail {
  run_root_update_case(init_values, UpdateRootBadLink)
}

test fail__spend_for_updating_elements_data__minted_list_asset(
  init_values via init_fuzzer(True, None),
) fail {
  run_root_update_case(init_values, UpdateRootMintedListAsset)
}

test fail__spend_for_updating_elements_data__bad_input_index(
  init_values via init_fuzzer(True, None),
) fail {
  run_root_update_case(init_values, UpdateRootBadInputIndex)
}

test fail__spend_for_updating_elements_data__bad_output_index(
  init_values via init_fuzzer(True, None),
) fail {
  run_root_update_case(init_values, UpdateRootBadOutputIndex)
}

test success__get_element_info__root(init_values via init_fuzzer(True, None)) {
  let InitArgs { script_hash, script_output, .. } = init_values
  {
    let
      element_address,
      lovelace,
      m_node_key,
      data,
      link,
    <- get_element_info(script_output)
    expect and {
        element_address == script_output.address,
        lovelace == min_lovelace,
        m_node_key == None,
        data == b_data,
        link == None,
      }
    True
  }
    |> eval_runner(script_hash)
}

test success__get_element_info__node(node_values via node_values_fuzzer()) {
  let (script_hash, _root_input, node_input) = node_values
  expect InlineDatum(node_datum_data) = node_input.output.datum
  expect Element { link: node_link, .. }: GenericElement = node_datum_data

  {
    let
      element_address,
      lovelace,
      m_node_key,
      data,
      link,
    <- get_element_info(node_input.output)
    expect Some(_) = m_node_key
    expect and {
        element_address == node_input.output.address,
        lovelace == min_lovelace,
        data == b_data,
        link == node_link,
      }
    True
  }
    |> eval_runner(script_hash)
}

test fail__get_element_info__bad_node_prefix(
  node_values via node_values_fuzzer(),
) fail {
  let (script_hash, _root_input, node_input) = node_values
  {
    let
      _element_address,
      _lovelace,
      _m_node_key,
      _data,
      _link,
    <- get_element_info(node_input.output)
    True
  }
    |> run_element_with(script_hash, test_root_key, #"ff", 1)
}

test success__get_root_element_info(init_values via init_fuzzer(True, None)) {
  let InitArgs { script_hash, script_output, .. } = init_values
  {
    let
      element_address,
      lovelace,
      data,
      link,
    <- get_root_element_info(script_output)
    expect and {
        element_address == script_output.address,
        lovelace == min_lovelace,
        data == b_data,
        link == None,
      }
    True
  }
    |> run_root_with(script_hash, test_root_key)
}

test fail__get_root_element_info__node(
  node_values via node_values_fuzzer(),
) fail {
  let (script_hash, _root_input, node_input) = node_values
  {
    let
      _element_address,
      _lovelace,
      _data,
      _link,
    <- get_root_element_info(node_input.output)
    True
  }
    |> run_root_with(script_hash, test_root_key)
}

test success__get_node_element_info(node_values via node_values_fuzzer()) {
  let (script_hash, _root_input, node_input) = node_values
  expect InlineDatum(node_datum_data) = node_input.output.datum
  expect Element { link: node_link, .. }: GenericElement = node_datum_data

  {
    let
      element_address,
      lovelace,
      node_key,
      data,
      link,
    <- get_node_element_info(node_input.output)
    expect and {
        element_address == node_input.output.address,
        lovelace == min_lovelace,
        bytearray.length(node_key) == 32 - test_node_key_prefix_length,
        data == b_data,
        link == node_link,
      }
    True
  }
    |> run_node_with(
        script_hash,
        test_node_key_prefix,
        test_node_key_prefix_length,
      )
}

test fail__get_node_element_info__root(
  init_values via init_fuzzer(True, None),
) fail {
  let InitArgs { script_hash, script_output, .. } = init_values
  {
    let
      _element_address,
      _lovelace,
      _node_key,
      _data,
      _link,
    <- get_node_element_info(script_output)
    True
  }
    |> run_node_with(
        script_hash,
        test_node_key_prefix,
        test_node_key_prefix_length,
      )
}

test fail__get_node_element_info__bad_node_prefix(
  node_values via node_values_fuzzer(),
) fail {
  let (script_hash, _root_input, node_input) = node_values
  {
    let
      _element_address,
      _lovelace,
      _node_key,
      _data,
      _link,
    <- get_node_element_info(node_input.output)
    True
  }
    |> run_node_with(script_hash, #"ff", 1)
}
