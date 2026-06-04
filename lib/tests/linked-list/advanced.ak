use aiken/builtin
use aiken/collection/dict
use aiken/crypto.{ScriptHash, blake2b_224}
use aiken/fuzz
use aiken/primitive/bytearray.{from_int_big_endian}
use aiken_design_patterns/linked_list.{
  Element, ElementEval, GenericElement, Node, Root, run_element_with,
  run_node_with, run_root_with,
}
use aiken_design_patterns/linked_list/advanced.{
  append_unordered, deinit, fold_from_root, get_element_info,
  get_node_element_info, get_root_element_info, init, insert_ascending,
  insert_descending, prepend_unordered, remove,
  spend_for_adding_or_removing_an_element, spend_for_updating_elements_data,
}
use aiken_design_patterns/linked_list/internal.{
  validate_no_reserved_list_asset_changes,
}
use aiken_design_patterns/linked_list/nested.{
  Ascending, Descending, ListOrdering, Unordered,
}
use aiken_design_patterns/utils
use cardano/address.{Address, Script}
use cardano/assets.{AssetName, PolicyId, Value}
use cardano/fuzz as cardano_fuzz
use cardano/transaction.{InlineDatum, Input, Output, OutputReference}

const min_lovelace = 2_000_000

const test_root_key = #""

const test_node_key_prefix = #"4e"

const test_node_key_prefix_length = bytearray.length(test_node_key_prefix)

const extra_asset_name = #"6578747261"

type InitMutation {
  InitNoMutation
  InitBadValidator
  InitExtraMint
}

type DeinitMutation {
  DeinitNoMutation
  DeinitExtraMint
}

type InsertMutation {
  InsertNoMutation
  InsertBadValidator
  InsertChangedAnchorRef
  InsertReservedRootMint
  InsertReservedNodeMint
}

type RemoveMutation {
  RemoveNoMutation
  RemoveBadValidator
  RemoveChangedAnchorRef
  RemoveReservedRootMint
  RemoveReservedNodeMint
}

type FoldMutation {
  FoldNoMutation
  FoldBadValidator
  FoldChangedRootRef
}

type UpdateMutation {
  UpdateNoMutation
  UpdateBadValidator
  UpdateBadLink
  UpdateBadInputIndex
  UpdateBadOutputIndex
  UpdateMintedListAsset
}

type InitArgs {
  inputs: List<Input>,
  nonce_out_ref: OutputReference,
  script_hash: ScriptHash,
  script_output: Output,
  root_data: Data,
  root_ref_script: Option<ScriptHash>,
}

type DeinitArgs {
  script_hash: ScriptHash,
  root_input: Input,
  inputs: List<Input>,
}

type InsertOrderedArgs {
  is_ascending: Bool,
  script_hash: ScriptHash,
  expected_anchor_input: Input,
  expected_anchor_key: Option<ByteArray>,
  inputs: List<Input>,
  continued_anchor_output: Output,
  node_output: Output,
  mint_value: Value,
  anchor_data: Data,
  continued_anchor_data: Data,
  new_node_key: ByteArray,
  new_node_data: Data,
  new_node_link: Option<ByteArray>,
  new_node_ref_script: Option<ScriptHash>,
  expected_extra_asset_change: Pair<AssetName, Int>,
}

type AppendArgs {
  script_hash: ScriptHash,
  expected_anchor_input: Input,
  expected_anchor_key: Option<ByteArray>,
  inputs: List<Input>,
  continued_anchor_output: Output,
  node_output: Output,
  mint_value: Value,
  anchor_data: Data,
  continued_anchor_data: Data,
  new_node_key: ByteArray,
  new_node_data: Data,
  new_node_ref_script: Option<ScriptHash>,
  expected_extra_asset_change: Pair<AssetName, Int>,
}

type PrependArgs {
  script_hash: ScriptHash,
  root_input: Input,
  inputs: List<Input>,
  continued_root_output: Output,
  node_output: Output,
  mint_value: Value,
  root_data: Data,
  continued_root_data: Data,
  new_node_key: ByteArray,
  new_node_data: Data,
  new_node_link: Option<ByteArray>,
  new_node_ref_script: Option<ScriptHash>,
  expected_extra_asset_change: Pair<AssetName, Int>,
}

type RemoveArgs {
  script_hash: ScriptHash,
  expected_anchor_input: Input,
  expected_anchor_key: Option<ByteArray>,
  expected_removing_node_input: Input,
  inputs: List<Input>,
  continued_anchor_output: Output,
  mint_value: Value,
  anchor_data: Data,
  continued_anchor_data: Data,
  removing_node_key: ByteArray,
  removing_node_data: Data,
  removing_node_link: Option<ByteArray>,
  expected_extra_asset_change: Pair<AssetName, Int>,
}

type UpdateArgs {
  script_hash: ScriptHash,
  element_input: Input,
  continued_element_output: Output,
  element_key: Option<ByteArray>,
  old_data: Data,
  old_ref_script: Option<ScriptHash>,
  new_data: Data,
  new_ref_script: Option<ScriptHash>,
  link: Option<ByteArray>,
}

fn one_byte_key_from_int(n: Int) -> ByteArray {
  n |> from_int_big_endian(1)
}

fn node_asset_name(node_key: ByteArray) -> AssetName {
  test_node_key_prefix |> bytearray.concat(node_key)
}

fn element_value(script_hash: ScriptHash, asset_name: AssetName) -> Value {
  assets.from_lovelace(min_lovelace)
    |> assets.merge(assets.from_asset(script_hash, asset_name, 1))
}

fn element_output(
  script_hash: ScriptHash,
  asset_name: AssetName,
  element: Element<Data, Data>,
  reference_script: Option<ScriptHash>,
) -> Output {
  Output {
    address: Address {
      payment_credential: Script(script_hash),
      stake_credential: None,
    },
    value: element_value(script_hash, asset_name),
    datum: InlineDatum(element),
    reference_script,
  }
}

fn element_input(
  output_reference: OutputReference,
  script_hash: ScriptHash,
  asset_name: AssetName,
  element: Element<Data, Data>,
  reference_script: Option<ScriptHash>,
) -> Input {
  Input {
    output_reference,
    output: element_output(script_hash, asset_name, element, reference_script),
  }
}

fn one_mint(script_hash: ScriptHash, asset_name: AssetName) -> Value {
  assets.from_asset(script_hash, asset_name, 1)
}

fn one_burn(script_hash: ScriptHash, asset_name: AssetName) -> Value {
  assets.from_asset(script_hash, asset_name, -1)
}

fn add_extra_mint(mint_value: Value, policy_id: PolicyId) -> Value {
  assets.merge(mint_value, one_mint(policy_id, extra_asset_name))
}

fn alter_output_link(output: Output) -> Output {
  expect InlineDatum(datum_data) = output.datum
  expect Element { data, link }: GenericElement = datum_data
  Output {
    ..output,
    datum: InlineDatum(
      Element {
        data,
        link: when link is {
          None -> Some(#"ff")
          Some(_) -> None
        },
      },
    ),
  }
}

fn alter_reference_script(output: Output, script_hash: ScriptHash) -> Output {
  Output {
    ..output,
    reference_script: Some(
      script_hash |> bytearray.concat("changed-ref") |> blake2b_224,
    ),
  }
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

fn expect_extra_asset(
  other_list_assets,
  expected_extra_asset_change: Pair<AssetName, Int>,
) -> Bool {
  let Pair(asset_name, quantity) = expected_extra_asset_change
  expect dict.get(other_list_assets, asset_name) == Some(quantity)
  True
}

fn input_out_ref_matches(
  should_check: Bool,
  actual_input: Input,
  expected_input: Input,
) -> Bool {
  when should_check is {
    True -> actual_input.output_reference == expected_input.output_reference
    False -> True
  }
}

fn two_input_out_refs_match(
  should_check: Bool,
  actual_first_input: Input,
  expected_first_input: Input,
  actual_second_input: Input,
  expected_second_input: Input,
) -> Bool {
  when should_check is {
    True -> and {
        actual_first_input.output_reference == expected_first_input.output_reference,
        actual_second_input.output_reference == expected_second_input.output_reference,
      }
    False -> True
  }
}

fn reference_script_fuzzer(
  script_hash: ScriptHash,
  label: ByteArray,
) -> Fuzzer<Option<ScriptHash>> {
  fuzz.one_of(
    [None, Some(script_hash |> bytearray.concat(label) |> blake2b_224)],
  )
}

fn init_fuzzer(root_datum: Bool, link: Option<ByteArray>) -> Fuzzer<InitArgs> {
  let inputs <- fuzz.and_then(utils.user_inputs_fuzzer())
  let nonce_out_ref =
    builtin.head_list(inputs)
      |> fn(i: Input) -> OutputReference { i.output_reference }
  let script_hash <- fuzz.and_then(cardano_fuzz.policy_id())
  let root_data <- fuzz.and_then(fuzz.data())
  let root_ref_script <-
    fuzz.and_then(reference_script_fuzzer(script_hash, "init-root"))
  let script_output =
    element_output(
      script_hash,
      test_root_key,
      Element {
        data: if root_datum {
          Root(root_data)
        } else {
          Node(root_data)
        },
        link,
      },
      root_ref_script,
    )
  fuzz.constant(
    InitArgs {
      inputs,
      nonce_out_ref,
      script_hash,
      script_output,
      root_data,
      root_ref_script,
    },
  )
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

fn run_init_case(init_values: InitArgs, mutation: InitMutation) -> Bool {
  let InitArgs {
    inputs,
    nonce_out_ref,
    script_hash,
    script_output,
    root_data,
    root_ref_script,
  } = init_values
  let mint_value =
    when mutation is {
      InitExtraMint ->
        one_mint(script_hash, test_root_key) |> add_extra_mint(script_hash)
      _ -> one_mint(script_hash, test_root_key)
    }
  let callback_result =
    when mutation is {
      InitBadValidator -> False
      _ -> True
    }

  {
    let
      element_address,
      lovelace,
      callback_data,
      callback_ref_script,
    <-
      init(
        utils.utxo_is_spent(inputs, nonce_out_ref),
        script_output,
        mint_value,
      )
    expect element_address == script_output.address
    expect lovelace == min_lovelace
    expect callback_data == root_data
    expect callback_ref_script == root_ref_script
    callback_result
  }
    |> run_root_with(script_hash, test_root_key)
}

fn run_deinit_case(deinit_values: DeinitArgs, mutation: DeinitMutation) -> Bool {
  let DeinitArgs { script_hash, root_input, inputs } = deinit_values
  let mint_value =
    when mutation is {
      DeinitExtraMint ->
        one_burn(script_hash, test_root_key)
          |> assets.merge(one_burn(script_hash, extra_asset_name))
      _ -> one_burn(script_hash, test_root_key)
    }

  {
    let
      actual_root_input,
      root_lovelace,
      root_data,
    <- deinit(inputs, mint_value)
    expect actual_root_input.output_reference == root_input.output_reference
    expect actual_root_input.output.address == root_input.output.address
    expect root_lovelace == min_lovelace
    expect InlineDatum(datum_data) = root_input.output.datum
    expect Element { data: root_element_data, .. }: GenericElement = datum_data
    expect Root { data: expected_root_data } = root_element_data
    root_data == expected_root_data
  }
    |> run_root_with(script_hash, test_root_key)
}

test success__init(init_values via init_fuzzer(True, None)) {
  run_init_case(init_values, InitNoMutation)
}

test fail__init__bad_root_data_validator(
  init_values via init_fuzzer(True, None),
) fail {
  run_init_case(init_values, InitBadValidator)
}

test fail__init__extra_mint(init_values via init_fuzzer(True, None)) fail {
  run_init_case(init_values, InitExtraMint)
}

test success__deinit(deinit_values via deinit_fuzzer(True, None)) {
  run_deinit_case(deinit_values, DeinitNoMutation)
}

test fail__deinit__extra_mint(deinit_values via deinit_fuzzer(True, None)) fail {
  run_deinit_case(deinit_values, DeinitExtraMint)
}

fn ordered_keys(
  ordering: ListOrdering,
  anchor_is_root: Bool,
  has_successor: Bool,
  base_key: Int,
) -> (Option<ByteArray>, ByteArray, Option<ByteArray>) {
  let lower_key = one_byte_key_from_int(base_key)
  let middle_key = one_byte_key_from_int(base_key + 1)
  let higher_key = one_byte_key_from_int(base_key + 2)
  let successor =
    if has_successor {
      Some(
        when ordering is {
          Ascending ->
            if anchor_is_root {
              middle_key
            } else {
              higher_key
            }
          Descending ->
            if anchor_is_root {
              middle_key
            } else {
              lower_key
            }
          Unordered -> higher_key
        },
      )
    } else {
      None
    }
  when ordering is {
    Ascending ->
      (
        if anchor_is_root {
          None
        } else {
          Some(lower_key)
        },
        if anchor_is_root {
          lower_key
        } else {
          middle_key
        },
        successor,
      )
    Descending ->
      (
        if anchor_is_root {
          None
        } else {
          Some(higher_key)
        },
        if anchor_is_root {
          higher_key
        } else {
          middle_key
        },
        successor,
      )
    Unordered ->
      (
        if anchor_is_root {
          None
        } else {
          Some(lower_key)
        },
        middle_key,
        successor,
      )
  }
}

fn insert_ordered_fuzzer() -> Fuzzer<InsertOrderedArgs> {
  let anchor_is_root <- fuzz.and_then(fuzz.bool())
  let has_successor <- fuzz.and_then(fuzz.bool())
  let is_ascending <- fuzz.and_then(fuzz.bool())
  let base_key <- fuzz.and_then(fuzz.int_between(1, 80))
  let ordering =
    if is_ascending {
      Ascending
    } else {
      Descending
    }
  let (expected_anchor_key, new_node_key, old_anchor_link) =
    ordered_keys(ordering, anchor_is_root, has_successor, base_key)
  let script_hash <- fuzz.and_then(cardano_fuzz.policy_id())
  let output_reference <- fuzz.and_then(cardano_fuzz.output_reference())
  let anchor_data <- fuzz.and_then(fuzz.data())
  let continued_anchor_data <- fuzz.and_then(fuzz.data())
  let new_node_data <- fuzz.and_then(fuzz.data())
  let anchor_ref_script <-
    fuzz.and_then(reference_script_fuzzer(script_hash, "insert-anchor"))
  let new_node_ref_script <-
    fuzz.and_then(reference_script_fuzzer(script_hash, "insert-new-node"))
  let anchor_asset_name =
    when expected_anchor_key is {
      None -> test_root_key
      Some(anchor_key) -> node_asset_name(anchor_key)
    }
  let new_node_asset_name = node_asset_name(new_node_key)
  let anchor_input =
    element_input(
      output_reference,
      script_hash,
      anchor_asset_name,
      Element {
        data: if anchor_is_root {
          Root(anchor_data)
        } else {
          Node(anchor_data)
        },
        link: old_anchor_link,
      },
      anchor_ref_script,
    )
  let inputs <-
    fuzz.and_then(
      utils.inputs_with_expected_inputs_fuzzer(script_hash, [anchor_input]),
    )
  let continued_anchor_output =
    element_output(
      script_hash,
      anchor_asset_name,
      Element {
        data: if anchor_is_root {
          Root(continued_anchor_data)
        } else {
          Node(continued_anchor_data)
        },
        link: Some(new_node_key),
      },
      anchor_ref_script,
    )
  let node_output =
    element_output(
      script_hash,
      new_node_asset_name,
      Element { data: Node(new_node_data), link: old_anchor_link },
      new_node_ref_script,
    )
  fuzz.constant(
    InsertOrderedArgs {
      is_ascending,
      script_hash,
      expected_anchor_input: anchor_input,
      expected_anchor_key,
      inputs,
      continued_anchor_output,
      node_output,
      mint_value: one_mint(script_hash, new_node_asset_name)
        |> add_extra_mint(script_hash),
      anchor_data,
      continued_anchor_data,
      new_node_key,
      new_node_data,
      new_node_link: old_anchor_link,
      new_node_ref_script,
      expected_extra_asset_change: Pair(extra_asset_name, 1),
    },
  )
}

fn insert_continued_anchor_output(
  continued_anchor_output: Output,
  script_hash: ScriptHash,
  mutation: InsertMutation,
) -> Output {
  when mutation is {
    InsertChangedAnchorRef ->
      alter_reference_script(continued_anchor_output, script_hash)
    _ -> continued_anchor_output
  }
}

fn insert_mint_value(
  mint_value: Value,
  script_hash: ScriptHash,
  mutation: InsertMutation,
) -> Value {
  when mutation is {
    InsertReservedRootMint ->
      mint_value |> assets.merge(one_mint(script_hash, test_root_key))
    InsertReservedNodeMint ->
      mint_value |> assets.merge(one_mint(script_hash, node_asset_name(#"ff")))
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
  insert_args: InsertOrderedArgs,
  mutation: InsertMutation,
  check_anchor_input: Bool,
) -> Bool {
  let InsertOrderedArgs {
    is_ascending,
    script_hash,
    expected_anchor_input,
    expected_anchor_key,
    inputs,
    continued_anchor_output,
    node_output,
    mint_value,
    anchor_data,
    continued_anchor_data,
    new_node_key,
    new_node_data,
    new_node_link,
    new_node_ref_script,
    expected_extra_asset_change,
  } = insert_args
  let insert_fn =
    if is_ascending {
      insert_ascending
    } else {
      insert_descending
    }
  {
    let
      anchor_input,
      anchor_lovelace_change,
      anchor_key,
      spent_anchor_data,
      cont_anchor_data,
      new_node_lovelace,
      callback_new_node_key,
      callback_new_node_data,
      callback_new_node_link,
      callback_new_node_ref_script,
      other_list_assets,
    <-
      insert_fn(
        insert_continued_anchor_output(
          continued_anchor_output,
          script_hash,
          mutation,
        ),
        node_output,
        inputs,
        insert_mint_value(mint_value, script_hash, mutation),
      )
    expect
      input_out_ref_matches(
        check_anchor_input,
        anchor_input,
        expected_anchor_input,
      )
    expect anchor_key == expected_anchor_key
    expect spent_anchor_data == anchor_data
    expect cont_anchor_data == continued_anchor_data
    expect callback_new_node_key == new_node_key
    expect callback_new_node_data == new_node_data
    expect callback_new_node_link == new_node_link
    expect callback_new_node_ref_script == new_node_ref_script
    expect expect_extra_asset(other_list_assets, expected_extra_asset_change)
    expect_structural_lovelace_change(
      anchor_lovelace_change,
      new_node_lovelace,
      insert_callback_result(mutation),
    )
  }
    |> eval_runner(script_hash)
}

test success__insert_ordered(insert_args via insert_ordered_fuzzer()) {
  run_ordered_insert_case(insert_args, InsertNoMutation, True)
}

test fail__insert_ordered__bad_additional_validator(
  insert_args via insert_ordered_fuzzer(),
) fail {
  run_ordered_insert_case(insert_args, InsertBadValidator, False)
}

test fail__insert_ordered__changed_anchor_reference_script(
  insert_args via insert_ordered_fuzzer(),
) fail {
  run_ordered_insert_case(insert_args, InsertChangedAnchorRef, False)
}

test fail__insert_ordered__reserved_root_key_mint(
  insert_args via insert_ordered_fuzzer(),
) fail {
  run_ordered_insert_case(insert_args, InsertReservedRootMint, False)
}

test fail__insert_ordered__reserved_node_prefix_mint(
  insert_args via insert_ordered_fuzzer(),
) fail {
  run_ordered_insert_case(insert_args, InsertReservedNodeMint, False)
}

fn append_unordered_fuzzer(node_has_link: Bool) -> Fuzzer<AppendArgs> {
  let anchor_is_root <- fuzz.and_then(fuzz.bool())
  let base_key <- fuzz.and_then(fuzz.int_between(1, 80))
  let (expected_anchor_key, new_node_key, _old_anchor_link) =
    ordered_keys(Unordered, anchor_is_root, False, base_key)
  let script_hash <- fuzz.and_then(cardano_fuzz.policy_id())
  let output_reference <- fuzz.and_then(cardano_fuzz.output_reference())
  let anchor_data <- fuzz.and_then(fuzz.data())
  let continued_anchor_data <- fuzz.and_then(fuzz.data())
  let new_node_data <- fuzz.and_then(fuzz.data())
  let anchor_ref_script <-
    fuzz.and_then(reference_script_fuzzer(script_hash, "append-anchor"))
  let new_node_ref_script <-
    fuzz.and_then(reference_script_fuzzer(script_hash, "append-new-node"))
  let anchor_asset_name =
    when expected_anchor_key is {
      None -> test_root_key
      Some(anchor_key) -> node_asset_name(anchor_key)
    }
  let new_node_asset_name = node_asset_name(new_node_key)
  let anchor_input =
    element_input(
      output_reference,
      script_hash,
      anchor_asset_name,
      Element {
        data: if anchor_is_root {
          Root(anchor_data)
        } else {
          Node(anchor_data)
        },
        link: None,
      },
      anchor_ref_script,
    )
  let inputs <-
    fuzz.and_then(
      utils.inputs_with_expected_inputs_fuzzer(script_hash, [anchor_input]),
    )
  let continued_anchor_output =
    element_output(
      script_hash,
      anchor_asset_name,
      Element {
        data: if anchor_is_root {
          Root(continued_anchor_data)
        } else {
          Node(continued_anchor_data)
        },
        link: Some(new_node_key),
      },
      anchor_ref_script,
    )
  let node_output =
    element_output(
      script_hash,
      new_node_asset_name,
      Element {
        data: Node(new_node_data),
        link: if node_has_link {
          Some(#"ff")
        } else {
          None
        },
      },
      new_node_ref_script,
    )
  fuzz.constant(
    AppendArgs {
      script_hash,
      expected_anchor_input: anchor_input,
      expected_anchor_key,
      inputs,
      continued_anchor_output,
      node_output,
      mint_value: one_mint(script_hash, new_node_asset_name)
        |> add_extra_mint(script_hash),
      anchor_data,
      continued_anchor_data,
      new_node_key,
      new_node_data,
      new_node_ref_script,
      expected_extra_asset_change: Pair(extra_asset_name, 1),
    },
  )
}

fn run_append_case(
  append_args: AppendArgs,
  mutation: InsertMutation,
  check_anchor_input: Bool,
) -> Bool {
  let AppendArgs {
    script_hash,
    expected_anchor_input,
    expected_anchor_key,
    inputs,
    continued_anchor_output,
    node_output,
    mint_value,
    anchor_data,
    continued_anchor_data,
    new_node_key,
    new_node_data,
    new_node_ref_script,
    expected_extra_asset_change,
  } = append_args
  {
    let
      anchor_input,
      anchor_lovelace_change,
      anchor_key,
      spent_anchor_data,
      cont_anchor_data,
      new_node_lovelace,
      callback_new_node_key,
      callback_new_node_data,
      callback_new_node_ref_script,
      other_list_assets,
    <-
      append_unordered(
        insert_continued_anchor_output(
          continued_anchor_output,
          script_hash,
          mutation,
        ),
        node_output,
        inputs,
        insert_mint_value(mint_value, script_hash, mutation),
      )
    expect
      input_out_ref_matches(
        check_anchor_input,
        anchor_input,
        expected_anchor_input,
      )
    expect anchor_key == expected_anchor_key
    expect spent_anchor_data == anchor_data
    expect cont_anchor_data == continued_anchor_data
    expect callback_new_node_key == new_node_key
    expect callback_new_node_data == new_node_data
    expect callback_new_node_ref_script == new_node_ref_script
    expect expect_extra_asset(other_list_assets, expected_extra_asset_change)
    expect_structural_lovelace_change(
      anchor_lovelace_change,
      new_node_lovelace,
      insert_callback_result(mutation),
    )
  }
    |> eval_runner(script_hash)
}

test success__append_unordered(append_args via append_unordered_fuzzer(False)) {
  run_append_case(append_args, InsertNoMutation, True)
}

test fail__append_unordered__node_has_link(
  append_args via append_unordered_fuzzer(True),
) fail {
  run_append_case(append_args, InsertNoMutation, False)
}

fn prepend_unordered_fuzzer() -> Fuzzer<PrependArgs> {
  let has_old_first_node <- fuzz.and_then(fuzz.bool())
  let base_key <- fuzz.and_then(fuzz.int_between(1, 80))
  let old_first_key = one_byte_key_from_int(base_key)
  let new_node_key = one_byte_key_from_int(base_key + 1)
  let root_link =
    if has_old_first_node {
      Some(old_first_key)
    } else {
      None
    }
  let script_hash <- fuzz.and_then(cardano_fuzz.policy_id())
  let output_reference <- fuzz.and_then(cardano_fuzz.output_reference())
  let root_data <- fuzz.and_then(fuzz.data())
  let continued_root_data <- fuzz.and_then(fuzz.data())
  let new_node_data <- fuzz.and_then(fuzz.data())
  let root_ref_script <-
    fuzz.and_then(reference_script_fuzzer(script_hash, "prepend-root"))
  let new_node_ref_script <-
    fuzz.and_then(reference_script_fuzzer(script_hash, "prepend-new-node"))
  let new_node_asset_name = node_asset_name(new_node_key)
  let root_input =
    element_input(
      output_reference,
      script_hash,
      test_root_key,
      Element { data: Root(root_data), link: root_link },
      root_ref_script,
    )
  let inputs <-
    fuzz.and_then(
      utils.inputs_with_expected_inputs_fuzzer(script_hash, [root_input]),
    )
  let continued_root_output =
    element_output(
      script_hash,
      test_root_key,
      Element { data: Root(continued_root_data), link: Some(new_node_key) },
      root_ref_script,
    )
  let node_output =
    element_output(
      script_hash,
      new_node_asset_name,
      Element { data: Node(new_node_data), link: root_link },
      new_node_ref_script,
    )
  fuzz.constant(
    PrependArgs {
      script_hash,
      root_input,
      inputs,
      continued_root_output,
      node_output,
      mint_value: one_mint(script_hash, new_node_asset_name)
        |> add_extra_mint(script_hash),
      root_data,
      continued_root_data,
      new_node_key,
      new_node_data,
      new_node_link: root_link,
      new_node_ref_script,
      expected_extra_asset_change: Pair(extra_asset_name, 1),
    },
  )
}

fn run_prepend_case(
  prepend_args: PrependArgs,
  mutation: InsertMutation,
  check_root_input: Bool,
) -> Bool {
  let PrependArgs {
    script_hash,
    root_input,
    inputs,
    continued_root_output,
    node_output,
    mint_value,
    root_data,
    continued_root_data,
    new_node_key,
    new_node_data,
    new_node_link,
    new_node_ref_script,
    expected_extra_asset_change,
  } = prepend_args
  {
    let
      scanned_root_input,
      root_lovelace_change,
      spent_root_data,
      cont_root_data,
      new_node_lovelace,
      callback_new_node_key,
      callback_new_node_data,
      callback_new_node_link,
      callback_new_node_ref_script,
      other_list_assets,
    <-
      prepend_unordered(
        insert_continued_anchor_output(
          continued_root_output,
          script_hash,
          mutation,
        ),
        node_output,
        inputs,
        insert_mint_value(mint_value, script_hash, mutation),
      )
    expect
      input_out_ref_matches(check_root_input, scanned_root_input, root_input)
    expect spent_root_data == root_data
    expect cont_root_data == continued_root_data
    expect callback_new_node_key == new_node_key
    expect callback_new_node_data == new_node_data
    expect callback_new_node_link == new_node_link
    expect callback_new_node_ref_script == new_node_ref_script
    expect expect_extra_asset(other_list_assets, expected_extra_asset_change)
    expect_structural_lovelace_change(
      root_lovelace_change,
      new_node_lovelace,
      insert_callback_result(mutation),
    )
  }
    |> eval_runner(script_hash)
}

test success__prepend_unordered(prepend_args via prepend_unordered_fuzzer()) {
  run_prepend_case(prepend_args, InsertNoMutation, True)
}

fn anchor_and_linked_node_fuzzer(anchor_is_root: Bool) -> Fuzzer<RemoveArgs> {
  let has_removed_node_link <- fuzz.and_then(fuzz.bool())
  let base_key <- fuzz.and_then(fuzz.int_between(1, 80))
  let anchor_key = one_byte_key_from_int(base_key)
  let removing_node_key = one_byte_key_from_int(base_key + 1)
  let next_node_key = one_byte_key_from_int(base_key + 2)
  let removing_node_link =
    if has_removed_node_link {
      Some(next_node_key)
    } else {
      None
    }
  let script_hash <- fuzz.and_then(cardano_fuzz.policy_id())
  let anchor_out_ref <- fuzz.and_then(cardano_fuzz.output_reference())
  let removing_node_out_ref <- fuzz.and_then(cardano_fuzz.output_reference())
  let anchor_data <- fuzz.and_then(fuzz.data())
  let continued_anchor_data <- fuzz.and_then(fuzz.data())
  let removing_node_data <- fuzz.and_then(fuzz.data())
  let anchor_ref_script <-
    fuzz.and_then(reference_script_fuzzer(script_hash, "remove-anchor"))
  let expected_anchor_key =
    if anchor_is_root {
      None
    } else {
      Some(anchor_key)
    }
  let anchor_asset_name =
    when expected_anchor_key is {
      None -> test_root_key
      Some(key) -> node_asset_name(key)
    }
  let removing_node_asset_name = node_asset_name(removing_node_key)
  let anchor_input =
    element_input(
      anchor_out_ref,
      script_hash,
      anchor_asset_name,
      Element {
        data: if anchor_is_root {
          Root(anchor_data)
        } else {
          Node(anchor_data)
        },
        link: Some(removing_node_key),
      },
      anchor_ref_script,
    )
  let removing_node_input =
    element_input(
      removing_node_out_ref,
      script_hash,
      removing_node_asset_name,
      Element { data: Node(removing_node_data), link: removing_node_link },
      None,
    )
  let inputs <-
    fuzz.and_then(
      utils.inputs_with_expected_inputs_fuzzer(
        script_hash,
        [anchor_input, removing_node_input],
      ),
    )
  let continued_anchor_output =
    element_output(
      script_hash,
      anchor_asset_name,
      Element {
        data: if anchor_is_root {
          Root(continued_anchor_data)
        } else {
          Node(continued_anchor_data)
        },
        link: removing_node_link,
      },
      anchor_ref_script,
    )
  fuzz.constant(
    RemoveArgs {
      script_hash,
      expected_anchor_input: anchor_input,
      expected_anchor_key,
      expected_removing_node_input: removing_node_input,
      inputs,
      continued_anchor_output,
      mint_value: one_burn(script_hash, removing_node_asset_name)
        |> add_extra_mint(script_hash),
      anchor_data,
      continued_anchor_data,
      removing_node_key,
      removing_node_data,
      removing_node_link,
      expected_extra_asset_change: Pair(extra_asset_name, 1),
    },
  )
}

fn remove_fuzzer() -> Fuzzer<RemoveArgs> {
  let anchor_is_root <- fuzz.and_then(fuzz.bool())
  anchor_and_linked_node_fuzzer(anchor_is_root)
}

fn remove_continued_anchor_output(
  continued_anchor_output: Output,
  script_hash: ScriptHash,
  mutation: RemoveMutation,
) -> Output {
  when mutation is {
    RemoveChangedAnchorRef ->
      alter_reference_script(continued_anchor_output, script_hash)
    _ -> continued_anchor_output
  }
}

fn remove_mint_value(
  mint_value: Value,
  script_hash: ScriptHash,
  mutation: RemoveMutation,
) -> Value {
  when mutation is {
    RemoveReservedRootMint ->
      mint_value |> assets.merge(one_mint(script_hash, test_root_key))
    RemoveReservedNodeMint ->
      mint_value |> assets.merge(one_mint(script_hash, node_asset_name(#"ff")))
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
  remove_args: RemoveArgs,
  mutation: RemoveMutation,
  check_inputs: Bool,
) -> Bool {
  let RemoveArgs {
    script_hash,
    expected_anchor_input,
    expected_anchor_key,
    expected_removing_node_input,
    inputs,
    continued_anchor_output,
    mint_value,
    anchor_data,
    continued_anchor_data,
    removing_node_key,
    removing_node_data,
    removing_node_link,
    expected_extra_asset_change,
  } = remove_args
  {
    let
      anchor_input,
      anchor_lovelace_change,
      anchor_key,
      spent_anchor_data,
      cont_anchor_data,
      removing_node_input,
      removing_node_lovelace,
      callback_removing_node_key,
      callback_removing_node_data,
      callback_removing_node_link,
      other_list_assets,
    <-
      remove(
        expected_anchor_input.output_reference,
        remove_continued_anchor_output(
          continued_anchor_output,
          script_hash,
          mutation,
        ),
        inputs,
        remove_mint_value(mint_value, script_hash, mutation),
      )
    expect
      two_input_out_refs_match(
        check_inputs,
        anchor_input,
        expected_anchor_input,
        removing_node_input,
        expected_removing_node_input,
      )
    expect anchor_key == expected_anchor_key
    expect spent_anchor_data == anchor_data
    expect cont_anchor_data == continued_anchor_data
    expect callback_removing_node_key == removing_node_key
    expect callback_removing_node_data == removing_node_data
    expect callback_removing_node_link == removing_node_link
    expect expect_extra_asset(other_list_assets, expected_extra_asset_change)
    expect_structural_lovelace_change(
      anchor_lovelace_change,
      removing_node_lovelace,
      remove_callback_result(mutation),
    )
  }
    |> eval_runner(script_hash)
}

test success__remove(remove_args via remove_fuzzer()) {
  run_remove_case(remove_args, RemoveNoMutation, True)
}

test fail__remove__bad_additional_validator(
  remove_args via remove_fuzzer(),
) fail {
  run_remove_case(remove_args, RemoveBadValidator, False)
}

test fail__remove__changed_anchor_reference_script(
  remove_args via remove_fuzzer(),
) fail {
  run_remove_case(remove_args, RemoveChangedAnchorRef, False)
}

test fail__remove__reserved_root_key_mint(remove_args via remove_fuzzer()) fail {
  run_remove_case(remove_args, RemoveReservedRootMint, False)
}

test fail__remove__reserved_node_prefix_mint(
  remove_args via remove_fuzzer(),
) fail {
  run_remove_case(remove_args, RemoveReservedNodeMint, False)
}

fn run_fold_case(
  fold_args: RemoveArgs,
  mutation: FoldMutation,
  check_inputs: Bool,
) -> Bool {
  let RemoveArgs {
    script_hash,
    expected_anchor_input,
    expected_removing_node_input,
    inputs,
    continued_anchor_output,
    mint_value,
    anchor_data,
    continued_anchor_data,
    removing_node_key,
    removing_node_data,
    removing_node_link,
    expected_extra_asset_change,
    ..
  } = fold_args
  let used_continued_root_output =
    when mutation is {
      FoldChangedRootRef ->
        alter_reference_script(continued_anchor_output, script_hash)
      _ -> continued_anchor_output
    }
  {
    let
      root_input,
      root_lovelace_change,
      spent_root_data,
      folding_node_input,
      folding_node_lovelace,
      callback_folding_node_key,
      callback_folding_node_data,
      callback_folding_node_link,
      cont_root_data,
      other_list_assets,
    <-
      fold_from_root(
        expected_anchor_input.output_reference,
        used_continued_root_output,
        inputs,
        mint_value,
      )
    expect
      two_input_out_refs_match(
        check_inputs,
        root_input,
        expected_anchor_input,
        folding_node_input,
        expected_removing_node_input,
      )
    expect spent_root_data == anchor_data
    expect cont_root_data == continued_anchor_data
    expect callback_folding_node_key == removing_node_key
    expect callback_folding_node_data == removing_node_data
    expect callback_folding_node_link == removing_node_link
    expect expect_extra_asset(other_list_assets, expected_extra_asset_change)
    expect_structural_lovelace_change(
      root_lovelace_change,
      folding_node_lovelace,
      when mutation is {
        FoldBadValidator -> False
        _ -> True
      },
    )
  }
    |> eval_runner(script_hash)
}

test success__fold_from_root(fold_args via anchor_and_linked_node_fuzzer(True)) {
  run_fold_case(fold_args, FoldNoMutation, True)
}

test fail__fold_from_root__bad_additional_validator(
  fold_args via anchor_and_linked_node_fuzzer(True),
) fail {
  run_fold_case(fold_args, FoldBadValidator, False)
}

test fail__fold_from_root__changed_root_reference_script(
  fold_args via anchor_and_linked_node_fuzzer(True),
) fail {
  run_fold_case(fold_args, FoldChangedRootRef, False)
}

test fail__fold_from_root__bad_anchor(
  fold_args via anchor_and_linked_node_fuzzer(False),
) fail {
  run_fold_case(fold_args, FoldNoMutation, False)
}

test success__spend_for_adding_or_removing_an_element(
  init_values via init_fuzzer(True, None),
) {
  let InitArgs { script_hash, .. } = init_values
  spend_for_adding_or_removing_an_element(
    script_hash,
    one_mint(script_hash, test_root_key),
  )
}

test fail__spend_for_adding_or_removing_an_element__wrong_policy(
  init_values via init_fuzzer(True, None),
) fail {
  let InitArgs { script_hash, .. } = init_values
  spend_for_adding_or_removing_an_element(
    script_hash,
    one_mint(blake2b_224(script_hash), test_root_key),
  )
}

fn update_fuzzer(is_root: Bool) -> Fuzzer<UpdateArgs> {
  let script_hash <- fuzz.and_then(cardano_fuzz.policy_id())
  let output_reference <- fuzz.and_then(cardano_fuzz.output_reference())
  let old_data <- fuzz.and_then(fuzz.data())
  let new_data <- fuzz.and_then(fuzz.data())
  let old_ref_script <-
    fuzz.and_then(reference_script_fuzzer(script_hash, "update-old-ref"))
  let new_ref_script <-
    fuzz.and_then(reference_script_fuzzer(script_hash, "update-new-ref"))
  let link <- fuzz.and_then(fuzz.one_of([None, Some(#"ff")]))
  let node_key = one_byte_key_from_int(1)
  let element_key =
    if is_root {
      None
    } else {
      Some(node_key)
    }
  let asset_name =
    when element_key is {
      None -> test_root_key
      Some(key) -> node_asset_name(key)
    }
  let spent_element_input =
    element_input(
      output_reference,
      script_hash,
      asset_name,
      Element {
        data: if is_root {
          Root(old_data)
        } else {
          Node(old_data)
        },
        link,
      },
      old_ref_script,
    )
  let continued_element_output =
    element_output(
      script_hash,
      asset_name,
      Element {
        data: if is_root {
          Root(new_data)
        } else {
          Node(new_data)
        },
        link,
      },
      new_ref_script,
    )
  fuzz.constant(
    UpdateArgs {
      script_hash,
      element_input: spent_element_input,
      continued_element_output,
      element_key,
      old_data,
      old_ref_script,
      new_data,
      new_ref_script,
      link,
    },
  )
}

fn run_update_case(update_args: UpdateArgs, mutation: UpdateMutation) -> Bool {
  let UpdateArgs {
    script_hash,
    element_input,
    continued_element_output,
    element_key,
    old_data,
    old_ref_script,
    new_data,
    new_ref_script,
    link,
  } = update_args
  let input_index =
    when mutation is {
      UpdateBadInputIndex -> 1
      _ -> 0
    }
  let output_index =
    when mutation is {
      UpdateBadOutputIndex -> 1
      _ -> 0
    }
  let outputs =
    when mutation is {
      UpdateBadLink -> [alter_output_link(continued_element_output)]
      UpdateBadOutputIndex ->
        [continued_element_output, alter_output_link(continued_element_output)]
      _ -> [continued_element_output]
    }
  let mint_value =
    when mutation is {
      UpdateMintedListAsset -> one_mint(script_hash, test_root_key)
      _ -> assets.zero
    }
  {
    let
      element_address,
      lovelace_change,
      callback_key,
      input_data,
      input_ref_script,
      output_data,
      output_ref_script,
      callback_link,
    <-
      spend_for_updating_elements_data(
        input_index,
        output_index,
        element_input.output_reference,
        [element_input],
        outputs,
        mint_value,
      )
    expect element_address == element_input.output.address
    expect lovelace_change == 0
    expect callback_key == element_key
    expect input_data == old_data
    expect input_ref_script == old_ref_script
    expect output_data == new_data
    expect output_ref_script == new_ref_script
    expect callback_link == link
    when mutation is {
      UpdateBadValidator -> False
      _ -> True
    }
  }
    |> eval_runner(script_hash)
}

test success__spend_for_updating_elements_data__root(
  update_args via update_fuzzer(True),
) {
  run_update_case(update_args, UpdateNoMutation)
}

test success__spend_for_updating_elements_data__node(
  update_args via update_fuzzer(False),
) {
  run_update_case(update_args, UpdateNoMutation)
}

test fail__spend_for_updating_elements_data__bad_additional_validator(
  update_args via update_fuzzer(True),
) fail {
  run_update_case(update_args, UpdateBadValidator)
}

test fail__spend_for_updating_elements_data__bad_link(
  update_args via update_fuzzer(True),
) fail {
  run_update_case(update_args, UpdateBadLink)
}

test fail__spend_for_updating_elements_data__minted_list_asset(
  update_args via update_fuzzer(True),
) fail {
  run_update_case(update_args, UpdateMintedListAsset)
}

test fail__spend_for_updating_elements_data__bad_input_index(
  update_args via update_fuzzer(True),
) fail {
  run_update_case(update_args, UpdateBadInputIndex)
}

test fail__spend_for_updating_elements_data__bad_output_index(
  update_args via update_fuzzer(True),
) fail {
  run_update_case(update_args, UpdateBadOutputIndex)
}

test success__get_element_info__root(info_args via update_fuzzer(True)) {
  let UpdateArgs {
    script_hash,
    element_input,
    element_key,
    old_data,
    old_ref_script,
    link,
    ..
  } = info_args
  {
    let
      element_address,
      lovelace,
      callback_key,
      data,
      callback_link,
      ref_script,
    <- get_element_info(element_input.output)
    expect element_address == element_input.output.address
    expect lovelace == min_lovelace
    expect callback_key == element_key
    expect data == old_data
    expect callback_link == link
    expect ref_script == old_ref_script
    True
  }
    |> eval_runner(script_hash)
}

test success__get_element_info__node(info_args via update_fuzzer(False)) {
  let UpdateArgs {
    script_hash,
    element_input,
    element_key,
    old_data,
    old_ref_script,
    link,
    ..
  } = info_args
  {
    let
      element_address,
      lovelace,
      callback_key,
      data,
      callback_link,
      ref_script,
    <- get_element_info(element_input.output)
    expect element_address == element_input.output.address
    expect lovelace == min_lovelace
    expect callback_key == element_key
    expect data == old_data
    expect callback_link == link
    expect ref_script == old_ref_script
    True
  }
    |> eval_runner(script_hash)
}

test success__get_root_element_info(info_args via update_fuzzer(True)) {
  let UpdateArgs {
    script_hash,
    element_input,
    old_data,
    old_ref_script,
    link,
    ..
  } = info_args
  {
    let
      element_address,
      lovelace,
      data,
      callback_link,
      ref_script,
    <- get_root_element_info(element_input.output)
    expect element_address == element_input.output.address
    expect lovelace == min_lovelace
    expect data == old_data
    expect callback_link == link
    expect ref_script == old_ref_script
    True
  }
    |> run_root_with(script_hash, test_root_key)
}

test success__get_node_element_info(info_args via update_fuzzer(False)) {
  let UpdateArgs {
    script_hash,
    element_input,
    element_key,
    old_data,
    old_ref_script,
    link,
    ..
  } = info_args
  expect Some(expected_node_key) = element_key
  {
    let
      element_address,
      lovelace,
      node_key,
      data,
      callback_link,
      ref_script,
    <- get_node_element_info(element_input.output)
    expect element_address == element_input.output.address
    expect lovelace == min_lovelace
    expect node_key == expected_node_key
    expect data == old_data
    expect callback_link == link
    expect ref_script == old_ref_script
    True
  }
    |> run_node_with(
        script_hash,
        test_node_key_prefix,
        test_node_key_prefix_length,
      )
}

test fail__reserved_list_asset_changes__root_key() fail {
  validate_no_reserved_list_asset_changes(
    dict.from_pairs([Pair(test_root_key, 1)]),
    test_root_key,
    test_node_key_prefix,
    test_node_key_prefix_length,
  )
}

test fail__reserved_list_asset_changes__node_prefix() fail {
  validate_no_reserved_list_asset_changes(
    dict.from_pairs([Pair(node_asset_name(#"ff"), 1)]),
    test_root_key,
    test_node_key_prefix,
    test_node_key_prefix_length,
  )
}
