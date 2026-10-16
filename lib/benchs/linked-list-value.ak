//// Compare the nested-list mint accumulator using identical sampled contexts.
//// Fixture generation runs in the sampler, outside the measured helper.
//// Run the Assets baseline and the native Value prototype with
//// lib/benchs/run-value-comparison.sh.
////
//// Linked-list spend helpers delegate to the dedicated mint helpers. These
//// benchmarks exercise that mint-side validation and its application callbacks.

use aiken/collection/dict
use aiken/collection/list
use aiken/crypto.{ScriptHash, blake2b_224}
use aiken/fuzz
use aiken/primitive/bytearray
use aiken_design_patterns/linked_list.{ElementEval, run_element_with}
use aiken_design_patterns/linked_list/nested.{
  Ascending, Descending, Element, GenericElement, InnerRoot, ListOrdering, Node,
  Root, Unordered, insert_inner_list_ascending, insert_inner_list_descending,
}
use aiken_design_patterns/utils
use cardano/address.{Address, Script}
use cardano/assets.{AssetName, Assets}
use cardano/fuzz as cardano_fuzz
use cardano/transaction.{InlineDatum, Input, Output, OutputReference}

type InsertOfInnerListCase {
  RootAnchorWithNodes
  DescendingOuterAnchorWithEmptyInnerList
}

type ExpectedInnerNode {
  key: ByteArray,
  data: Data,
  link: Option<ByteArray>,
  reference_script: Option<ScriptHash>,
}

type InsertOfInnerListArgs {
  script_hash: ScriptHash,
  inner_ordering: ListOrdering,
  anchor_input: Input,
  inputs: List<Input>,
  continued_anchor_output: Output,
  new_inner_root_output: Output,
  inner_node_outputs: List<Output>,
  tx_mint: Assets,
  anchor_key: Option<ByteArray>,
  anchor_data: Data,
  cont_anchor_data: Data,
  anchor_link: Option<ByteArray>,
  new_inner_root_key: ByteArray,
  new_inner_root_data: Data,
  new_inner_root_child_link: Option<ByteArray>,
  new_inner_root_ref_script: Option<ScriptHash>,
  expected_inner_nodes: List<ExpectedInnerNode>,
  expected_last_inner_node_key: Option<ByteArray>,
  expected_extra_asset_change: Option<Pair<AssetName, Int>>,
}

const min_lovelace = 2_000_000

const test_root_key = #""

const test_node_key_prefix = #"4e"

const test_node_key_prefix_length = bytearray.length(test_node_key_prefix)

const extra_asset_name = #"6578747261"

fn one_byte_key_from_int(n: Int) -> ByteArray {
  n |> bytearray.from_int_big_endian(1)
}

fn node_asset_name(node_key: ByteArray) -> AssetName {
  test_node_key_prefix |> bytearray.concat(node_key)
}

fn element_value(script_hash: ScriptHash, asset_name: AssetName) -> Assets {
  assets.from_lovelace(min_lovelace)
    |> assets.merge(assets.from_asset(script_hash, asset_name, 1))
}

fn element_output(
  script_hash: ScriptHash,
  asset_name: AssetName,
  element: GenericElement,
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
  element: GenericElement,
  reference_script: Option<ScriptHash>,
) -> Input {
  Input {
    output_reference,
    output: element_output(script_hash, asset_name, element, reference_script),
  }
}

fn one_mint(script_hash: ScriptHash, asset_name: AssetName) -> Assets {
  assets.from_asset(script_hash, asset_name, 1)
}

fn reference_script_fuzzer(
  script_hash: ScriptHash,
  label: ByteArray,
) -> Fuzzer<Option<ScriptHash>> {
  fuzz.one_of(
    [None, Some(script_hash |> bytearray.concat(label) |> blake2b_224)],
  )
}

fn list_ordering_fuzzer() -> Fuzzer<ListOrdering> {
  fuzz.one_of([Ascending, Descending, Unordered])
}

fn eval_element(eval: ElementEval<Bool>, script_hash: ScriptHash) -> Bool {
  eval
    |> run_element_with(
        script_hash,
        test_root_key,
        test_node_key_prefix,
        test_node_key_prefix_length,
      )
}

fn inner_node_keys_for_ordering(
  ordering: ListOrdering,
  base_key: Int,
) -> (ByteArray, ByteArray) {
  when ordering is {
    Ascending ->
      (one_byte_key_from_int(base_key), one_byte_key_from_int(base_key + 1))
    Descending ->
      (one_byte_key_from_int(base_key + 1), one_byte_key_from_int(base_key))
    // Unordered fixtures only care about link shape; key ordering is ignored.
    Unordered ->
      (one_byte_key_from_int(base_key + 1), one_byte_key_from_int(base_key))
  }
}

fn insert_of_inner_list_fuzzer(
  scenario: InsertOfInnerListCase,
) -> Fuzzer<InsertOfInnerListArgs> {
  let script_hash <- fuzz.and_then(cardano_fuzz.policy_id())
  let inner_ordering <- fuzz.and_then(list_ordering_fuzzer())
  let outer_base_key <- fuzz.and_then(
    when scenario is {
      RootAnchorWithNodes -> fuzz.int_between(100, 120)
      DescendingOuterAnchorWithEmptyInnerList -> fuzz.int_between(1, 80)
    },
  )
  let inner_base_key <- fuzz.and_then(fuzz.int_between(1, 80))
  let anchor_data <- fuzz.and_then(fuzz.data())
  let cont_anchor_data <- fuzz.and_then(fuzz.data())
  let new_inner_root_data <- fuzz.and_then(fuzz.data())
  let first_node_data <- fuzz.and_then(fuzz.data())
  let second_node_data <- fuzz.and_then(fuzz.data())
  let new_inner_root_ref_script <- fuzz.and_then(
    reference_script_fuzzer(script_hash, "new-inner-root"),
  )
  let first_node_ref_script <- fuzz.and_then(
    reference_script_fuzzer(script_hash, "first-inner-node"),
  )
  let second_node_ref_script <- fuzz.and_then(
    reference_script_fuzzer(script_hash, "second-inner-node"),
  )
  let generated_anchor_ref_script <- fuzz.and_then(
    reference_script_fuzzer(script_hash, "outer-anchor"),
  )
  let output_reference <- fuzz.and_then(cardano_fuzz.output_reference())
  let  
      (
        anchor_key,
        anchor_asset_name,
        new_inner_root_key,
        next_outer_key,
        anchor_ref_script,
        anchor_element_data,
      )
    = when scenario is {
    RootAnchorWithNodes ->
      (
        None,
        test_root_key,
        one_byte_key_from_int(outer_base_key),
        one_byte_key_from_int(outer_base_key + 1),
        None,
        Root(anchor_data),
      )
    DescendingOuterAnchorWithEmptyInnerList -> {
      let anchor_key = one_byte_key_from_int(outer_base_key + 2)
      (
        Some(anchor_key),
        node_asset_name(anchor_key),
        one_byte_key_from_int(outer_base_key + 1),
        one_byte_key_from_int(outer_base_key),
        generated_anchor_ref_script,
        InnerRoot { data: anchor_data, child_link: None },
      )
    }
  }
  let (first_node_key, second_node_key) = inner_node_keys_for_ordering(
    inner_ordering,
    inner_base_key,
  )
  let cont_anchor_element_data = when scenario is {
    RootAnchorWithNodes -> Root(cont_anchor_data)
    DescendingOuterAnchorWithEmptyInnerList ->
      InnerRoot { data: cont_anchor_data, child_link: None }
  }
  let new_inner_root_asset_name = node_asset_name(new_inner_root_key)
  let first_node_asset_name = node_asset_name(first_node_key)
  let second_node_asset_name = node_asset_name(second_node_key)
  let anchor_link = Some(next_outer_key)
  let new_inner_root_child_link = when scenario is {
    RootAnchorWithNodes -> Some(first_node_key)
    DescendingOuterAnchorWithEmptyInnerList -> None
  }
  let anchor_input = element_input(
    output_reference,
    script_hash,
    anchor_asset_name,
    Element { data: anchor_element_data, link: anchor_link },
    anchor_ref_script,
  )
  let inputs <- fuzz.and_then(
    utils.inputs_with_expected_inputs_fuzzer(script_hash, [anchor_input]),
  )
  let continued_anchor_output = element_output(
    script_hash,
    anchor_asset_name,
    Element { data: cont_anchor_element_data, link: Some(new_inner_root_key) },
    anchor_ref_script,
  )
  let new_inner_root_output = element_output(
    script_hash,
    new_inner_root_asset_name,
    Element {
      data: InnerRoot {
        data: new_inner_root_data,
        child_link: new_inner_root_child_link,
      },
      link: anchor_link,
    },
    new_inner_root_ref_script,
  )
  let expected_first_node = ExpectedInnerNode {
    key: first_node_key,
    data: first_node_data,
    link: Some(second_node_key),
    reference_script: first_node_ref_script,
  }
  let expected_second_node = ExpectedInnerNode {
    key: second_node_key,
    data: second_node_data,
    link: None,
    reference_script: second_node_ref_script,
  }
  let first_node_output = element_output(
    script_hash,
    first_node_asset_name,
    Element { data: Node(first_node_data), link: Some(second_node_key) },
    first_node_ref_script,
  )
  let second_node_output = element_output(
    script_hash,
    second_node_asset_name,
    Element { data: Node(second_node_data), link: None },
    second_node_ref_script,
  )
  let  
      (
        inner_node_outputs,
        expected_inner_nodes,
        expected_last_inner_node_key,
        tx_mint,
        expected_extra_asset_change,
      )
    = when scenario is {
    RootAnchorWithNodes ->
      (
        [first_node_output, second_node_output],
        [expected_first_node, expected_second_node],
        Some(second_node_key),
        one_mint(script_hash, new_inner_root_asset_name)
          |> assets.merge(one_mint(script_hash, first_node_asset_name))
          |> assets.merge(one_mint(script_hash, second_node_asset_name))
          |> assets.merge(one_mint(script_hash, extra_asset_name)),
        Some(Pair(extra_asset_name, 1)),
      )
    DescendingOuterAnchorWithEmptyInnerList ->
      ([], [], None, one_mint(script_hash, new_inner_root_asset_name), None)
  }

  fuzz.constant(
    InsertOfInnerListArgs {
      script_hash,
      inner_ordering,
      anchor_input,
      inputs,
      continued_anchor_output,
      new_inner_root_output,
      inner_node_outputs,
      tx_mint,
      anchor_key,
      anchor_data,
      cont_anchor_data,
      anchor_link,
      new_inner_root_key,
      new_inner_root_data,
      new_inner_root_child_link,
      new_inner_root_ref_script,
      expected_inner_nodes,
      expected_last_inner_node_key,
      expected_extra_asset_change,
    },
  )
}

fn validate_with_nodes(args: InsertOfInnerListArgs) -> Bool {
  let  
      InsertOfInnerListArgs {
        script_hash,
        inner_ordering,
        anchor_input,
        inputs,
        continued_anchor_output,
        new_inner_root_output,
        inner_node_outputs,
        tx_mint,
        anchor_key,
        anchor_data,
        cont_anchor_data,
        anchor_link,
        new_inner_root_key,
        new_inner_root_data,
        new_inner_root_child_link,
        new_inner_root_ref_script,
        expected_inner_nodes,
        expected_last_inner_node_key,
        expected_extra_asset_change,
      }
    = args

  {
    let  
        input,
        lovelace_change,
        callback_anchor_key,
        callback_anchor_data,
        callback_cont_anchor_data,
        callback_anchor_link,
        final_state,
        non_structural_list_assets,
        non_structural_list_inputs
      <- insert_inner_list_ascending(
      ordering_of_inner_node_keys: inner_ordering,
      continued_anchor_element_output: continued_anchor_output,
      new_inner_root_output: new_inner_root_output,
      inputs: inputs,
      inner_node_outputs: inner_node_outputs,
      tx_mint: tx_mint,
      prepare_state: fn(lovelace, key, data, link, reference_script) {
        expect and {
            lovelace == min_lovelace,
            key == new_inner_root_key,
            data == new_inner_root_data,
            link == new_inner_root_child_link,
            reference_script == new_inner_root_ref_script,
          }
        None
      },
      node_validator: fn(
        _state,
        index,
        address,
        lovelace,
        key,
        data,
        link,
        reference_script,
      ) {
        expect  
            Some(ExpectedInnerNode {
              key: expected_key,
              data: expected_data,
              link: expected_link,
              reference_script: expected_reference_script,
            })
          = list.at(expected_inner_nodes, index)
        expect Some(expected_output) = list.at(inner_node_outputs, index)
        expect and {
            address == expected_output.address,
            lovelace == min_lovelace,
            key == expected_key,
            data == expected_data,
            link == expected_link,
            reference_script == expected_reference_script,
          }
        Some(key)
      },
    )
    and {
      input.output_reference == anchor_input.output_reference,
      lovelace_change == 0,
      callback_anchor_key == anchor_key,
      callback_anchor_data == anchor_data,
      callback_cont_anchor_data == cont_anchor_data,
      callback_anchor_link == anchor_link,
      final_state == expected_last_inner_node_key,
      non_structural_list_inputs == [],
      when expected_extra_asset_change is {
        Some(Pair(asset_name, quantity)) ->
          dict.get(non_structural_list_assets, asset_name) == Some(quantity)
        None -> dict.is_empty(non_structural_list_assets)
      },
    }
  }
    |> eval_element(script_hash)
}

fn validate_empty(args: InsertOfInnerListArgs) -> Bool {
  let  
      InsertOfInnerListArgs {
        script_hash,
        inner_ordering,
        anchor_input,
        inputs,
        continued_anchor_output,
        new_inner_root_output,
        inner_node_outputs,
        tx_mint,
        anchor_key,
        anchor_data,
        cont_anchor_data,
        anchor_link,
        new_inner_root_key,
        new_inner_root_data,
        new_inner_root_ref_script,
        expected_inner_nodes,
        expected_last_inner_node_key,
        expected_extra_asset_change,
        ..
      }
    = args

  {
    let  
        input,
        lovelace_change,
        callback_anchor_key,
        callback_anchor_data,
        callback_cont_anchor_data,
        callback_anchor_link,
        final_state,
        non_structural_list_assets,
        non_structural_list_inputs
      <- insert_inner_list_descending(
      ordering_of_inner_node_keys: inner_ordering,
      continued_anchor_element_output: continued_anchor_output,
      new_inner_root_output: new_inner_root_output,
      inputs: inputs,
      inner_node_outputs: inner_node_outputs,
      tx_mint: tx_mint,
      prepare_state: fn(lovelace, key, data, link, reference_script) {
        expect and {
            lovelace == min_lovelace,
            key == new_inner_root_key,
            data == new_inner_root_data,
            link == None,
            reference_script == new_inner_root_ref_script,
          }
        None
      },
      node_validator: fn(
        _state,
        index,
        address,
        lovelace,
        key,
        data,
        link,
        reference_script,
      ) {
        expect  
            Some(ExpectedInnerNode {
              key: expected_key,
              data: expected_data,
              link: expected_link,
              reference_script: expected_reference_script,
            })
          = list.at(expected_inner_nodes, index)
        expect Some(expected_output) = list.at(inner_node_outputs, index)
        expect and {
            address == expected_output.address,
            lovelace == min_lovelace,
            key == expected_key,
            data == expected_data,
            link == expected_link,
            reference_script == expected_reference_script,
          }
        Some(key)
      },
    )
    and {
      input.output_reference == anchor_input.output_reference,
      lovelace_change == 0,
      callback_anchor_key == anchor_key,
      callback_anchor_data == anchor_data,
      callback_cont_anchor_data == cont_anchor_data,
      callback_anchor_link == anchor_link,
      final_state == expected_last_inner_node_key,
      non_structural_list_inputs == [],
      when expected_extra_asset_change is {
        Some(Pair(asset_name, quantity)) ->
          dict.get(non_structural_list_assets, asset_name) == Some(quantity)
        None -> dict.is_empty(non_structural_list_assets)
      },
    }
  }
    |> eval_element(script_hash)
}

fn large_sampler(
  ordering: ListOrdering,
  count: Int,
) -> Sampler<InsertOfInnerListArgs> {
  fn(_) {
    fuzz.map(
      insert_of_inner_list_fuzzer(RootAnchorWithNodes),
      fn(args) {
        let  
            InsertOfInnerListArgs {
              script_hash,
              new_inner_root_key,
              new_inner_root_data,
              new_inner_root_ref_script,
              anchor_link,
              ..
            }
          = args
        let ascending_keys = list.map(
          list.range(1, count),
          one_byte_key_from_int,
        )
        let keys = when ordering is {
          Ascending -> ascending_keys
          _ -> list.reverse(ascending_keys)
        }
        let child_link = list.head(keys)
        let expected_nodes = list.indexed_map(
          keys,
          fn(index, key) {
            ExpectedInnerNode {
              key,
              data: key,
              link: list.at(keys, index + 1),
              reference_script: None,
            }
          },
        )
        let node_outputs = list.map(
          expected_nodes,
          fn(node) {
            let ExpectedInnerNode { key, data, link, reference_script } = node
            element_output(
              script_hash,
              node_asset_name(key),
              Element { data: Node(data), link },
              reference_script,
            )
          },
        )
        let mint = list.foldl(
          keys,
          one_mint(script_hash, node_asset_name(new_inner_root_key))
            |> assets.merge(one_mint(script_hash, extra_asset_name)),
          fn(key, so_far) {
            assets.add(so_far, script_hash, node_asset_name(key), 1)
          },
        )
        InsertOfInnerListArgs {
          ..args,
          inner_ordering: ordering,
          new_inner_root_output: element_output(
            script_hash,
            node_asset_name(new_inner_root_key),
            Element {
              data: InnerRoot { data: new_inner_root_data, child_link },
              link: anchor_link,
            },
            new_inner_root_ref_script,
          ),
          new_inner_root_child_link: child_link,
          inner_node_outputs: node_outputs,
          expected_inner_nodes: expected_nodes,
          expected_last_inner_node_key: list.last(keys),
          tx_mint: mint,
        }
      },
    )
  }
}

fn sample(scenario: InsertOfInnerListCase) -> Sampler<InsertOfInnerListArgs> {
  fn(_) { insert_of_inner_list_fuzzer(scenario) }
}

// Each sampler has a fixed node count, so --max-size 1 measures one context.
// The seed selects the same context in the baseline and prototype runs.
bench with_two_nodes(args via sample(RootAnchorWithNodes)) {
  validate_with_nodes(args)
}

bench empty(args via sample(DescendingOuterAnchorWithEmptyInnerList)) {
  validate_empty(args)
}

test with_two_nodes_fixture(
  args via insert_of_inner_list_fuzzer(RootAnchorWithNodes),
) {
  validate_with_nodes(args)
}

test empty_fixture(
  args via insert_of_inner_list_fuzzer(DescendingOuterAnchorWithEmptyInnerList),
) {
  validate_empty(args)
}

fn large_fixture(
  ordering: ListOrdering,
  count: Int,
) -> Fuzzer<InsertOfInnerListArgs> {
  let sampler = large_sampler(ordering, count)
  sampler(1)
}

bench nodes_16_ascending(args via large_sampler(Ascending, 16)) {
  validate_with_nodes(args)
}

test nodes_16_ascending_fixture(args via large_fixture(Ascending, 16)) {
  validate_with_nodes(args)
}

bench nodes_16_descending(args via large_sampler(Descending, 16)) {
  validate_with_nodes(args)
}

test nodes_16_descending_fixture(args via large_fixture(Descending, 16)) {
  validate_with_nodes(args)
}

bench nodes_64_ascending(args via large_sampler(Ascending, 64)) {
  validate_with_nodes(args)
}

test nodes_64_ascending_fixture(args via large_fixture(Ascending, 64)) {
  validate_with_nodes(args)
}

bench nodes_64_descending(args via large_sampler(Descending, 64)) {
  validate_with_nodes(args)
}

test nodes_64_descending_fixture(args via large_fixture(Descending, 64)) {
  validate_with_nodes(args)
}
