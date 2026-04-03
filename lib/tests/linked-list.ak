use aiken/builtin
use aiken/crypto.{ScriptHash, blake2b_224, sha2_256}
use aiken/fuzz
use aiken/primitive/bytearray
use aiken_design_patterns/linked_list.{
  Element, Eval, Node, Root, append_unordered, deinit, fold_from_root, init,
  insert_ascending, insert_descending, prepend_unordered, remove, run_eval_with,
  run_root_with,
}
use aiken_design_patterns/utils
use cardano/address.{Address, Script, VerificationKey}
use cardano/assets.{PolicyId, Value}
use cardano/transaction.{InlineDatum, Input, Output, OutputReference}

// ## Tests

type GenericElement =
  Element<Data, Data>

const min_lovelace = 2_000_000

const test_root_key = #""

const test_node_key = #"00"

const test_node_key_length = 1

const b_data = builtin.b_data(#"00")

fn change_tn_by(b: ByteArray, change: Int) -> ByteArray {
  let b_length = bytearray.length(b)
  b
    |> bytearray.to_int_big_endian
    |> fn(x: Int) -> Int { x + change }
    |> bytearray.from_int_big_endian(b_length)
}

type KeyOrdering {
  Ascending
  Descending
  Unordered
}

fn two_elements_fuzzer(
  label: ByteArray,
  anchor_is_root: Bool,
  node_has_link: Bool,
  key_ordering: KeyOrdering,
) -> Fuzzer<(ScriptHash, Input, Input)> {
  let label_length = bytearray.length(label)
  let tn_length = 32 - label_length
  let script_hash <- fuzz.and_then(fuzz.bytearray_fixed(28))
  let init_no_label_tn_0 <- fuzz.and_then(fuzz.bytearray_fixed(tn_length))
  let random_no_label_tn_a <- fuzz.and_then(fuzz.bytearray_fixed(tn_length))
  let random_no_label_tn_b <- fuzz.and_then(fuzz.bytearray_fixed(tn_length))
  let (no_label_tn_0, no_label_tn_1, no_label_tn_2) =
    when key_ordering is {
      Ascending ->
        (
          init_no_label_tn_0,
          init_no_label_tn_0 |> change_tn_by(1),
          init_no_label_tn_0 |> change_tn_by(2),
        )
      Descending ->
        (
          init_no_label_tn_0 |> change_tn_by(2),
          init_no_label_tn_0 |> change_tn_by(1),
          init_no_label_tn_0,
        )
      Unordered ->
        (init_no_label_tn_0, random_no_label_tn_a, random_no_label_tn_b)
    }
  let tn_0 =
    if anchor_is_root {
      test_root_key
    } else {
      label |> bytearray.concat(no_label_tn_0)
    }
  let tn_1 = label |> bytearray.concat(no_label_tn_1)
  let lovelace_value = assets.from_lovelace(min_lovelace)
  let state_nft_0 = assets.from_asset(script_hash, tn_0, 1)
  let state_nft_1 = assets.from_asset(script_hash, tn_1, 1)
  let v_0 = assets.merge(lovelace_value, state_nft_0)
  let v_1 = assets.merge(lovelace_value, state_nft_1)
  let out_ref_0 <- fuzz.and_then(utils.output_reference_fuzzer())
  let out_ref_1 <- fuzz.and_then(utils.output_reference_fuzzer())
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
          value: v_0,
          datum: InlineDatum(
            Element {
              data: if anchor_is_root {
                Root(b_data)
              } else {
                Node(b_data)
              },
              link: Some(no_label_tn_1),
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
          value: v_1,
          datum: InlineDatum(
            Element {
              data: Node(b_data),
              link: if node_has_link {
                Some(no_label_tn_2)
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

fn alter_outputs_address(output: Output) -> Output {
  expect Script(script_hash) = output.address.payment_credential
  let altered_address: Address =
    Address {
      payment_credential: VerificationKey(script_hash),
      stake_credential: None,
    }
  Output { ..output, address: altered_address }
}

fn alter_outputs_link(output: Output) -> Output {
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

fn eval_runner(eval: Eval, policy_id: PolicyId) -> Bool {
  eval
    |> run_eval_with(
        policy_id,
        test_root_key,
        test_node_key,
        test_node_key_length,
      )
}

fn init_fuzzer(
  root_datum: Bool,
  link: Option<ByteArray>,
) -> Fuzzer<(List<Input>, OutputReference, ScriptHash, Output)> {
  let inputs <- fuzz.and_then(utils.user_inputs_fuzzer())
  let out_ref =
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
  fuzz.constant((inputs, out_ref, script_hash, script_output))
}

test success__init(init_values via init_fuzzer(True, None)) {
  let (inputs, out_ref, script_hash, script_output) = init_values
  let root_eval = {
    let
      root_lovelace,
      _root_data,
    <-
      init(
        utils.utxo_is_spent(inputs, out_ref),
        script_output,
        assets.from_asset(script_hash, test_root_key, 1),
      )
    expect root_lovelace == min_lovelace
    True
  }
  root_eval |> run_root_with(script_hash, test_root_key)
}

test fail__init__bad_datum(init_values via init_fuzzer(False, None)) fail {
  let (inputs, out_ref, script_hash, script_output) = init_values
  let root_eval = {
    let
      root_lovelace,
      _root_data,
    <-
      init(
        utils.utxo_is_spent(inputs, out_ref),
        script_output,
        assets.from_asset(script_hash, test_root_key, 1),
      )
    expect root_lovelace == min_lovelace
    True
  }
  root_eval |> run_root_with(script_hash, test_root_key)
}

test fail__init__bad_asset_name(init_values via init_fuzzer(True, None)) fail {
  let (inputs, out_ref, script_hash, script_output) = init_values
  let root_eval = {
    let
      root_lovelace,
      _root_data,
    <-
      init(
        utils.utxo_is_spent(inputs, out_ref),
        script_output,
        assets.from_asset(script_hash, test_root_key, 1),
      )
    expect root_lovelace == min_lovelace
    True
  }
  root_eval |> run_root_with(script_hash, "ROOT")
}

test fail__init__bad_nonce(init_values via init_fuzzer(True, None)) fail {
  let (inputs, out_ref, script_hash, script_output) = init_values
  let root_eval = {
    let
      root_lovelace,
      _root_data,
    <-
      init(
        utils.utxo_is_spent(
          inputs,
          out_ref
            |> fn(o_ref: OutputReference) -> OutputReference {
                OutputReference {
                  ..o_ref,
                  transaction_id: sha2_256(o_ref.transaction_id),
                }
              },
        ),
        script_output,
        assets.from_asset(script_hash, test_root_key, 1),
      )
    expect root_lovelace == min_lovelace
    True
  }
  root_eval |> run_root_with(script_hash, test_root_key)
}

test fail__init__bad_first_link(
  init_values via init_fuzzer(True, Some(test_root_key)),
) fail {
  let (inputs, out_ref, script_hash, script_output) = init_values
  let root_eval = {
    let
      root_lovelace,
      _root_data,
    <-
      init(
        utils.utxo_is_spent(inputs, out_ref),
        script_output,
        assets.from_asset(script_hash, test_root_key, 1),
      )
    expect root_lovelace == min_lovelace
    True
  }
  root_eval |> run_root_with(script_hash, test_root_key)
}

test fail__init__bad_nft_symbol(init_values via init_fuzzer(True, None)) fail {
  let (inputs, out_ref, script_hash, script_output) = init_values
  let root_eval = {
    let
      root_lovelace,
      _root_data,
    <-
      init(
        utils.utxo_is_spent(inputs, out_ref),
        script_output,
        assets.from_asset(script_hash, test_root_key, 1),
      )
    expect root_lovelace == min_lovelace
    True
  }
  root_eval |> run_root_with(blake2b_224(script_hash), test_root_key)
}

test fail__init__bad_root_data_validator(
  init_values via init_fuzzer(True, None),
) fail {
  let (inputs, out_ref, script_hash, script_output) = init_values
  {
    let
      root_lovelace,
      _root_data,
    <-
      init(
        utils.utxo_is_spent(inputs, out_ref),
        script_output,
        assets.from_asset(script_hash, test_root_key, 1),
      )
    expect root_lovelace == min_lovelace
    False
  }
    |> run_root_with(script_hash, test_root_key)
}

test fail__init__bad_mint(init_values via init_fuzzer(True, None)) fail {
  let (inputs, out_ref, script_hash, script_output) = init_values
  let root_eval = {
    let
      root_lovelace,
      _root_data,
    <- init(utils.utxo_is_spent(inputs, out_ref), script_output, assets.zero)
    expect root_lovelace == min_lovelace
    True
  }
  root_eval |> run_root_with(script_hash, test_root_key)
}

test success__deinit(init_values via init_fuzzer(True, None)) {
  let (_inputs, out_ref, script_hash, script_output) = init_values
  let root_input = Input { output_reference: out_ref, output: script_output }
  let root_eval = {
    let
      root_lovelace,
      _root_data,
    <- deinit(root_input, assets.from_asset(script_hash, test_root_key, -1))
    expect root_lovelace == min_lovelace
    True
  }
  root_eval |> run_root_with(script_hash, test_root_key)
}

test fail__deinit__bad_datum(init_values via init_fuzzer(False, None)) fail {
  let (_inputs, out_ref, script_hash, script_output) = init_values
  let root_input = Input { output_reference: out_ref, output: script_output }
  let root_eval = {
    let
      root_lovelace,
      _root_data,
    <- deinit(root_input, assets.from_asset(script_hash, test_root_key, -1))
    expect root_lovelace == min_lovelace
    True
  }
  root_eval |> run_root_with(script_hash, test_root_key)
}

test fail__deinit__bad_link(
  init_values via init_fuzzer(
    True,
    Some(#"0000000000000000000000000000000000000000000000000000000000000000"),
  ),
) fail {
  let (_inputs, out_ref, script_hash, script_output) = init_values
  let root_input = Input { output_reference: out_ref, output: script_output }
  let root_eval = {
    let
      root_lovelace,
      _root_data,
    <- deinit(root_input, assets.from_asset(script_hash, test_root_key, -1))
    expect root_lovelace == min_lovelace
    True
  }
  root_eval |> run_root_with(script_hash, test_root_key)
}

test fail__deinit__bad_nft_symbol(init_values via init_fuzzer(True, None)) fail {
  let (_inputs, out_ref, script_hash, script_output) = init_values
  let root_input = Input { output_reference: out_ref, output: script_output }
  let root_eval = {
    let
      root_lovelace,
      _root_data,
    <- deinit(root_input, assets.from_asset(script_hash, test_root_key, -1))
    expect root_lovelace == min_lovelace
    True
  }
  root_eval |> run_root_with(blake2b_224(script_hash), test_root_key)
}

test fail__deinit__bad_root_data_validator(
  init_values via init_fuzzer(True, None),
) fail {
  let (_inputs, out_ref, script_hash, script_output) = init_values
  let root_input = Input { output_reference: out_ref, output: script_output }
  let root_eval = {
    let
      root_lovelace,
      _root_data,
    <- deinit(root_input, assets.from_asset(script_hash, test_root_key, -1))
    expect root_lovelace == min_lovelace
    False
  }
  root_eval |> run_root_with(script_hash, test_root_key)
}

test fail__deinit__bad_mint(init_values via init_fuzzer(True, None)) fail {
  let (_inputs, out_ref, script_hash, script_output) = init_values
  let root_input = Input { output_reference: out_ref, output: script_output }
  let root_eval = {
    let root_lovelace, _root_data <- deinit(root_input, assets.zero)
    expect root_lovelace == min_lovelace
    True
  }
  root_eval |> run_root_with(script_hash, test_root_key)
}

fn additional_test_helper(
  anchor_is_root: Bool,
  args: (ScriptHash, Input, Input),
) -> Fuzzer<(ScriptHash, Input, Output, Output, Value)> {
  let (script_hash, cont_root_input, node_input) = args
  expect InlineDatum(node_datum_data) = node_input.output.datum
  expect Element { link: nodes_link, .. }: GenericElement = node_datum_data
  let root_element: GenericElement =
    Element(
      if anchor_is_root {
        Root(b_data)
      } else {
        Node(b_data)
      },
      nodes_link,
    )
  let root_output: Output =
    Output { ..cont_root_input.output, datum: InlineDatum(root_element) }
  let root_input: Input = Input { ..cont_root_input, output: root_output }
  fuzz.constant(
    (
      script_hash,
      root_input,
      cont_root_input.output,
      node_input.output,
      node_input.output.value |> assets.without_lovelace,
    ),
  )
}

fn insert_ordered_fuzzer() -> Fuzzer<
  (Bool, ScriptHash, Input, Output, Output, Value),
> {
  let label = test_node_key
  let anchor_is_root <- fuzz.and_then(fuzz.bool())
  let node_has_link <- fuzz.and_then(fuzz.bool())
  let is_ascending <- fuzz.and_then(fuzz.bool())
  let args <-
    fuzz.and_then(
      two_elements_fuzzer(
        label,
        anchor_is_root,
        node_has_link,
        if is_ascending {
          Ascending
        } else {
          Descending
        },
      ),
    )
  let (script_hash, anchor_input, cont_anchor_output, node_output, mint_value) <-
    fuzz.and_then(additional_test_helper(anchor_is_root, args))
  fuzz.constant(
    (
      is_ascending,
      script_hash,
      anchor_input,
      cont_anchor_output,
      node_output,
      mint_value,
    ),
  )
}

test insert_unit_test() {
  let is_ascending = False
  let script_hash = #"00000000000000000000000000000000000000000000000000000000"
  let tn_0 = #"000000000000000000000000000000000000000000000000000000"
  let tn_1 = #"000000000000000000000000000000000000000000000000000001"
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
        datum: InlineDatum(Element { data: Root(b_data), link: Some(tn_0) }),
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
      datum: InlineDatum(Element { data: Root(b_data), link: Some(tn_1) }),
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
              test_node_key |> bytearray.concat(tn_1),
              1,
            ),
          ),
      datum: InlineDatum(Element { data: Node(b_data), link: Some(tn_0) }),
      reference_script: None,
    }
  let mint_value =
    assets.from_asset(script_hash, test_node_key |> bytearray.concat(tn_1), 1)
  let insert_fn =
    if is_ascending {
      insert_ascending
    } else {
      insert_descending
    }
  let eval = {
    let
      anchor_lovelace_change,
      _m_anchor_key,
      _anchor_data,
      new_node_lovelace,
      _new_key,
      _new_node_data,
      _new_node_link,
    <- insert_fn(root_input, cont_root_output, node_output, mint_value)
    expect and {
        anchor_lovelace_change == 0,
        new_node_lovelace == min_lovelace,
      }
    True
  }
  eval |> eval_runner(script_hash)
}

test success__insert(insert_ordered_args via insert_ordered_fuzzer()) {
  let (
    is_ascending,
    script_hash,
    root_input,
    cont_root_output,
    node_output,
    mint_value,
  ) = insert_ordered_args
  let insert_fn =
    if is_ascending {
      insert_ascending
    } else {
      insert_descending
    }
  let eval = {
    let
      anchor_lovelace_change,
      _m_anchor_key,
      _anchor_data,
      new_node_lovelace,
      _new_key,
      _new_node_data,
      _new_node_link,
    <- insert_fn(root_input, cont_root_output, node_output, mint_value)
    expect and {
        anchor_lovelace_change == 0,
        new_node_lovelace == min_lovelace,
      }
    True
  }
  eval |> eval_runner(script_hash)
}

test fail__insert__bad_nft_symbol(
  insert_ordered_args via insert_ordered_fuzzer(),
) fail {
  let (
    is_ascending,
    script_hash,
    root_input,
    cont_root_output,
    node_output,
    mint_value,
  ) = insert_ordered_args
  let insert_fn =
    if is_ascending {
      insert_ascending
    } else {
      insert_descending
    }
  let eval = {
    let
      anchor_lovelace_change,
      _m_anchor_key,
      _anchor_data,
      new_node_lovelace,
      _new_key,
      _new_node_data,
      _new_node_link,
    <- insert_fn(root_input, cont_root_output, node_output, mint_value)
    expect and {
        anchor_lovelace_change == 0,
        new_node_lovelace == min_lovelace,
      }
    True
  }
  eval |> eval_runner(blake2b_224(script_hash))
}

test fail__insert__bad_continued_root_destination(
  insert_ordered_args via insert_ordered_fuzzer(),
) fail {
  let (
    is_ascending,
    script_hash,
    root_input,
    cont_root_output,
    node_output,
    mint_value,
  ) = insert_ordered_args
  let insert_fn =
    if is_ascending {
      insert_ascending
    } else {
      insert_descending
    }
  let eval = {
    let
      anchor_lovelace_change,
      _m_anchor_key,
      _anchor_data,
      new_node_lovelace,
      _new_key,
      _new_node_data,
      _new_node_link,
    <-
      insert_fn(
        root_input,
        alter_outputs_address(cont_root_output),
        node_output,
        mint_value,
      )
    expect and {
        anchor_lovelace_change == 0,
        new_node_lovelace == min_lovelace,
      }
    True
  }
  eval |> eval_runner(script_hash)
}

test fail__insert__bad_node_destination(
  insert_ordered_args via insert_ordered_fuzzer(),
) fail {
  let (
    is_ascending,
    script_hash,
    root_input,
    cont_root_output,
    node_output,
    mint_value,
  ) = insert_ordered_args
  let insert_fn =
    if is_ascending {
      insert_ascending
    } else {
      insert_descending
    }
  let eval = {
    let
      anchor_lovelace_change,
      _m_anchor_key,
      _anchor_data,
      new_node_lovelace,
      _new_key,
      _new_node_data,
      _new_node_link,
    <-
      insert_fn(
        root_input,
        cont_root_output,
        alter_outputs_address(node_output),
        mint_value,
      )
    expect and {
        anchor_lovelace_change == 0,
        new_node_lovelace == min_lovelace,
      }
    True
  }
  eval |> eval_runner(script_hash)
}

test fail__insert__bad_continued_root_link(
  insert_ordered_args via insert_ordered_fuzzer(),
) fail {
  let (
    is_ascending,
    script_hash,
    root_input,
    cont_root_output,
    node_output,
    mint_value,
  ) = insert_ordered_args
  let insert_fn =
    if is_ascending {
      insert_ascending
    } else {
      insert_descending
    }
  let eval = {
    let
      anchor_lovelace_change,
      _m_anchor_key,
      _anchor_data,
      new_node_lovelace,
      _new_key,
      _new_node_data,
      _new_node_link,
    <-
      insert_fn(
        root_input,
        alter_outputs_link(cont_root_output),
        node_output,
        mint_value,
      )
    expect and {
        anchor_lovelace_change == 0,
        new_node_lovelace == min_lovelace,
      }
    True
  }
  eval |> eval_runner(script_hash)
}

test fail__insert__bad_node_link(
  insert_ordered_args via insert_ordered_fuzzer(),
) fail {
  let (
    is_ascending,
    script_hash,
    root_input,
    cont_root_output,
    node_output,
    mint_value,
  ) = insert_ordered_args
  let insert_fn =
    if is_ascending {
      insert_ascending
    } else {
      insert_descending
    }
  let eval = {
    let
      anchor_lovelace_change,
      _m_anchor_key,
      _anchor_data,
      new_node_lovelace,
      _new_key,
      _new_node_data,
      _new_node_link,
    <-
      insert_fn(
        root_input,
        cont_root_output,
        alter_outputs_link(node_output),
        mint_value,
      )
    expect and {
        anchor_lovelace_change == 0,
        new_node_lovelace == min_lovelace,
      }
    True
  }
  eval |> eval_runner(script_hash)
}

test fail__insert__bad_additional_validator(
  insert_ordered_args via insert_ordered_fuzzer(),
) fail {
  let (
    is_ascending,
    script_hash,
    root_input,
    cont_root_output,
    node_output,
    mint_value,
  ) = insert_ordered_args
  let insert_fn =
    if is_ascending {
      insert_ascending
    } else {
      insert_descending
    }
  let eval = {
    let
      anchor_lovelace_change,
      _m_anchor_key,
      _anchor_data,
      new_node_lovelace,
      _new_key,
      _new_node_data,
      _new_node_link,
    <- insert_fn(root_input, cont_root_output, node_output, mint_value)
    expect and {
        anchor_lovelace_change == 0,
        new_node_lovelace == min_lovelace,
      }
    False
  }
  eval |> eval_runner(script_hash)
}

test fail__insert__bad_mint(
  insert_ordered_args via insert_ordered_fuzzer(),
) fail {
  let (
    is_ascending,
    script_hash,
    root_input,
    cont_root_output,
    node_output,
    _mint_value,
  ) = insert_ordered_args
  let insert_fn =
    if is_ascending {
      insert_ascending
    } else {
      insert_descending
    }
  let eval = {
    let
      anchor_lovelace_change,
      _m_anchor_key,
      _anchor_data,
      new_node_lovelace,
      _new_key,
      _new_node_data,
      _new_node_link,
    <- insert_fn(root_input, cont_root_output, node_output, assets.zero)
    expect and {
        anchor_lovelace_change == 0,
        new_node_lovelace == min_lovelace,
      }
    True
  }
  eval |> eval_runner(script_hash)
}

fn append_unordered_fuzzer(
  node_has_link: Bool,
) -> Fuzzer<(ScriptHash, Input, Output, Output, Value)> {
  let label = test_node_key
  let anchor_is_root <- fuzz.and_then(fuzz.bool())
  let args <-
    fuzz.and_then(
      two_elements_fuzzer(label, anchor_is_root, node_has_link, Unordered),
    )
  additional_test_helper(anchor_is_root, args)
}

test success__append(append_unordered_args via append_unordered_fuzzer(False)) {
  let (script_hash, root_input, cont_root_output, node_output, mint_value) =
    append_unordered_args
  let eval = {
    let
      anchor_lovelace_change,
      _m_anchor_key,
      _anchor_data,
      new_node_lovelace,
      _new_key,
      _new_node_data,
    <- append_unordered(root_input, cont_root_output, node_output, mint_value)
    expect and {
        anchor_lovelace_change == 0,
        new_node_lovelace == min_lovelace,
      }
    True
  }
  eval |> eval_runner(script_hash)
}

test fail__append__node_has_link(
  append_unordered_args via append_unordered_fuzzer(True),
) fail {
  let (script_hash, root_input, cont_root_output, node_output, mint_value) =
    append_unordered_args
  let eval = {
    let
      anchor_lovelace_change,
      _m_anchor_key,
      _anchor_data,
      new_node_lovelace,
      _new_key,
      _new_node_data,
    <- append_unordered(root_input, cont_root_output, node_output, mint_value)
    expect and {
        anchor_lovelace_change == 0,
        new_node_lovelace == min_lovelace,
      }
    True
  }
  eval |> eval_runner(script_hash)
}

test fail__append__bad_nft_symbol(
  append_unordered_args via append_unordered_fuzzer(False),
) fail {
  let (script_hash, root_input, cont_root_output, node_output, mint_value) =
    append_unordered_args
  let eval = {
    let
      anchor_lovelace_change,
      _m_anchor_key,
      _anchor_data,
      new_node_lovelace,
      _new_key,
      _new_node_data,
    <- append_unordered(root_input, cont_root_output, node_output, mint_value)
    expect and {
        anchor_lovelace_change == 0,
        new_node_lovelace == min_lovelace,
      }
    True
  }
  eval |> eval_runner(blake2b_224(script_hash))
}

test fail__append__bad_continued_root_destination(
  append_unordered_args via append_unordered_fuzzer(False),
) fail {
  let (script_hash, root_input, cont_root_output, node_output, mint_value) =
    append_unordered_args
  let altered_cont_root_output = alter_outputs_address(cont_root_output)
  let eval = {
    let
      anchor_lovelace_change,
      _m_anchor_key,
      _anchor_data,
      new_node_lovelace,
      _new_key,
      _new_node_data,
    <-
      append_unordered(
        root_input,
        altered_cont_root_output,
        node_output,
        mint_value,
      )
    expect and {
        anchor_lovelace_change == 0,
        new_node_lovelace == min_lovelace,
      }
    True
  }
  eval |> eval_runner(script_hash)
}

test fail__append__bad_node_destination(
  append_unordered_args via append_unordered_fuzzer(False),
) fail {
  let (script_hash, root_input, cont_root_output, node_output, mint_value) =
    append_unordered_args
  let altered_node_output = alter_outputs_address(node_output)
  let eval = {
    let
      anchor_lovelace_change,
      _m_anchor_key,
      _anchor_data,
      new_node_lovelace,
      _new_key,
      _new_node_data,
    <-
      append_unordered(
        root_input,
        cont_root_output,
        altered_node_output,
        mint_value,
      )
    expect and {
        anchor_lovelace_change == 0,
        new_node_lovelace == min_lovelace,
      }
    True
  }
  eval |> eval_runner(script_hash)
}

test fail__append__bad_continued_root_link(
  append_unordered_args via append_unordered_fuzzer(False),
) fail {
  let (script_hash, root_input, cont_root_output, node_output, mint_value) =
    append_unordered_args
  let altered_cont_root_output = alter_outputs_link(cont_root_output)
  let eval = {
    let
      anchor_lovelace_change,
      _m_anchor_key,
      _anchor_data,
      new_node_lovelace,
      _new_key,
      _new_node_data,
    <-
      append_unordered(
        root_input,
        altered_cont_root_output,
        node_output,
        mint_value,
      )
    expect and {
        anchor_lovelace_change == 0,
        new_node_lovelace == min_lovelace,
      }
    True
  }
  eval |> eval_runner(script_hash)
}

test fail__append__bad_node_link(
  append_unordered_args via append_unordered_fuzzer(False),
) fail {
  let (script_hash, root_input, cont_root_output, node_output, mint_value) =
    append_unordered_args
  let altered_node_output = alter_outputs_link(node_output)
  let eval = {
    let
      anchor_lovelace_change,
      _m_anchor_key,
      _anchor_data,
      new_node_lovelace,
      _new_key,
      _new_node_data,
    <-
      append_unordered(
        root_input,
        cont_root_output,
        altered_node_output,
        mint_value,
      )
    expect and {
        anchor_lovelace_change == 0,
        new_node_lovelace == min_lovelace,
      }
    True
  }
  eval |> eval_runner(script_hash)
}

test fail__append__bad_mint(
  append_unordered_args via append_unordered_fuzzer(False),
) fail {
  let (script_hash, root_input, cont_root_output, node_output, _mint_value) =
    append_unordered_args
  let eval = {
    let
      anchor_lovelace_change,
      _m_anchor_key,
      _anchor_data,
      new_node_lovelace,
      _new_key,
      _new_node_data,
    <- append_unordered(root_input, cont_root_output, node_output, assets.zero)
    expect and {
        anchor_lovelace_change == 0,
        new_node_lovelace == min_lovelace,
      }
    True
  }
  eval |> eval_runner(script_hash)
}

fn prepend_unordered_fuzzer(
  anchor_is_root: Bool,
) -> Fuzzer<(ScriptHash, Input, Output, Output, Value)> {
  let label = test_node_key
  let node_has_link <- fuzz.and_then(fuzz.bool())
  let args <-
    fuzz.and_then(
      two_elements_fuzzer(label, anchor_is_root, node_has_link, Unordered),
    )
  additional_test_helper(anchor_is_root, args)
}

test success__prepend(prepend_unordered_args via prepend_unordered_fuzzer(True)) {
  let (script_hash, root_input, cont_root_output, node_output, mint_value) =
    prepend_unordered_args
  let eval = {
    let
      root_lovelace_change,
      _root_data,
      new_node_lovelace,
      _new_key,
      _new_node_data,
      _new_node_link,
    <- prepend_unordered(root_input, cont_root_output, node_output, mint_value)
    expect and {
        root_lovelace_change == 0,
        new_node_lovelace == min_lovelace,
      }
    True
  }
  eval |> eval_runner(script_hash)
}

test fail__prepend__non_root_anchor(
  prepend_unordered_args via prepend_unordered_fuzzer(False),
) fail {
  let (script_hash, root_input, cont_root_output, node_output, mint_value) =
    prepend_unordered_args
  let eval = {
    let
      root_lovelace_change,
      _root_data,
      new_node_lovelace,
      _new_key,
      _new_node_data,
      _new_node_link,
    <- prepend_unordered(root_input, cont_root_output, node_output, mint_value)
    expect and {
        root_lovelace_change == 0,
        new_node_lovelace == min_lovelace,
      }
    True
  }
  eval |> eval_runner(script_hash)
}

test fail__prepend__bad_nft_symbol(
  prepend_unordered_args via prepend_unordered_fuzzer(True),
) fail {
  let (script_hash, root_input, cont_root_output, node_output, mint_value) =
    prepend_unordered_args
  let eval = {
    let
      root_lovelace_change,
      _root_data,
      new_node_lovelace,
      _new_key,
      _new_node_data,
      _new_node_link,
    <- prepend_unordered(root_input, cont_root_output, node_output, mint_value)
    expect and {
        root_lovelace_change == 0,
        new_node_lovelace == min_lovelace,
      }
    True
  }
  eval |> eval_runner(blake2b_224(script_hash))
}

test fail__prepend__bad_continued_root_destination(
  prepend_unordered_args via prepend_unordered_fuzzer(True),
) fail {
  let (script_hash, root_input, cont_root_output, node_output, mint_value) =
    prepend_unordered_args
  let eval = {
    let
      root_lovelace_change,
      _root_data,
      new_node_lovelace,
      _new_key,
      _new_node_data,
      _new_node_link,
    <-
      prepend_unordered(
        root_input,
        alter_outputs_address(cont_root_output),
        node_output,
        mint_value,
      )
    expect and {
        root_lovelace_change == 0,
        new_node_lovelace == min_lovelace,
      }
    True
  }
  eval |> eval_runner(script_hash)
}

test fail__prepend__bad_node_destination(
  prepend_unordered_args via prepend_unordered_fuzzer(True),
) fail {
  let (script_hash, root_input, cont_root_output, node_output, mint_value) =
    prepend_unordered_args
  let eval = {
    let
      root_lovelace_change,
      _root_data,
      new_node_lovelace,
      _new_key,
      _new_node_data,
      _new_node_link,
    <-
      prepend_unordered(
        root_input,
        cont_root_output,
        alter_outputs_address(node_output),
        mint_value,
      )
    expect and {
        root_lovelace_change == 0,
        new_node_lovelace == min_lovelace,
      }
    True
  }
  eval |> eval_runner(script_hash)
}

test fail__prepend__bad_continued_root_link(
  prepend_unordered_args via prepend_unordered_fuzzer(True),
) fail {
  let (script_hash, root_input, cont_root_output, node_output, mint_value) =
    prepend_unordered_args
  let eval = {
    let
      root_lovelace_change,
      _root_data,
      new_node_lovelace,
      _new_key,
      _new_node_data,
      _new_node_link,
    <-
      prepend_unordered(
        root_input,
        alter_outputs_link(cont_root_output),
        node_output,
        mint_value,
      )
    expect and {
        root_lovelace_change == 0,
        new_node_lovelace == min_lovelace,
      }
    True
  }
  eval |> eval_runner(script_hash)
}

test fail__prepend__bad_node_link(
  prepend_unordered_args via prepend_unordered_fuzzer(True),
) fail {
  let (script_hash, root_input, cont_root_output, node_output, mint_value) =
    prepend_unordered_args
  let eval = {
    let
      root_lovelace_change,
      _root_data,
      new_node_lovelace,
      _new_key,
      _new_node_data,
      _new_node_link,
    <-
      prepend_unordered(
        root_input,
        cont_root_output,
        alter_outputs_link(node_output),
        mint_value,
      )
    expect and {
        root_lovelace_change == 0,
        new_node_lovelace == min_lovelace,
      }
    True
  }
  eval |> eval_runner(script_hash)
}

test fail__prepend__bad_mint(
  prepend_unordered_args via prepend_unordered_fuzzer(True),
) fail {
  let (script_hash, root_input, cont_root_output, node_output, _mint_value) =
    prepend_unordered_args
  let eval = {
    let
      root_lovelace_change,
      _root_data,
      new_node_lovelace,
      _new_key,
      _new_node_data,
      _new_node_link,
    <- prepend_unordered(root_input, cont_root_output, node_output, assets.zero)
    expect and {
        root_lovelace_change == 0,
        new_node_lovelace == min_lovelace,
      }
    True
  }
  eval |> eval_runner(script_hash)
}

fn remove_fuzzer() -> Fuzzer<(ScriptHash, Input, Input, Output, Value)> {
  let anchor_is_root <- fuzz.and_then(fuzz.bool())
  fold_from_root_fuzzer(anchor_is_root)
}

test success__remove(remove_args via remove_fuzzer()) {
  let (script_hash, root_input, node_input, cont_root_output, mint_value) =
    remove_args
  let eval = {
    let
      anchor_lovelace_change,
      _m_anchor_key,
      _anchor_data,
      removing_node_lovelace,
      _removing_key,
      _removing_node_data,
      _removing_node_link,
    <- remove(root_input, node_input, cont_root_output, mint_value)
    expect and {
        anchor_lovelace_change == 0,
        removing_node_lovelace == min_lovelace,
      }
    True
  }
  eval |> eval_runner(script_hash)
}

test fail__remove__bad_nft_symbol(remove_args via remove_fuzzer()) fail {
  let (script_hash, root_input, node_input, cont_root_output, mint_value) =
    remove_args
  let eval = {
    let
      anchor_lovelace_change,
      _m_anchor_key,
      _anchor_data,
      removing_node_lovelace,
      _removing_key,
      _removing_node_data,
      _removing_node_link,
    <- remove(root_input, node_input, cont_root_output, mint_value)
    expect and {
        anchor_lovelace_change == 0,
        removing_node_lovelace == min_lovelace,
      }
    True
  }
  eval |> eval_runner(blake2b_224(script_hash))
}

test fail__remove__bad_continued_root_destination(
  remove_args via remove_fuzzer(),
) fail {
  let (script_hash, root_input, node_input, cont_root_output, mint_value) =
    remove_args
  let eval = {
    let
      anchor_lovelace_change,
      _m_anchor_key,
      _anchor_data,
      removing_node_lovelace,
      _removing_key,
      _removing_node_data,
      _removing_node_link,
    <-
      remove(
        root_input,
        node_input,
        alter_outputs_address(cont_root_output),
        mint_value,
      )
    expect and {
        anchor_lovelace_change == 0,
        removing_node_lovelace == min_lovelace,
      }
    True
  }
  eval |> eval_runner(script_hash)
}

test fail__remove__bad_continued_root_link(remove_args via remove_fuzzer()) fail {
  let (script_hash, root_input, node_input, cont_root_output, mint_value) =
    remove_args
  let eval = {
    let
      anchor_lovelace_change,
      _m_anchor_key,
      _anchor_data,
      removing_node_lovelace,
      _removing_key,
      _removing_node_data,
      _removing_node_link,
    <-
      remove(
        root_input,
        node_input,
        alter_outputs_link(cont_root_output),
        mint_value,
      )
    expect and {
        anchor_lovelace_change == 0,
        removing_node_lovelace == min_lovelace,
      }
    True
  }
  eval |> eval_runner(script_hash)
}

test fail__remove__bad_additional_validator(
  remove_args via remove_fuzzer(),
) fail {
  let (script_hash, root_input, node_input, cont_root_output, mint_value) =
    remove_args
  let eval = {
    let
      anchor_lovelace_change,
      _m_anchor_key,
      _anchor_data,
      removing_node_lovelace,
      _removing_key,
      _removing_node_data,
      _removing_node_link,
    <- remove(root_input, node_input, cont_root_output, mint_value)
    expect and {
        anchor_lovelace_change == 0,
        removing_node_lovelace == min_lovelace,
      }
    False
  }
  eval |> eval_runner(script_hash)
}

test fail__remove__bad_mint(remove_args via remove_fuzzer()) fail {
  let (script_hash, root_input, node_input, cont_root_output, _mint_value) =
    remove_args
  let eval = {
    let
      anchor_lovelace_change,
      _m_anchor_key,
      _anchor_data,
      removing_node_lovelace,
      _removing_key,
      _removing_node_data,
      _removing_node_link,
    <- remove(root_input, node_input, cont_root_output, assets.zero)
    expect and {
        anchor_lovelace_change == 0,
        removing_node_lovelace == min_lovelace,
      }
    True
  }
  eval |> eval_runner(script_hash)
}

test fail__remove__anchor_burnt(remove_args via remove_fuzzer()) fail {
  let (script_hash, root_input, node_input, cont_root_output, _mint_value) =
    remove_args
  let eval = {
    let
      anchor_lovelace_change,
      _m_anchor_key,
      _anchor_data,
      removing_node_lovelace,
      _removing_key,
      _removing_node_data,
      _removing_node_link,
    <-
      remove(
        root_input,
        node_input,
        cont_root_output,
        cont_root_output.value |> assets.without_lovelace |> assets.negate,
      )
    expect and {
        anchor_lovelace_change == 0,
        removing_node_lovelace == min_lovelace,
      }
    True
  }
  eval |> eval_runner(script_hash)
}

fn fold_from_root_fuzzer(
  anchor_is_root: Bool,
) -> Fuzzer<(ScriptHash, Input, Input, Output, Value)> {
  let label = test_node_key
  let node_has_link <- fuzz.and_then(fuzz.bool())
  let (script_hash, root_input, node_input) <-
    fuzz.and_then(
      two_elements_fuzzer(label, anchor_is_root, node_has_link, Unordered),
    )
  expect InlineDatum(node_datum_data) = node_input.output.datum
  expect Element { link: nodes_link, .. }: GenericElement = node_datum_data
  let cont_root_element: GenericElement =
    Element(
      if anchor_is_root {
        Root(b_data)
      } else {
        Node(b_data)
      },
      nodes_link,
    )
  let cont_root_output: Output =
    Output { ..root_input.output, datum: InlineDatum(cont_root_element) }
  fuzz.constant(
    (
      script_hash,
      root_input,
      node_input,
      cont_root_output,
      node_input.output.value |> assets.without_lovelace |> assets.negate,
    ),
  )
}

test success__fold_from_root(fold_args via fold_from_root_fuzzer(True)) {
  let (script_hash, root_input, node_input, cont_root_output, mint_value) =
    fold_args
  fold_from_root(
    root_input,
    node_input,
    cont_root_output,
    mint_value,
    fn(
      root_lovelace_change,
      _root_data,
      removing_node_lovelace,
      _removing_key,
      _removing_node_data,
      _removing_node_link,
      _cont_root_data,
    ) {
      expect and {
          root_lovelace_change == 0,
          removing_node_lovelace == min_lovelace,
        }
      True
    },
  )
    |> eval_runner(script_hash)
}

test fail__fold_from_root__bad_nft_symbol(
  fold_args via fold_from_root_fuzzer(True),
) fail {
  let (script_hash, root_input, node_input, cont_root_output, mint_value) =
    fold_args
  fold_from_root(
    root_input,
    node_input,
    cont_root_output,
    mint_value,
    fn(
      root_lovelace_change,
      _root_data,
      removing_node_lovelace,
      _removing_key,
      _removing_node_data,
      _removing_node_link,
      _cont_root_data,
    ) {
      expect and {
          root_lovelace_change == 0,
          removing_node_lovelace == min_lovelace,
        }
      True
    },
  )
    |> eval_runner(blake2b_224(script_hash))
}

test fail__fold_from_root__bad_continued_root_destination(
  fold_args via fold_from_root_fuzzer(True),
) fail {
  let (script_hash, root_input, node_input, cont_root_output, mint_value) =
    fold_args
  fold_from_root(
    root_input,
    node_input,
    alter_outputs_address(cont_root_output),
    mint_value,
    fn(
      root_lovelace_change,
      _root_data,
      removing_node_lovelace,
      _removing_key,
      _removing_node_data,
      _removing_node_link,
      _cont_root_data,
    ) {
      expect and {
          root_lovelace_change == 0,
          removing_node_lovelace == min_lovelace,
        }
      True
    },
  )
    |> eval_runner(script_hash)
}

test fail__fold_from_root__bad_continued_root_link(
  fold_args via fold_from_root_fuzzer(True),
) fail {
  let (script_hash, root_input, node_input, cont_root_output, mint_value) =
    fold_args
  fold_from_root(
    root_input,
    node_input,
    alter_outputs_link(cont_root_output),
    mint_value,
    fn(
      root_lovelace_change,
      _root_data,
      removing_node_lovelace,
      _removing_key,
      _removing_node_data,
      _removing_node_link,
      _cont_root_data,
    ) {
      expect and {
          root_lovelace_change == 0,
          removing_node_lovelace == min_lovelace,
        }
      True
    },
  )
    |> eval_runner(script_hash)
}

test fail__fold_from_root__bad_additional_validator(
  fold_args via fold_from_root_fuzzer(True),
) fail {
  let (script_hash, root_input, node_input, cont_root_output, mint_value) =
    fold_args
  fold_from_root(
    root_input,
    node_input,
    cont_root_output,
    mint_value,
    fn(
      root_lovelace_change,
      _root_data,
      removing_node_lovelace,
      _removing_key,
      _removing_node_data,
      _removing_node_link,
      _cont_root_data,
    ) {
      expect and {
          root_lovelace_change == 0,
          removing_node_lovelace == min_lovelace,
        }
      False
    },
  )
    |> eval_runner(script_hash)
}

test fail__fold_from_root__bad_mint(
  fold_args via fold_from_root_fuzzer(True),
) fail {
  let (script_hash, root_input, node_input, cont_root_output, _mint_value) =
    fold_args
  fold_from_root(
    root_input,
    node_input,
    cont_root_output,
    assets.zero,
    fn(
      root_lovelace_change,
      _root_data,
      removing_node_lovelace,
      _removing_key,
      _removing_node_data,
      _removing_node_link,
      _cont_root_data,
    ) {
      expect and {
          root_lovelace_change == 0,
          removing_node_lovelace == min_lovelace,
        }
      True
    },
  )
    |> eval_runner(script_hash)
}

test fail__fold_from_root__bad_anchor(
  fold_args via fold_from_root_fuzzer(False),
) fail {
  let (script_hash, root_input, node_input, cont_root_output, mint_value) =
    fold_args
  fold_from_root(
    root_input,
    node_input,
    cont_root_output,
    mint_value,
    fn(
      root_lovelace_change,
      _root_data,
      removing_node_lovelace,
      _removing_key,
      _removing_node_data,
      _removing_node_link,
      _cont_root_data,
    ) {
      expect and {
          root_lovelace_change == 0,
          removing_node_lovelace == min_lovelace,
        }
      True
    },
  )
    |> eval_runner(script_hash)
}

test fail__fold_from_root__anchor_burnt(
  fold_args via fold_from_root_fuzzer(True),
) fail {
  let (script_hash, root_input, node_input, cont_root_output, _mint_value) =
    fold_args
  fold_from_root(
    root_input,
    node_input,
    cont_root_output,
    cont_root_output.value |> assets.without_lovelace |> assets.negate,
    fn(
      root_lovelace_change,
      _root_data,
      removing_node_lovelace,
      _removing_key,
      _removing_node_data,
      _removing_node_link,
      _cont_root_data,
    ) {
      expect and {
          root_lovelace_change == 0,
          removing_node_lovelace == min_lovelace,
        }
      True
    },
  )
    |> eval_runner(script_hash)
}

// ## Extra Mint Tests
//
// These tests verify that minting additional NFTs under the same policy
// alongside a legitimate operation is rejected. Each test constructs a
// "poisoned" mint value that includes the correct NFT plus an extra one.

/// Helper to add an extra NFT under the same policy to a mint value.
fn add_extra_mint(mint_value: Value, policy_id: PolicyId) -> Value {
  let extra_token_name = #"deadbeef"
  assets.merge(mint_value, assets.from_asset(policy_id, extra_token_name, 1))
}

test fail__init__extra_mint(init_values via init_fuzzer(True, None)) fail {
  let (inputs, out_ref, script_hash, script_output) = init_values
  let poisoned_mint =
    assets.from_asset(script_hash, test_root_key, 1)
      |> add_extra_mint(script_hash)
  let root_eval = {
    let
      root_lovelace,
      _root_data,
    <- init(utils.utxo_is_spent(inputs, out_ref), script_output, poisoned_mint)
    expect root_lovelace == min_lovelace
    True
  }
  root_eval |> run_root_with(script_hash, test_root_key)
}

test fail__deinit__extra_mint(init_values via init_fuzzer(True, None)) fail {
  let (_inputs, out_ref, script_hash, script_output) = init_values
  let root_input = Input { output_reference: out_ref, output: script_output }
  let poisoned_mint =
    assets.from_asset(script_hash, test_root_key, -1)
      |> add_extra_mint(script_hash)
  let root_eval = {
    let root_lovelace, _root_data <- deinit(root_input, poisoned_mint)
    expect root_lovelace == min_lovelace
    True
  }
  root_eval |> run_root_with(script_hash, test_root_key)
}

test fail__insert__extra_mint(
  insert_ordered_args via insert_ordered_fuzzer(),
) fail {
  let (
    is_ascending,
    script_hash,
    root_input,
    cont_root_output,
    node_output,
    mint_value,
  ) = insert_ordered_args
  let insert_fn =
    if is_ascending {
      insert_ascending
    } else {
      insert_descending
    }
  let poisoned_mint = mint_value |> add_extra_mint(script_hash)
  let eval = {
    let
      anchor_lovelace_change,
      _m_anchor_key,
      _anchor_data,
      new_node_lovelace,
      _new_key,
      _new_node_data,
      _new_node_link,
    <- insert_fn(root_input, cont_root_output, node_output, poisoned_mint)
    expect and {
        anchor_lovelace_change == 0,
        new_node_lovelace == min_lovelace,
      }
    True
  }
  eval |> eval_runner(script_hash)
}

test fail__append__extra_mint(
  append_unordered_args via append_unordered_fuzzer(False),
) fail {
  let (script_hash, root_input, cont_root_output, node_output, mint_value) =
    append_unordered_args
  let poisoned_mint = mint_value |> add_extra_mint(script_hash)
  let eval = {
    let
      anchor_lovelace_change,
      _m_anchor_key,
      _anchor_data,
      new_node_lovelace,
      _new_key,
      _new_node_data,
    <-
      append_unordered(root_input, cont_root_output, node_output, poisoned_mint)
    expect and {
        anchor_lovelace_change == 0,
        new_node_lovelace == min_lovelace,
      }
    True
  }
  eval |> eval_runner(script_hash)
}

test fail__prepend__extra_mint(
  prepend_unordered_args via prepend_unordered_fuzzer(True),
) fail {
  let (script_hash, root_input, cont_root_output, node_output, mint_value) =
    prepend_unordered_args
  let poisoned_mint = mint_value |> add_extra_mint(script_hash)
  let eval = {
    let
      root_lovelace_change,
      _root_data,
      new_node_lovelace,
      _new_key,
      _new_node_data,
      _new_node_link,
    <-
      prepend_unordered(
        root_input,
        cont_root_output,
        node_output,
        poisoned_mint,
      )
    expect and {
        root_lovelace_change == 0,
        new_node_lovelace == min_lovelace,
      }
    True
  }
  eval |> eval_runner(script_hash)
}

test fail__remove__extra_mint(remove_args via remove_fuzzer()) fail {
  let (script_hash, root_input, node_input, cont_root_output, mint_value) =
    remove_args
  let poisoned_mint = mint_value |> add_extra_mint(script_hash)
  let eval = {
    let
      anchor_lovelace_change,
      _m_anchor_key,
      _anchor_data,
      removing_node_lovelace,
      _removing_key,
      _removing_node_data,
      _removing_node_link,
    <- remove(root_input, node_input, cont_root_output, poisoned_mint)
    expect and {
        anchor_lovelace_change == 0,
        removing_node_lovelace == min_lovelace,
      }
    True
  }
  eval |> eval_runner(script_hash)
}

test fail__fold_from_root__extra_mint(
  fold_args via fold_from_root_fuzzer(True),
) fail {
  let (script_hash, root_input, node_input, cont_root_output, mint_value) =
    fold_args
  let poisoned_mint = mint_value |> add_extra_mint(script_hash)
  fold_from_root(
    root_input,
    node_input,
    cont_root_output,
    poisoned_mint,
    fn(
      root_lovelace_change,
      _root_data,
      removing_node_lovelace,
      _removing_key,
      _removing_node_data,
      _removing_node_link,
      _cont_root_data,
    ) {
      expect and {
          root_lovelace_change == 0,
          removing_node_lovelace == min_lovelace,
        }
      True
    },
  )
    |> eval_runner(script_hash)
}
