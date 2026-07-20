use aiken/primitive/bytearray
use aiken_design_patterns/governance_validation.{
  AddProposal, CoupleWithGovernanceAction, GovernanceActionSubmitted,
  Initialized, MintPassedProposal, PassedProposal,
  validate_add_proposal_script_data_hash,
  validate_add_proposal_tx_id_from_script_data_hash,
  validate_pass_script_data_hash, validate_spend_only_script_data_hash,
  validate_tx_id_from_script_data_hash_with_mint,
  validate_tx_id_from_script_data_hash_with_proposal_procedures,
}
use aiken_design_patterns/linked_list.{Element, Node, Root}
use cardano/address.{Address, Inline, Script, VerificationKey}
use cardano/assets
use cardano/transaction.{InlineDatum, Input, NoDatum, Output, OutputReference}

// Fixtures emitted by governance-offchain/examples/happy-path.mjs.
const network_tag = 0

const zero_tx_id =
  #"0000000000000000000000000000000000000000000000000000000000000000"

const governance_policy =
  #"ca87300440ecc00a7976bd1bffc9e145f56759efde723bd452aace35"

const proposer_payment_hash =
  #"b98f586c77582f05dc688ae6731d5fa8aec58577bcf60c806cff1c05"

const proposer_stake_hash =
  #"9dd9b25ab2407d52ae028115abbda92c24ed18135edcfd007c5a85da"

const required_script_for_final_burn =
  #"b0cae7ded5e27464eadd910dfcf0b227da1c5a2a4423a82a57ea28a8"

const governance_reference_tx_id =
  #"f255708031038e462652139127f54e8e9427ffc31296b5c9ca4e2683ad73bd1e"

const root_asset_name = #"50524f504f53414c535f524f4f54"

const node_key = #"0000002a"

const node_asset_name = #"4255494c54494e5f494e4445585f0000002a"

const pass_asset_name =
  #"50415353b0cae7ded5e27464eadd910dfcf0b227da1c5a2a4423a82a57ea28a8"

const collateral_output_cbor =
  #"82583900b98f586c77582f05dc688ae6731d5fa8aec58577bcf60c806cff1c059dd9b25ab2407d52ae028115abbda92c24ed18135edcfd007c5a85da1b000000746a063cc0"

const collateral_fee_cbor = #"1a004c4b40"

const initial_cost_model =
  #"99015e1a000189b41901a401011903e818ad00011903e819ea350401192baf18201a000312591920a404193e801864193e801864193e801864193e801864193e801864193e80186418641864193e8018641a000170a718201a00020782182019f016041a0001194a18b2000119568718201a0001643519030104021a00014f581a0001e143191c893903831906b41903c018391a00014f580001011903e819a7a9040219779f197053184b011a000db464196a8f0119ca3f19022e011999101903e819ecb2011a00022a4718201a000144ce1820193bc318201a0001291101193371041956540a197147184a01197147184a0119a9151902280119aecd19021d0119843c18201a00010a9618201a00011aaa1820191c4b1820191cdf1820192d1a18201a00014f581a0001e143191c893903831906b41903c018391a00014f5800011a0001614219020700011a000122c118201a00014f581a0001e143191c893903831906b41903c018391a00014f580001011a00014f581a0001e143191c893903831906b41903c018391a00014f5800011a000e94721a0003414000021a0004213c19583c041a00163cad19fc3604194ff30104001a00022aa818201a000189b41901a401011a00013eff182019e86a1820194eae182019600c1820195108182019654d182019602f18201a0290f1e70a1a032e93af1937fd0a1a0298e40b1966c40a193e801864193e8018641a000eaf1f121a002a6e06061a0006be98011a0321aac7190eac121a00041699121a048e466e1922a4121a0327ec9a121a001e743c18241a0031410f0c1a000dbf9e011a09f2f6d31910d318241a0004578218241a096e44021967b518241a0473cee818241a13e62472011a0f23d40118481a00212c5618481a0022814619fc3b041a00032b00192076041a0013be0419702c183f00011a000f59d919aa6718fb00011a000187551902d61902cf00011a000187551902d61902cf00011a000187551902d61902cf00011a0001a5661902a800011a00017468011a00044a391949a000011a0002bfe2189f01011a00026b371922ee00011a00026e9219226d00011a0001a3e2190ce2011a00019e4919028f011a001df8bb195fc8031a000943b11a0003891119cf9800011a0001c7e71907a5041a000389cb0a1903e819610607011a00038a4a18201a132ed9841a017eceb5121a24d436c71a0402f5a818241a0005723c1947ed182d151a00035b2f1924e4011903e81a0002a0541a0002cb6e061818151a000341231a00096fa11907ce196e62011903e819950f02161903e81a000176bd01010b1903e81a00043c490c15"

const cost_model_prefix = bytearray.take(initial_cost_model, 107)

const cost_model_postfix = bytearray.drop(initial_cost_model, 108)

const accepted_cost_model =
  cost_model_prefix
    |> bytearray.concat(#"02")
    |> bytearray.concat(cost_model_postfix)

const governance_address =
  Address {
    payment_credential: Script(governance_policy),
    stake_credential: None,
  }

const proposer_address =
  Address {
    payment_credential: VerificationKey(proposer_payment_hash),
    stake_credential: Some(Inline(VerificationKey(proposer_stake_hash))),
  }

fn input(tx_id: ByteArray, output_index: Int) -> Input {
  Input {
    output_reference: OutputReference { transaction_id: tx_id, output_index },
    output: Output {
      address: proposer_address,
      value: assets.from_lovelace(0),
      datum: NoDatum,
      reference_script: None,
    },
  }
}

const governance_reference_inputs = [input(governance_reference_tx_id, 0)]

const root_value =
  assets.from_lovelace(5_000_000)
    |> assets.merge(assets.from_asset(governance_policy, root_asset_name, 1))

const node_value =
  assets.from_lovelace(6_318_460)
    |> assets.merge(assets.from_asset(governance_policy, node_asset_name, 1))

const pass_value =
  assets.from_lovelace(6_318_460)
    |> assets.merge(assets.from_asset(governance_policy, pass_asset_name, 1))

const add_proposal_tx_id =
  #"1f85059eb102ed55ef8de90c27b3e3b7da4c7f84e9e8a51a8d4b7bb418c2aab7"

const add_proposal_script_data_hash =
  #"7bbe0f3ef185908a3e58262c1e0662f8e7bfe2b6ff5ce2f80ffc5caadf6bdf21"

const add_proposal_spend_redeemer_index = 1

const add_proposal_spend_cpu = 16_760_229

const add_proposal_spend_mem = 50_866

const add_proposal_mint_cpu = 607_083_574

const add_proposal_mint_mem = 1_676_468

const add_proposal_invalid_before = 128_812_909

const add_proposal_ttl = 128_813_209

const add_proposal_collateral_inputs_cbor =
  #"d9010281825820000000000000000000000000000000000000000000000000000000000000000002"

const add_proposal_redeemer =
  AddProposal {
    anchor_output_index: 0,
    proposal_node_output_index: 1,
    invalid_before: add_proposal_invalid_before,
    ttl: add_proposal_ttl,
    collateral_inputs: add_proposal_collateral_inputs_cbor,
    collateral_output: collateral_output_cbor,
    collateral_fee: collateral_fee_cbor,
  }

const add_proposal_inputs =
  [
    input(zero_tx_id, 2),
    input(
      #"35c320db746032b4e4527f550945b1808c5506adb6abd41c2f5189e0b08c9e57",
      0,
    ),
  ]

const add_proposal_outputs =
  [
    Output {
      address: governance_address,
      value: root_value,
      datum: InlineDatum(Element { data: Root(#""), link: Some(node_key) }),
      reference_script: None,
    },
    Output {
      address: governance_address,
      value: node_value,
      datum: InlineDatum(
        Element {
          data: Node(
            Initialized {
              proposer: proposer_address,
              subject_script_hash: required_script_for_final_burn,
              initialization_script_data_hash: add_proposal_script_data_hash,
              spend_redeemer_index: add_proposal_spend_redeemer_index,
              cost_model_prefix,
              initial_builtin_cost: 1,
              cost_model_postfix,
              acceptance_builtin_cost: 2,
              spend_cpu: add_proposal_spend_cpu,
              spend_mem: add_proposal_spend_mem,
              mint_cpu: add_proposal_mint_cpu,
              mint_mem: add_proposal_mint_mem,
              must_couple_by: 1_784_500_009_000,
              required_script_for_final_burn,
            },
          ),
          link: None,
        },
      ),
      reference_script: None,
    },
    Output {
      address: proposer_address,
      value: assets.from_lovelace(499_993_107_867),
      datum: NoDatum,
      reference_script: None,
    },
  ]

const add_proposal_mint =
  assets.from_asset(governance_policy, node_asset_name, 1)

const couple_proposal_tx_id =
  #"98327121832b13ef3074903b6d324d62a65d28f9a2cc58bdad65a34e282a841b"

const couple_proposal_script_data_hash =
  #"941e8de6013b829b78a2f9c616d7e02cc0d8f11b5a5db88a8b6b3044c8c6d9ec"

const couple_proposal_spend_redeemer_index = 1

const couple_proposal_spend_cpu = 844_061_451

const couple_proposal_spend_mem = 1_262_077

const couple_proposal_ttl = 128_813_229

const couple_proposal_collateral_inputs_cbor =
  #"d9010281825820000000000000000000000000000000000000000000000000000000000000000003"

const couple_anchor_url =
  #"68747470733a2f2f6578616d706c652e746573742f676f7665726e616e63652f636f73742d6d6f64656c2d3432"

const couple_anchor_data_hash =
  #"0000000000000000000000000000000000000000000000000000000000000000"

const couple_proposal_redeemer =
  CoupleWithGovernanceAction {
    proposal_input_index: 1,
    proposal_output_index: 0,
    ttl: couple_proposal_ttl,
    anchor_url: couple_anchor_url,
    anchor_data_hash: couple_anchor_data_hash,
    collateral_inputs: couple_proposal_collateral_inputs_cbor,
    collateral_output: collateral_output_cbor,
    collateral_fee: collateral_fee_cbor,
  }

const couple_proposal_inputs =
  [input(zero_tx_id, 3), input(add_proposal_tx_id, 1)]

const couple_proposal_outputs =
  [
    Output {
      address: governance_address,
      value: node_value,
      datum: InlineDatum(
        Element {
          data: Node(
            GovernanceActionSubmitted {
              proposer: proposer_address,
              subject_script_hash: required_script_for_final_burn,
              gov_action_script_data_hash: couple_proposal_script_data_hash,
              spend_redeemer_index: couple_proposal_spend_redeemer_index,
              cost_model_prefix,
              acceptance_builtin_cost: 2,
              cost_model_postfix,
              spend_cpu: couple_proposal_spend_cpu,
              spend_mem: couple_proposal_spend_mem,
              valid_until: 1_787_092_009_000,
              required_script_for_final_burn,
            },
          ),
          link: None,
        },
      ),
      reference_script: None,
    },
    Output {
      address: proposer_address,
      value: assets.from_lovelace(498_999_394_307),
      datum: NoDatum,
      reference_script: None,
    },
  ]

const couple_proposal_procedures_cbor =
  #"d9010281841a3b9aca00581de09dd9b25ab2407d52ae028115abbda92c24ed18135edcfd007c5a85da8400f6a112a102"
    |> bytearray.concat(accepted_cost_model)
    |> bytearray.concat(
        #"f682782d68747470733a2f2f6578616d706c652e746573742f676f7665726e616e63652f636f73742d6d6f64656c2d343258200000000000000000000000000000000000000000000000000000000000000000",
      )

const mint_pass_tx_id =
  #"025630f44fba02cbc9ff5596697185f4978e3c3a6cd0a8b0e7475e9117e92496"

const mint_pass_script_data_hash =
  #"0800695b5142a8636f818c6596b377a17afb83a8511de71d26a1aa78b454da32"

const mint_pass_anchor_spend_redeemer_index = 1

const mint_pass_proposal_spend_redeemer_index = 2

const mint_pass_anchor_spend_cpu = 16_760_229

const mint_pass_anchor_spend_mem = 50_866

const mint_pass_proposal_spend_cpu = 19_092_712

const mint_pass_proposal_spend_mem = 54_028

const mint_pass_mint_cpu = 498_098_056

const mint_pass_mint_mem = 1_248_445

const mint_pass_ttl = 128_813_249

const mint_pass_collateral_inputs_cbor =
  #"d9010281825820000000000000000000000000000000000000000000000000000000000000000004"

const mint_pass_redeemer =
  MintPassedProposal {
    anchor_input_outref: OutputReference {
      transaction_id: add_proposal_tx_id,
      output_index: 0,
    },
    anchor_output_index: 0,
    passed_proposal_output_index: 1,
    ttl: mint_pass_ttl,
    collateral_inputs: mint_pass_collateral_inputs_cbor,
    collateral_output: collateral_output_cbor,
    collateral_fee: collateral_fee_cbor,
  }

const mint_pass_inputs =
  [
    input(zero_tx_id, 4),
    input(add_proposal_tx_id, 0),
    input(couple_proposal_tx_id, 0),
  ]

const mint_pass_outputs =
  [
    Output {
      address: governance_address,
      value: root_value,
      datum: InlineDatum(Element { data: Root(#""), link: None }),
      reference_script: None,
    },
    Output {
      address: governance_address,
      value: pass_value,
      datum: InlineDatum(
        PassedProposal {
          proposer: proposer_address,
          passed_proposal_script_data_hash: mint_pass_script_data_hash,
          anchor_spend_redeemer_index: mint_pass_anchor_spend_redeemer_index,
          proposal_spend_redeemer_index: mint_pass_proposal_spend_redeemer_index,
          anchor_spend_cpu: mint_pass_anchor_spend_cpu,
          anchor_spend_mem: mint_pass_anchor_spend_mem,
          node_spend_cpu: mint_pass_proposal_spend_cpu,
          node_spend_mem: mint_pass_proposal_spend_mem,
          mint_cpu: mint_pass_mint_cpu,
          mint_mem: mint_pass_mint_mem,
          required_script_for_final_burn,
        },
      ),
      reference_script: None,
    },
    Output {
      address: proposer_address,
      value: assets.from_lovelace(499_999_494_604),
      datum: NoDatum,
      reference_script: None,
    },
  ]

const mint_pass_mint =
  assets.from_asset(governance_policy, node_asset_name, -1)
    |> assets.merge(assets.from_asset(governance_policy, pass_asset_name, 1))

test success__validate_add_proposal_script_data_hash() {
  validate_add_proposal_script_data_hash(
    add_proposal_script_data_hash,
    initial_cost_model,
    add_proposal_spend_cpu,
    add_proposal_spend_mem,
    add_proposal_mint_cpu,
    add_proposal_mint_mem,
    add_proposal_spend_redeemer_index,
    add_proposal_redeemer,
  )
}

test success__validate_add_proposal_tx_id_from_script_data_hash() {
  validate_add_proposal_tx_id_from_script_data_hash(
    add_proposal_tx_id,
    add_proposal_script_data_hash,
    add_proposal_inputs,
    governance_reference_inputs,
    add_proposal_outputs,
    network_tag,
    573_673,
    add_proposal_invalid_before,
    add_proposal_ttl,
    add_proposal_mint,
    [proposer_payment_hash],
    add_proposal_collateral_inputs_cbor,
    collateral_output_cbor,
    collateral_fee_cbor,
  )
}

test success__validate_spend_only_script_data_hash() {
  validate_spend_only_script_data_hash(
    couple_proposal_script_data_hash,
    initial_cost_model,
    couple_proposal_spend_cpu,
    couple_proposal_spend_mem,
    couple_proposal_spend_redeemer_index,
    couple_proposal_redeemer,
  )
}

test success__validate_tx_id_from_script_data_hash_with_proposal_procedures() {
  validate_tx_id_from_script_data_hash_with_proposal_procedures(
    couple_proposal_tx_id,
    couple_proposal_script_data_hash,
    couple_proposal_inputs,
    governance_reference_inputs,
    couple_proposal_outputs,
    network_tag,
    605_693,
    couple_proposal_ttl,
    couple_proposal_procedures_cbor,
    [proposer_payment_hash],
    couple_proposal_collateral_inputs_cbor,
    collateral_output_cbor,
    collateral_fee_cbor,
  )
}

test success__validate_pass_script_data_hash() {
  validate_pass_script_data_hash(
    mint_pass_script_data_hash,
    accepted_cost_model,
    mint_pass_anchor_spend_cpu,
    mint_pass_anchor_spend_mem,
    mint_pass_proposal_spend_cpu,
    mint_pass_proposal_spend_mem,
    mint_pass_mint_cpu,
    mint_pass_mint_mem,
    mint_pass_anchor_spend_redeemer_index,
    mint_pass_proposal_spend_redeemer_index,
    mint_pass_redeemer,
  )
}

test success__validate_tx_id_from_script_data_hash_with_mint() {
  validate_tx_id_from_script_data_hash_with_mint(
    mint_pass_tx_id,
    mint_pass_script_data_hash,
    mint_pass_inputs,
    governance_reference_inputs,
    mint_pass_outputs,
    network_tag,
    505_396,
    mint_pass_ttl,
    mint_pass_mint,
    [proposer_payment_hash],
    mint_pass_collateral_inputs_cbor,
    collateral_output_cbor,
    collateral_fee_cbor,
  )
}
