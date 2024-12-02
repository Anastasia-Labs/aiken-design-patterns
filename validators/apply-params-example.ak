use aiken/cbor
use aiken/collection/list
use aiken/crypto.{Hash, Sha2_256, blake2b_224, sha2_256}
use aiken/primitive/bytearray
use aiken_design_patterns/apply_params.{
  ParameterizedRedeemer, ParameterizedRedeemer3, apply_param,
}
use cardano/address.{Address, Script}
use cardano/assets.{PolicyId}
use cardano/transaction.{Output, OutputReference, Transaction}

// Sample prefix and postfix values obtained from `spending_example`
const destination_script_prefix: ByteArray =
  #"59014059013d010100332323232323223225980099191919192cc004cdc3a400460146ea80062646464a6646601a6002601c6ea80184c8c8c8c966002602c005159800980298091baa0038991919192cc004c06800a2646464b30013371e6e50dd980100b4566002601860326ea803626466e3cdc90009bae301d301b375401c646466e28004dd99ba8003337140026ecc00cdd98014590184590181bad301b301c002301a0013017375401d1640606eb4c060004c060008dd7180b00098099baa0038b20228b2028375a602800260280046024002601e6ea8018dc3a40002c601e6020004601c00260166ea80062c8048c030c034008c02c004c02c008c024004c018dd5000c52689b2b2008375c002ae6955ceaab9e5573eae855d1261225820"

const destination_script_postfix: ByteArray = #"0001"

validator mint_example {
  mint(redeemer: OutputReference, _own_policy: PolicyId, tx: Transaction) {
    let Transaction { mint, outputs, .. } = tx
    let target_script_cbor =
      apply_param(
        prefix: destination_script_prefix,
        param: cbor.serialise(redeemer),
        postfix: destination_script_postfix,
      )
    expect [
      Output {
        address: Address {
          payment_credential: Script(destination_script_hash),
          ..
        },
        value: produced_value,
        ..
      },
    ] = outputs
    and {
      assets.without_lovelace(produced_value) == mint,
      destination_script_hash == blake2b_224(target_script_cbor),
      list.length(assets.flatten(mint)) == 1,
    }
  }

  else(_) {
    fail
  }
}

validator spending_example(parameter: Hash<Sha2_256, OutputReference>) {
  spend(
    datum: Option<Hash<Sha2_256, Int>>,
    redeemer: ParameterizedRedeemer<OutputReference, Int>,
    own_out_ref: OutputReference,
    tx: Transaction,
  ) {
    apply_params.spend_wrapper_validator(
      hashed_parameter: parameter,
      parameter_serialiser: fn(p: OutputReference) { cbor.serialise(p) },
      validator_function: fn(
        nonce: OutputReference,
        m_secret: Option<Hash<Sha2_256, Int>>,
        answer: Int,
        _own_out_ref: OutputReference,
        _tx: Transaction,
      ) -> Bool {
        expect Some(hashed_secret) = m_secret
        let raw_secret =
          cbor.serialise(nonce)
            |> bytearray.concat(cbor.serialise(nonce))
            |> bytearray.concat(cbor.serialise(answer))
        sha2_256(raw_secret) == hashed_secret
      },
      datum: datum,
      outer_redeemer: redeemer,
      output_reference: own_out_ref,
      tx: tx,
    )
  }

  else(_) {
    fail
  }
}

validator spending_example_3(
  param_0: Hash<Sha2_256, OutputReference>,
  param_1: Hash<Sha2_256, OutputReference>,
  param_2: Hash<Sha2_256, OutputReference>,
) {
  spend(
    datum: Option<Hash<Sha2_256, Int>>,
    redeemer: ParameterizedRedeemer3<
      OutputReference,
      OutputReference,
      OutputReference,
      Int,
    >,
    own_out_ref: OutputReference,
    tx: Transaction,
  ) {
    apply_params.spend_wrapper_validator_3(
      hashed_parameter_0: param_0,
      hashed_parameter_1: param_1,
      hashed_parameter_2: param_2,
      parameter_serialiser_0: fn(p: OutputReference) { cbor.serialise(p) },
      parameter_serialiser_1: fn(q: OutputReference) { cbor.serialise(q) },
      parameter_serialiser_2: fn(s: OutputReference) { cbor.serialise(s) },
      validator_function: fn(
        nonce_0: OutputReference,
        nonce_1: OutputReference,
        nonce_2: OutputReference,
        m_secret: Option<Hash<Sha2_256, Int>>,
        answer: Int,
        _own_out_ref: OutputReference,
        _tx: Transaction,
      ) -> Bool {
        expect Some(hashed_secret) = m_secret
        let raw_secret =
          cbor.serialise(nonce_0)
            |> bytearray.concat(cbor.serialise(nonce_0))
            |> bytearray.concat(cbor.serialise(nonce_1))
            |> bytearray.concat(cbor.serialise(nonce_1))
            |> bytearray.concat(cbor.serialise(nonce_2))
            |> bytearray.concat(cbor.serialise(nonce_2))
            |> bytearray.concat(cbor.serialise(answer))
        sha2_256(raw_secret) == hashed_secret
      },
      datum: datum,
      outer_redeemer: redeemer,
      output_reference: own_out_ref,
      tx: tx,
    )
  }

  else(_) {
    fail
  }
}
