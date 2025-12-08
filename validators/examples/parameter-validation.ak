//// @hidden

use aiken/cbor
use aiken/collection/list
use aiken/crypto.{Blake2b_224, Hash, blake2b_224}
use aiken/primitive/bytearray
use aiken_design_patterns/parameter_validation.{
  Parameter, Parameter3, ParameterizedRedeemer, ParameterizedRedeemer2,
  ParameterizedRedeemer3, apply_param,
}
use cardano/address.{Address, Script}
use cardano/assets.{PolicyId}
use cardano/transaction.{Output, OutputReference, Transaction}

// Sample prefix and postfix values obtained from `parameterized_spend`
const destination_script_prefix: ByteArray =
  #"59012f0101003229800aba2aba1aab9faab9eaab9dab9a9bae002488888896600264653001300800198041804800cc0200092225980099b8748008c020dd500144ca60026018003300c300d0019b874800122259800980098061baa00789919192cc004c04c00a264b300130053010375400313232332259800980c001c4c8c96600266e3cde41bb30010148acc004c02cc058dd500644cdc79bc83371466e28dd98009bb30013766603260340046eb8c064c05cdd5006459015459015180c000980a9baa00f8b202c375a602a0026eb8c054008c054004c044dd5000c5900f1809001c590111bad30110013011001300d375400f16402c3009375400516401c300800130043754011149a26cac80109811e581c"

validator dependent_mint {
  mint(redeemer: OutputReference, _own_policy: PolicyId, tx: Transaction) {
    let Transaction { mint, outputs, .. } = tx
    let target_script_hash =
      apply_param(
        version: 3,
        prefix: destination_script_prefix,
        param: cbor.serialise(redeemer),
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
      destination_script_hash == target_script_hash,
      list.length(assets.flatten(mint)) == 1,
    }
  }

  else(_) {
    fail
  }
}

validator parameterized_spend(
  hashed_parameter: Hash<Blake2b_224, OutputReference>,
) {
  spend(
    m_secret: Option<Hash<Blake2b_224, Int>>,
    outer_redeemer: ParameterizedRedeemer<OutputReference, Int>,
    _own_out_ref: OutputReference,
    _tx: Transaction,
  ) {
    let
      parameter,
      redeemer,
    <-
      parameter_validation.wrapper(
        hashed_parameter,
        fn(p: OutputReference) { cbor.serialise(p) },
        outer_redeemer,
      )
    expect Some(hashed_secret) = m_secret
    let nonce = parameter
    let answer = redeemer
    let raw_secret =
      cbor.serialise(nonce)
        |> bytearray.concat(cbor.serialise(nonce))
        |> bytearray.concat(cbor.serialise(answer))
    blake2b_224(raw_secret) == hashed_secret
  }

  else(_) {
    fail
  }
}

validator parameterized_spend_2(
  hashed_parameter_0: Hash<Blake2b_224, OutputReference>,
  hashed_parameter_1: Hash<Blake2b_224, OutputReference>,
) {
  spend(
    m_secret: Option<Hash<Blake2b_224, Int>>,
    outer_redeemer: ParameterizedRedeemer2<
      OutputReference,
      OutputReference,
      Int,
    >,
    _own_out_ref: OutputReference,
    _tx: Transaction,
  ) {
    let
      param_0,
      param_1,
      redeemer,
    <-
      parameter_validation.wrapper_2(
        hashed_parameter_0,
        hashed_parameter_1,
        fn(p: OutputReference) { cbor.serialise(p) },
        fn(q: OutputReference) { cbor.serialise(q) },
        outer_redeemer,
      )
    expect Some(hashed_secret) = m_secret
    let nonce_0 = param_0
    let nonce_1 = param_1
    let answer = redeemer
    let raw_secret =
      cbor.serialise(nonce_0)
        |> bytearray.concat(cbor.serialise(nonce_0))
        |> bytearray.concat(cbor.serialise(nonce_0))
        |> bytearray.concat(cbor.serialise(nonce_1))
        |> bytearray.concat(cbor.serialise(nonce_1))
        |> bytearray.concat(cbor.serialise(answer))
    blake2b_224(raw_secret) == hashed_secret
  }

  else(_) {
    fail
  }
}

validator parameterized_spend_3(
  hashed_parameter_0: Hash<Blake2b_224, OutputReference>,
  hashed_parameter_1: Hash<Blake2b_224, OutputReference>,
  hashed_parameter_2: Hash<Blake2b_224, OutputReference>,
) {
  spend(
    m_secret: Option<Hash<Blake2b_224, Int>>,
    outer_redeemer: ParameterizedRedeemer3<
      OutputReference,
      OutputReference,
      OutputReference,
      Int,
    >,
    _own_out_ref: OutputReference,
    _tx: Transaction,
  ) {
    let
      param_0,
      param_1,
      param_2,
      redeemer,
    <-
      parameter_validation.wrapper_3(
        hashed_parameter_0,
        hashed_parameter_1,
        hashed_parameter_2,
        fn(p: OutputReference) { cbor.serialise(p) },
        fn(q: OutputReference) { cbor.serialise(q) },
        fn(s: OutputReference) { cbor.serialise(s) },
        outer_redeemer,
      )
    expect Some(hashed_secret) = m_secret
    let nonce_0 = param_0
    let nonce_1 = param_1
    let nonce_2 = param_2
    let answer = redeemer
    let raw_secret =
      cbor.serialise(nonce_0)
        |> bytearray.concat(cbor.serialise(nonce_0))
        |> bytearray.concat(cbor.serialise(nonce_1))
        |> bytearray.concat(cbor.serialise(nonce_1))
        |> bytearray.concat(cbor.serialise(nonce_2))
        |> bytearray.concat(cbor.serialise(nonce_2))
        |> bytearray.concat(cbor.serialise(answer))
    blake2b_224(raw_secret) == hashed_secret
  }

  else(_) {
    fail
  }
}

validator parameterized_mint(
  hashed_parameter: Hash<Blake2b_224, OutputReference>,
) {
  mint(
    outer_redeemer: Parameter<OutputReference>,
    own_policy: PolicyId,
    tx: Transaction,
  ) {
    let param <-
      parameter_validation.wrapper_no_redeemer(
        hashed_parameter,
        fn(p: OutputReference) { cbor.serialise(p) },
        outer_redeemer,
      )
    let nonce = param
    let token_name = cbor.serialise(nonce) |> blake2b_224
    assets.flatten(tx.mint) == [(own_policy, token_name, 1)]
  }

  else(_) {
    fail
  }
}

validator parameterized_mint_3(
  hashed_parameter_0: Hash<Blake2b_224, OutputReference>,
  hashed_parameter_1: Hash<Blake2b_224, OutputReference>,
  hashed_parameter_2: Hash<Blake2b_224, OutputReference>,
) {
  mint(
    outer_redeemer: Parameter3<
      OutputReference,
      OutputReference,
      OutputReference,
    >,
    own_policy: PolicyId,
    tx: Transaction,
  ) {
    let
      param_0,
      param_1,
      param_2,
    <-
      parameter_validation.wrapper_no_redeemer_3(
        hashed_parameter_0,
        hashed_parameter_1,
        hashed_parameter_2,
        fn(p: OutputReference) { cbor.serialise(p) },
        fn(q: OutputReference) { cbor.serialise(q) },
        fn(s: OutputReference) { cbor.serialise(s) },
        outer_redeemer,
      )
    let nonce_0 = param_0
    let nonce_1 = param_1
    let nonce_2 = param_2
    let token_name =
      cbor.serialise(nonce_0)
        |> bytearray.concat(cbor.serialise(nonce_0))
        |> bytearray.concat(cbor.serialise(nonce_1))
        |> bytearray.concat(cbor.serialise(nonce_2))
        |> blake2b_224
    assets.flatten(tx.mint) == [(own_policy, token_name, 1)]
  }

  else(_) {
    fail
  }
}
