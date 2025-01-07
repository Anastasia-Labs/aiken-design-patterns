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
  #"590129010100332323232323223225333004323232323253330093370e900118051baa001132332253323300d3001300e375400c264646464a666028602c0042a666022600a60246ea800c4c8c8c8c94ccc060c0680084c8c8c94ccc060cdc79b92376600402c2a666030601860326ea80344cdc79b923371466e28dd98011bb300237666ea0004dd7180e180d1baa00d1616375a603660380046034002602e6ea803858dd6980c000980c0011bae3016001301337540062c2c6eb4c050004c050008c048004c03cdd50031b874800058c038004c038c03c004c02cdd50008b1806180680198058011805001180500098031baa00114984d958dd7000ab9a5573aaae7955cfaba157449811e581c"

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

validator parameterized_spend(parameter: Hash<Blake2b_224, OutputReference>) {
  spend(
    datum: Option<Hash<Blake2b_224, Int>>,
    redeemer: ParameterizedRedeemer<OutputReference, Int>,
    own_out_ref: OutputReference,
    tx: Transaction,
  ) {
    parameter_validation.spend_wrapper(
      hashed_parameter: parameter,
      parameter_serialiser: fn(p: OutputReference) { cbor.serialise(p) },
      validator_function: fn(
        nonce: OutputReference,
        m_secret: Option<Hash<Blake2b_224, Int>>,
        answer: Int,
        _own_out_ref: OutputReference,
        _tx: Transaction,
      ) -> Bool {
        expect Some(hashed_secret) = m_secret
        let raw_secret =
          cbor.serialise(nonce)
            |> bytearray.concat(cbor.serialise(nonce))
            |> bytearray.concat(cbor.serialise(answer))
        blake2b_224(raw_secret) == hashed_secret
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

validator parameterized_spend_2(
  param_0: Hash<Blake2b_224, OutputReference>,
  param_1: Hash<Blake2b_224, OutputReference>,
) {
  spend(
    datum: Option<Hash<Blake2b_224, Int>>,
    redeemer: ParameterizedRedeemer2<OutputReference, OutputReference, Int>,
    own_out_ref: OutputReference,
    tx: Transaction,
  ) {
    parameter_validation.spend_wrapper_2(
      hashed_parameter_0: param_0,
      hashed_parameter_1: param_1,
      parameter_serialiser_0: fn(p: OutputReference) { cbor.serialise(p) },
      parameter_serialiser_1: fn(q: OutputReference) { cbor.serialise(q) },
      validator_function: fn(
        nonce_0: OutputReference,
        nonce_1: OutputReference,
        m_secret: Option<Hash<Blake2b_224, Int>>,
        answer: Int,
        _own_out_ref: OutputReference,
        _tx: Transaction,
      ) -> Bool {
        expect Some(hashed_secret) = m_secret
        let raw_secret =
          cbor.serialise(nonce_0)
            |> bytearray.concat(cbor.serialise(nonce_0))
            |> bytearray.concat(cbor.serialise(nonce_0))
            |> bytearray.concat(cbor.serialise(nonce_1))
            |> bytearray.concat(cbor.serialise(nonce_1))
            |> bytearray.concat(cbor.serialise(answer))
        blake2b_224(raw_secret) == hashed_secret
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

validator parameterized_spend_3(
  param_0: Hash<Blake2b_224, OutputReference>,
  param_1: Hash<Blake2b_224, OutputReference>,
  param_2: Hash<Blake2b_224, OutputReference>,
) {
  spend(
    datum: Option<Hash<Blake2b_224, Int>>,
    redeemer: ParameterizedRedeemer3<
      OutputReference,
      OutputReference,
      OutputReference,
      Int,
    >,
    own_out_ref: OutputReference,
    tx: Transaction,
  ) {
    parameter_validation.spend_wrapper_3(
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
        m_secret: Option<Hash<Blake2b_224, Int>>,
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
        blake2b_224(raw_secret) == hashed_secret
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

validator parameterized_mint(param: Hash<Blake2b_224, OutputReference>) {
  mint(
    redeemer: Parameter<OutputReference>,
    own_policy: PolicyId,
    tx: Transaction,
  ) {
    parameter_validation.no_datum_wrapper_no_redeemer(
      hashed_parameter: param,
      parameter_serialiser: fn(p: OutputReference) { cbor.serialise(p) },
      validator_function: fn(
        nonce: OutputReference,
        policy: PolicyId,
        tx: Transaction,
      ) -> Bool {
        let token_name = cbor.serialise(nonce) |> blake2b_224
        assets.flatten(tx.mint) == [(policy, token_name, 1)]
      },
      outer_redeemer: redeemer,
      variable_arg: own_policy,
      tx: tx,
    )
  }

  else(_) {
    fail
  }
}

validator parameterized_mint_3(
  param_0: Hash<Blake2b_224, OutputReference>,
  param_1: Hash<Blake2b_224, OutputReference>,
  param_2: Hash<Blake2b_224, OutputReference>,
) {
  mint(
    redeemer: Parameter3<OutputReference, OutputReference, OutputReference>,
    own_policy: PolicyId,
    tx: Transaction,
  ) {
    parameter_validation.no_datum_wrapper_no_redeemer_3(
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
        policy: PolicyId,
        tx: Transaction,
      ) -> Bool {
        let token_name =
          cbor.serialise(nonce_0)
            |> bytearray.concat(cbor.serialise(nonce_0))
            |> bytearray.concat(cbor.serialise(nonce_1))
            |> bytearray.concat(cbor.serialise(nonce_2))
            |> blake2b_224
        assets.flatten(tx.mint) == [(policy, token_name, 1)]
      },
      outer_redeemer: redeemer,
      variable_arg: own_policy,
      tx: tx,
    )
  }

  else(_) {
    fail
  }
}

validator prehashed_param_mint_3(
  param_0: Hash<Blake2b_224, OutputReference>,
  param_1: Hash<Blake2b_224, OutputReference>,
  param_2: Hash<Blake2b_224, OutputReference>,
) {
  mint(redeemer: Data, own_policy: PolicyId, tx: Transaction) {
    parameter_validation.prehashed_param_no_datum_wrapper_3(
      validator_function: fn(
        nonce_0: Hash<Blake2b_224, OutputReference>,
        nonce_1: Hash<Blake2b_224, OutputReference>,
        nonce_2: Hash<Blake2b_224, OutputReference>,
        _redeemer: Data,
        policy: PolicyId,
        tx: Transaction,
      ) -> Bool {
        let token_name =
          cbor.serialise(nonce_0)
            |> bytearray.concat(cbor.serialise(nonce_1))
            |> bytearray.concat(cbor.serialise(nonce_2))
            |> blake2b_224
        assets.flatten(tx.mint) == [(policy, token_name, 1)]
      },
      parameter_0: param_0,
      parameter_1: param_1,
      parameter_2: param_2,
      redeemer: redeemer,
      variable_arg: own_policy,
      tx: tx,
    )
  }

  else(_) {
    fail
  }
}
