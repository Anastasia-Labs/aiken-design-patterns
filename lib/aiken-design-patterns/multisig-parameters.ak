//// # Multisig-controlled parameters
////
//// Store application parameters in the inline datum of a singleton NFT UTxO.
//// A bootstrap nonce permits its one-time mint. A quorum of distinct authorized
//// signers approves the mint and each update. The application chooses the NFT
//// asset name and validates each produced datum through a callback.
////
//// Use `validate_mint` and `validate_spend` in the same concrete validator, so
//// its applied hash is both the NFT policy ID and the spending-script hash.
//// Fix the nonce, signer list, threshold, and asset name for that deployment.
//// Every mint and spend must pass through the corresponding helper; reject
//// unsupported purposes and do not add branches that bypass these checks.
//// Pass the handler's actual transaction and own policy ID or output reference.
////
//// Bootstrap consumes the nonce. Updates authenticate the consumed NFT.
//// Both count configured keys listed in the transaction's required signers
//// (`Transaction.extra_signatories` in Plutus). A nonce owner who is also
//// an authorized signer counts when their key is declared there.
//// Produced outputs contain only ADA and the NFT, have an inline datum, and
//// carry no reference script. Updates may change ADA and staking credentials.
////
//// The final callback receives the authenticated output datum as raw `Data`.
//// Decode it and enforce application-specific requirements using backpassing.
//// Returning `False` or failing rejects the transaction. The callback runs once
//// after the shared checks; the helpers impose no datum schema or value bounds.

use aiken/collection/list
use aiken/crypto.{VerificationKeyHash}
use cardano/address.{Address, Script}
use cardano/assets.{AssetName, PolicyId}
use cardano/transaction.{
  InlineDatum, Input, Output, OutputReference, Transaction,
}

/// Bootstrap the parameters UTxO with exactly one NFT and no other minting.
/// The nonce must be consumed, the authorized signers must be unique, and the
/// transaction must declare at least `threshold` of those signers. The
/// threshold must be positive. `output_index` selects the actual transaction
/// output whose inline datum is passed to `validate_datum` after these checks.
pub fn validate_mint(
  bootstrap_nonce: OutputReference,
  authorized_signers: List<VerificationKeyHash>,
  threshold: Int,
  asset_name: AssetName,
  output_index: Int,
  own_policy: PolicyId,
  tx: Transaction,
  validate_datum: fn(Data) -> Bool,
) -> Bool {
  let Transaction { inputs, outputs, mint, extra_signatories, .. } = tx

  expect
    inputs
      |> list.any(fn(input) { input.output_reference == bootstrap_nonce })
  expect mint == assets.from_asset(own_policy, asset_name, 1)
  expect has_quorum(authorized_signers, threshold, extra_signatories)

  let datum <- validate_output(
    outputs |> list.expect_at(output_index),
    own_policy,
    asset_name,
  )

  validate_datum(datum)
}

/// Update the authenticated parameters UTxO with threshold authorization.
/// `own_outref` selects the consumed input by its full output reference, and
/// `continuation_output_index` selects the actual continuing output. Both must
/// carry exactly the configured NFT apart from ADA and share the script payment
/// credential. The callback validates the continuing inline datum. Additional
/// signatories and unrelated-policy minting are allowed; ADA and the staking
/// credential need not be preserved.
pub fn validate_spend(
  authorized_signers: List<VerificationKeyHash>,
  threshold: Int,
  asset_name: AssetName,
  continuation_output_index: Int,
  own_outref: OutputReference,
  tx: Transaction,
  validate_datum: fn(Data) -> Bool,
) -> Bool {
  let Transaction { inputs, outputs, extra_signatories, .. } = tx

  expect  
      Input {
        output: Output {
          address: Address { payment_credential: Script(own_policy), .. },
          value: input_value,
          ..
        },
        ..
      }
    = inputs
    |> list.expect_find(fn(input) { input.output_reference == own_outref })

  expect input_value |> assets.has_nft_strict(own_policy, asset_name)
  expect has_quorum(authorized_signers, threshold, extra_signatories)

  let datum <- validate_output(
    outputs |> list.expect_at(continuation_output_index),
    own_policy,
    asset_name,
  )

  validate_datum(datum)
}

fn has_quorum(
  authorized_signers: List<VerificationKeyHash>,
  threshold: Int,
  extra_signatories: List<VerificationKeyHash>,
) -> Bool {
  and {
    threshold > 0,
    authorized_signers == list.unique(authorized_signers),
    list.foldl(
      authorized_signers,
      0,
      fn(signer, count) {
        if list.has(extra_signatories, signer) {
          count + 1
        } else {
          count
        }
      },
    ) >= threshold,
  }
}

fn validate_output(
  output: Output,
  own_policy: PolicyId,
  asset_name: AssetName,
  validate_datum: fn(Data) -> Bool,
) -> Bool {
  expect  
      Output {
        address: Address { payment_credential: Script(output_policy), .. },
        value,
        datum: InlineDatum(datum),
        reference_script: None,
      }
    = output

  expect output_policy == own_policy
  expect value |> assets.has_nft_strict(own_policy, asset_name)

  validate_datum(datum)
}
