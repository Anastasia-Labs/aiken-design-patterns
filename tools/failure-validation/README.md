# Failure validation

Run the validators in `validators/failure-validation.ak` through a complete
Ed25519 failure-validation scenario. Arguments committed in a script UTxO's
inline datum cause signature verification to return `False`. A later transaction
consumes the resulting collateral return and references that still-unspent UTxO
to mint proof of the failed invocation. Lucid Evolution 0.6.2 builds and signs
the transactions; Scalus 1.3.0 validates and applies them to its in-memory ledger
through a local Lucid provider.

## Run

Requires Node.js 22.16 or newer, pnpm 9.15.4, and Aiken. From this directory:

```sh
pnpm install --frozen-lockfile
pnpm scenario
```

Every run builds a fresh Plutus V3 blueprint with `--env testnet`, which sets the
network tag used by the proof policy to zero. The default compiler is
`/home/km/code/aiken/target/debug/aiken`; set `AIKEN` to another executable path
when needed. Compiler failures stop the run. When stdout is not a terminal, the
launcher uses the util-linux `script` command to give Aiken a TTY and preserve its
diagnostics.

The scenario starts a fresh emulator at a fixed slot with deterministic test
keys and 1,000 ADA in its transaction wallet. All balances exist only in memory.
It uses Scalus's bundled Preview protocol parameters and slot configuration;
running the scenario requires no network service or credentials.

## Transactions

1. Publish two reference-script UTxOs at a dedicated wallet address: the shared
   `delegated_spend` validator and the `failure_proof` mint policy. The spending,
   withdrawal, and registration handlers share one script hash. The mint policy
   takes that hash as its sole parameter. Prepare two separate 100 ADA collateral
   UTxOs.
2. Register the shared script's stake credential using its reference script and
   `publish` handler. Lock 20 ADA at its spending address with the inline Data
   list `[public_key, message, signature]`, and create a separate 10 ADA wallet
   UTxO. The public key and signature are from RFC 8032 section 7.1, test 1, which
   signs an empty message; this demo uses message `01` to make verification return
   `False`. All three arguments are byte strings, so argument preparation succeeds.
3. Spend exactly those two ordinary inputs, reference the shared validator once,
   and include precisely one zero withdrawal. The only redeemers are `Spend`
   and `Withdraw`. Ledger input order determines the spending pointer and its
   Boolean redeemer: `True` selects input 0, `False` selects input 1. The withdrawal
   uses `Void` at index 0. Spending succeeds; withdrawal applies
   `verify_ed25519_signature` to the inline arguments and fails. Submit it with
   `isValid=false`: the collateral input is consumed, its return goes to the
   transaction wallet, and both ordinary inputs stay unspent. The ordinary outputs
   are not created.
4. Explicitly consume the collateral-return UTxO and reference both the deployed
   mint policy and the original spending UTxO. Supply the finalized failed
   transaction's witness and the indices selecting those inputs to mint one NFT
   to the transaction wallet. Its asset name is the failed transaction's raw
   32-byte hash, represented as 64 hex characters. A separate UTxO supplies
   collateral for this successful mint.

The failed transaction uses these prescribed execution budgets, matching the
values authenticated by the mint policy:

| Allocation | Memory | CPU |
|---|---:|---:|
| Spending | 50,000 | 14,000,000 |
| Withdrawal | 17,450,000 | 9,986,000,000 |
| Transaction maximum | 17,500,000 | 10,000,000,000 |

The withdrawal receives the maximum minus the spending allocation for each
resource. An evaluator hook runs each endpoint with Scalus within its allocation
and supplies the prescribed values to Lucid's fee/change balancing loop. The
tool rechecks the final transaction's exact declared budgets and reports actual
consumption separately. It also checks that the emulator's protocol maxima match
these totals. Spending success is checked under the bundled Preview cost model;
this measurement does not establish a sufficient allowance under other protocol
parameters. Ledger validation remains enabled for every submission. This demo
expects verification to return `False`; budget exhaustion and other unexpected
failures stop the run.

Lucid's signer sets `isValid=true`, so the tool sets the flag to false after
signing and checks that the body, witnesses, and transaction hash are unchanged.
A phase-2 failure marked `isValid=true` is rejected without a ledger update;
the correctly marked `isValid=false` transaction is accepted and applies the
collateral state change. The tool checks both outcomes.

Each script transaction sets its total collateral to
`ceil(finalFee * collateralPercentage / 100)` lovelace, using the emulator's
protocol parameters and integer arithmetic. The tool rebuilds before signing
until the fee and collateral agree, since adding collateral fields changes the
fee. The bundled Preview parameters require 150% of the final fee.

The return collateral is at `failedTransactionHash#ordinaryOutputCount`. Its
amount is the 100 ADA collateral input minus this exact minimum charge. The tool
explicitly spends this output in the mint transaction and verifies that both
reference scripts and both original ordinary inputs remain unspent.

The `failure_proof` mint policy calls `failure_validation.validate_mint` to
authenticate the failed transaction, shared script identity, redeemers, and
declared budgets. The proof witness contains the ordinary outputs, fee, other
ordinary input's reference, collateral input's reference, total collateral,
reference-input list, redeemer encoding, and Plutus V3 cost model. Its transaction
fields come from the finalized producing transaction; its cost model comes from
the emulator parameters used to build and evaluate that transaction.

The original script UTxO remains available as a reference input, proving the
producing transaction failed. The policy requires exactly one NFT named with
that transaction's hash; consuming its collateral return prevents reuse of the
evidence. The policy's continuation receives the authenticated inline datum and
checks that it contains exactly three byte strings. It checks argument
preparation without executing the builtin. Malformed argument structure cannot
produce an accepted proof. Byte-string length errors belong to the builtin
itself and qualify as failure evidence, as do builtin `False` results and
exhaustion of the prescribed withdrawal allowance.

## Results and checks

Successful runs print a report and write the following under the repository's
ignored `artifacts/failure-validation/` directory:

- `plutus.json`: the fresh blueprint.
- `01-deployment.cbor`, `02-registration-and-funding.cbor`,
  `03-failed-spend.cbor`, `04-mint.cbor`: signed transaction CBOR as hex text.
- `report.json`: the builtin name, arguments and inline datum; both ordinary
  input references, spending index and Boolean redeemer; the shared script hash,
  spending and reward addresses, reference UTxOs, and transaction hashes;
  validation results with each endpoint's `declared` and `consumed` execution
  budgets (`memory` and `steps`); the failed
  transaction's fee, collateral percentage, minimum charge, returned amount, and
  the NFT unit. Integer quantities are decimal strings.

The command exits nonzero on an unexpected script result, ledger rejection, or
failed assertion. These local checks compile one blueprint for the test run,
exercise provider conversions and credential queries, and verify:

- The complete failure-to-proof flow with the script input at either ledger index.
- Successful verification of the original empty-message signature: both ordinary
  inputs are consumed, collateral remains unspent, and no collateral return exists.
- Withdrawal failure for a non-list datum, missing argument, or wrong argument
  type, followed by rejection of the proof mint during script evaluation.
- Rejection of a proof witness naming an incorrect other ordinary input.
- Prescribed execution budgets, exact minimum collateral, reference-script
  preservation, and the proof NFT's name and quantity.

```sh
pnpm typecheck
pnpm test
```

Scalus documents its [collateral handling](https://scalus.org/docs/testing/emulator)
and [Lucid provider integration](https://scalus.org/docs/testing/js-emulator).
