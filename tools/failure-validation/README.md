# Failure validation

Run the validators in `validators/failure-validation.ak` through a
complete reference-script and collateral-return scenario. Lucid Evolution 0.6.2
builds and signs the transactions; Scalus 1.3.0 validates and applies them to its
in-memory ledger through a local Lucid provider.

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

1. Publish three reference-script UTxOs at a dedicated wallet address and prepare
   two separate 100 ADA collateral UTxOs. The spending validator is parameterized
   with the withdrawal validator's hash before deployment. The `failure_proof`
   mint policy is parameterized with both applied script hashes.
2. Register the withdrawal script's stake credential using its reference script
   and `publish` handler, and lock 20 ADA with an inline unit datum at the spending
   script address.
3. Build a spend with precisely one zero withdrawal and two redeemers, `Spend`
   and `Withdraw`. Reference the deployed spending and withdrawal scripts. The
   spending validator succeeds; the withdrawal validator deliberately fails.
   Submit it with `isValid=false`: the collateral input is consumed, its return
   goes to the transaction wallet, and the ordinary inputs stay unspent. The
   ordinary outputs are not created.
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
resource. An evaluator hook runs each script with Scalus within its allocation
and supplies the prescribed values to Lucid's fee/change balancing loop. The
tool rechecks the final transaction's exact declared budgets and reports actual
consumption separately. It also checks that the emulator's protocol maxima match
these totals. Ledger validation remains enabled for every submission. Budget
exhaustion and other unexpected failures stop the run.

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
explicitly spends this output in the mint transaction and verifies that all three
reference scripts and the original spending-script UTxO remain unspent.

The `failure_proof` mint policy calls `failure_validation.validate_mint` to
authenticate the failed transaction, script identities, redeemers, and declared
budgets. The witness comes from the final transaction body and witnesses,
including the Plutus V3 cost model and redeemer encoding. The original spending
UTxO remains available as a reference input, proving the producing transaction
failed. The policy requires exactly one NFT named with that transaction's hash;
consuming its collateral return prevents reuse of the evidence. Its continuation
accepts the authenticated withdrawal redeemer because the example withdrawal
validator ignores that data and always fails.

## Results and checks

Successful runs print a report and write the following under the repository's
ignored `artifacts/failure-validation/` directory:

- `plutus.json`: the fresh blueprint.
- `01-deployment.cbor`, `02-registration-and-funding.cbor`,
  `03-failed-spend.cbor`, `04-mint.cbor`: signed transaction CBOR as hex text.
- `report.json`: addresses, script hashes, reference UTxOs, transaction hashes,
  validation results with each script's `declared` and `consumed` execution
  budgets (`memory` and `steps`), the failed
  transaction's fee, collateral percentage, minimum charge, returned amount, and
  the NFT unit. Integer quantities are decimal strings.

The command exits nonzero on an unexpected script result, ledger rejection, or
failed assertion. These commands check TypeScript, exercise provider conversions
and credential queries, and run the complete scenario:

```sh
pnpm typecheck
pnpm test
```

Scalus documents its [collateral handling](https://scalus.org/docs/testing/emulator)
and [Lucid provider integration](https://scalus.org/docs/testing/js-emulator).
