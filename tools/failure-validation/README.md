# Failure validation

Run the validators in `validators/examples/failure-validation.ak` through a
complete reference-script and collateral-return scenario. Lucid Evolution 0.6.2
builds and signs the transactions; Scalus 1.3.0 validates and applies them to its
in-memory ledger through a local Lucid provider.

## Run

Requires Node.js 22.16 or newer, pnpm 9.15.4, and Aiken. From this directory:

```sh
pnpm install --frozen-lockfile
pnpm scenario
```

Every run builds a fresh Plutus V3 blueprint. The default compiler is
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
   with the withdrawal validator's hash before deployment.
2. Register the withdrawal script's stake credential using its reference script
   and `publish` handler, and lock 20 ADA with an inline unit datum at the spending
   script address.
3. Build a spend with precisely one zero withdrawal and two redeemers, `Spend`
   and `Withdraw`. Reference the deployed spending and withdrawal scripts. The
   spending validator succeeds; the withdrawal validator deliberately fails.
   Submit it with `isValid=false`: the collateral input is consumed, its return
   goes to the transaction wallet, and the ordinary inputs stay unspent. The
   ordinary outputs are not created.
4. Explicitly consume the collateral-return UTxO and reference the deployed mint
   policy to mint one NFT to the transaction wallet. Its asset name is the failed
   transaction's raw 32-byte hash, represented as 64 hex characters. A separate
   UTxO supplies collateral for this successful mint.

The failed transaction uses an evaluator hook that runs each script with Scalus
and supplies its measured memory and CPU cost to Lucid's fee/change balancing
loop. Scalus reports the consumed budget for a deliberate script failure too,
so the withdrawal receives precisely the budget needed to reach that failure.
The tool rechecks the final transaction and asserts that both redeemers declare
exactly their measured costs. Ledger validation remains enabled for every
submission. Budget exhaustion and other unexpected failures stop the run.

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

The mint policy is the example's permissive `temp_always_mint` validator. The
scenario supplies and checks the quantity and asset name; the policy does not
enforce those rules or a one-time issuance constraint.

## Results and checks

Successful runs print a report and write the following under the repository's
ignored `artifacts/failure-validation/` directory:

- `plutus.json`: the fresh blueprint.
- `01-deployment.cbor`, `02-registration-and-funding.cbor`,
  `03-failed-spend.cbor`, `04-mint.cbor`: signed transaction CBOR as hex text.
- `report.json`: addresses, script hashes, reference UTxOs, transaction hashes,
  validation results with each script's measured execution budget, the failed
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
