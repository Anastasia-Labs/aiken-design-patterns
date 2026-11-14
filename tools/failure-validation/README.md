# Failure validation

Run `validators/failure-validation.ak` against configured builtin invocations.
Arguments are supplied in a withdrawal redeemer. A failed invocation creates
collateral return, which a later transaction consumes to mint a proof. The proof
policy reads its execution budgets from a parameters NFT controlled by authorized
payment keys.

Lucid Evolution 0.6.2 builds and signs transactions. Scalus 1.3.0 evaluates scripts
locally. `Custom` applies transactions to a deterministic in-memory ledger;
`Mainnet`, `Preprod`, and `Preview` submit them through Blockfrost.

## Run and network configuration

Requires Node.js 22.16 or newer, pnpm 9.15.4, Aiken, and util-linux `script` when
running without a terminal. From this directory:

```sh
pnpm install --frozen-lockfile
cp .env.example .env
NETWORK=Custom pnpm scenario
NETWORK=Custom pnpm scenario --builtin bls12_381_g1_uncompress
NETWORK=Preprod pnpm scenario --resume "/absolute/path/to/run-directory"
```

| Environment variable | Meaning |
|---|---|
| `NETWORK` | Exactly `Custom`, `Mainnet`, `Preprod`, or `Preview`; defaults to `Custom`. |
| `BLOCKFROST_API_KEY` | Required on live networks; a project key for the selected network. |
| `WALLET_SEED` | Required on live networks; a valid BIP-39 mnemonic. |
| `AIKEN` | Optional compiler executable; defaults to `aiken` on `PATH`. |

The runner automatically loads `tools/failure-validation/.env`, including when
launched from the repository root. Copy `.env.example` to `.env` and edit its
values. Exported shell variables take precedence; `NETWORK=Custom pnpm scenario`
always selects the emulator. A missing `.env` is allowed, and `NETWORK` defaults
to `Custom` when neither the file nor the shell sets it. The `.env` file is ignored
by Git.

The seed selects the standard CIP-1852 account-0 base-address wallet: payment key
`m/1852'/1815'/0'/0/0`, stake key `m/1852'/1815'/0'/2/0`, with no passphrase.
Set `NETWORK=Preprod` and your credentials in `.env`, then run all builtins:

```sh
pnpm scenario
```

To select one builtin, use `pnpm scenario --builtin bls12_381_g1_uncompress`.
To continue an interrupted live run, use `pnpm scenario --resume <run-directory>`.
The directory may be absolute or relative. `--resume` cannot be combined with
`--builtin`. Resume is supported on Mainnet, Preprod, and Preview; Custom always
starts a fresh deterministic emulator.

A resumed run uses its saved network, selected cases, and compiled scripts. Set
the same wallet seed and a Blockfrost key for that network before resuming. If `NETWORK` is set, it
must match the saved network. The derived account-0 wallet address and payment
key hash must match the run's manifest. Changes to the local builtin registry or
compiler do not replace saved cases or scripts.

The [official Blockfrost endpoints](https://blockfrost.dev/start-building) are
`https://cardano-mainnet.blockfrost.io/api/v0`,
`https://cardano-preprod.blockfrost.io/api/v0`, and
`https://cardano-preview.blockfrost.io/api/v0`. Invalid network names, missing
credentials, and invalid mnemonics stop before compilation. Live initialization
checks protocol access before compiling. API keys and seeds are never included in
reports, CBOR files, or the manifest.

Fund the wallet's account-0 address on the selected network with ADA-only outputs.
The tool needs ADA for reference scripts, one parameters NFT, one 100 ADA rolling
failure-collateral seed, ordinary inputs, fees, and any stake registration
deposit. A separate existing ADA-only wallet output is reused as collateral for
setup and proof transactions. A wallet without separate bootstrap, collateral,
and funding outputs is split automatically. Token-bearing outputs, reference
scripts, and reserved inputs are excluded from ordinary coin selection. Lucid
selects funding from this filtered pool, leaving unused wallet UTxOs unspent.
Signed transactions are checked against the current maximum transaction size
before submission. Live runs spend fees and deposits, and expected failures
charge the rolling collateral. Use a dedicated wallet without concurrent
spending while the run is in progress.

`Custom` needs no credentials or network service for transaction execution.
It starts at a fixed slot with public deterministic test keys and 1,000 ADA,
uses Scalus's bundled Preview parameters and slot configuration, and gives every
case a fresh emulator with a 2-of-3 parameters configuration. Live networks use
current Blockfrost protocol parameters and a 1-of-1 configuration controlled by
the supplied wallet's payment key. A live run applies that parameters policy once
for the selected builtins; each builtin keeps its own withdrawal and proof
policies and receives its own stake registration only when needed.

## Compilation and builtin cases

Each selected builtin gets a fresh Plutus V3 blueprint. All selected blueprints
are compiled and saved before the first submission. Compilation uses a
temporary copy of the project and an isolated generated `failure_tooling`
environment with network tag `1` for Mainnet and `0` for all other networks.
Repository environment files and onchain sources are untouched. Downloaded
Aiken dependencies are copied when available. Builds always have a TTY and check
the compiler exit status. Temporary build projects are deleted after success,
errors, and handled interruptions. Test blueprints are temporary too.

Edit `BUILTINS` and `CASES` in `src/builtins.ts`:

```ts
// BUILTINS: builtin_name(argument types) -> result type
"bls12_381_g1_uncompress(ByteArray) -> G1Element"

// CASES: builtin_name/case-name|outcome|withdrawal-redeemer-CBOR
"bls12_381_g1_uncompress/empty|builtin-error|9f40ff"
```

Use zero through six `ByteArray` arguments and a concrete return type. Each builtin
needs a case; case names use lowercase letters, digits, hyphens, or underscores.
The complete configuration is validated before compilation, including entries
not selected by `--builtin`. Redeemers must be Data lists of the declared arity
containing only byte strings. The generator keeps argument preparation in the
withdrawal and proof policy consistent.

| Outcome | Local invocation | Confirmed transaction effects |
|---|---|---|
| `success` | Returns `True` or completes with a non-Boolean result | Ordinary input pays the fee; zero outputs and no proof |
| `false` | Returns `False`; requires a Boolean builtin | Collateral return is consumed by a proof mint |
| `builtin-error` | Raises a builtin error | Collateral return is consumed by a proof mint |

The 12 configured cases cover G1/G2 decompression, ECDSA, and Schnorr verification.
Vector sources are recorded beside the cases. Unexpected failures, including
budget exhaustion, stop the run. The onchain proof also permits budget exhaustion;
it does not classify the failure cause.

## Setup, funding, and submission

Live runs deploy one shared parameters policy and reference script set for all
selected builtins. The bootstrap consumes one real wallet UTxO as its unique
nonce, mints one `FAILURE_PARAMETERS` NFT, and stores the protocol execution
limits in an inline datum. Each builtin's proof policy is applied to this common
parameters policy. The runner checks each distinct withdrawal stake credential
and registers it once when needed. It packs the NFT bootstrap, 100 ADA collateral
seed, reference scripts, and registration certificates into signed setup
transactions that fit the network's current maximum transaction size. Scripts
created as reference outputs are attached to those transactions directly.

Each case has one funding transaction with a single ordinary output sized to the
exact withdrawal fee. The fee calculation uses the selected rolling collateral
value and builds and signs both candidates before submitting:

1. Build a canonical withdrawal template with the declared execution budget.
2. Build an unsubmitted funding transaction and finalize the withdrawal using its
   actual output references, zero ordinary outputs, and collateral return.
3. Calculate the minimum fee from the signed bytes, execution units, and reference
   script charges; repeat if the exact-fee ordinary input needs to change.
4. Save the finalized funding and withdrawal CBOR together, including the final
   `isValid=false` envelope for failure cases. Submit funding, await its outputs,
   then submit the saved withdrawal bytes.
   Failure to converge within eight passes stops before funding submission.

Every script transaction declares exactly
`ceil(finalFee * collateralPercentage / 100)` lovelace of total collateral.
Successful withdrawals leave the current collateral UTxO available. For a failed
invocation, the live path submits only the finalized `isValid=false` envelope,
preserving the signed body and witnesses. It awaits collateral return at
`transactionHash#0` before constructing the proof. The proof consumes that return;
its ADA-only change becomes the next rolling collateral UTxO. If that change is
too small to cover collateral and minimum return ADA, the runner selects the
largest eligible existing wallet UTxO, or stops before funding the next case.
The proof references the builtin's proof script and shared parameters NFT. Its
token name is the producing transaction's raw 32-byte hash. The recorded Preprod
projection leaves about 34.46 ADA after rolling a 100 ADA seed through all eight
failure cases.

Lucid's Blockfrost provider supplies the current protocol version, cost models,
fees, deposits, execution limits, and collateral rules. Lucid uses a local Scalus
evaluator configured from the same protocol snapshot used to build the transaction.
The runtime refreshes parameters before setup,
each case, and proof construction. The producing snapshot is retained for the
proof witness. If execution limits change after bootstrap, the run stops before
starting another case. The emulator tests exercise authorized budget updates,
insufficient signatures, and the requirement for proof budgets to match the
live parameters NFT.

Submission is sequential. Lucid polls inclusion every three seconds with a
ten-minute deadline per transaction; required current UTxOs are checked within
the remaining budget. A transaction must appear in a block with the expected
validity flag, and its required outputs and input consumption must be visible.
Spendability is checked against **current address UTxOs**, including collateral
return. Historical `consumed_by_tx` is not used as evidence of spendability.

Rejection, timeout, or interruption stops the run. Resume checks each saved hash
on chain first. It skips confirmed steps, waits for pending steps, and can send
the same saved bytes once when a transaction is not found and its required inputs
remain spendable. It never rebuilds a saved transaction or selects replacement
funding. If inputs are unavailable and the outcome is unclear, it waits for
confirmation and stops on timeout. An accepted transaction can survive a lost
submission response; resume recognizes its hash without minting another proof.
Completed runs are checked no-ops.
`SIGINT` and `SIGTERM` preserve completed writes and stop further submissions.

## Artifacts and verification

CLI runs preserve earlier runs under:

```text
artifacts/failure-validation/<NETWORK>/<timestamp-and-unique-id>/
  manifest.json                         # authoritative v2 run state on live networks
  report.json
  transactions.json
  transaction-status.json
  <builtin>/plutus.json
  setup/                                # shared live setup and rolling collateral
    report.json
    transactions.json
    transaction-status.json
    <transaction>.cbor
    <transaction>.hash
  <builtin>/<case>/
    report.json
    producing-protocol.json
    transactions.json
    transaction-status.json
    <transaction>.cbor
    <transaction>.hash
```

Custom setup transactions are recorded in each case's directory and each Custom
case uses an isolated emulator. On live networks, `manifest.json` records wallet
identity, complete case selection, compiled scripts and hashes, the shared
parameters NFT, setup and case checkpoints, protocol snapshots, rolling
collateral checkpoints, and ordered signed transactions. It is saved atomically
before submission.
Integer quantities are decimal strings. The `.cbor`, `.hash`, reports, and
bundles are generated views of that state. Status files track signing,
submission, and confirmation incrementally and preserve partial results on failure.
`transactions.json` retains the array-of-`{ "cbor": "..." }` format used by
[CIP-103](https://cips.cardano.org/cip/CIP-0103). The run-level bundle contains all
recorded transactions in execution order, including shared setup and any final
transaction whose submission outcome is unknown. Consult `transaction-status.json`
for its status; bundle presence alone does not imply confirmation.

Case reports record arguments, the redeemer, expected outcome, ordinary input,
exact fee, script references, parameters NFT, signer hashes, declared and consumed
budgets, collateral, and proof token details. Reports label local Scalus evaluation
separately from observed emulator or confirmed chain effects. Numeric quantities
that require integer precision are decimal strings. Deliberate rejection tests
and assertions over the entire ledger run only in `Custom`.

```sh
pnpm typecheck
NETWORK=Custom pnpm test
```

Tests run all 12 configured cases plus Ed25519, `equals_bytearray`, and `new_list`;
they retain preparation-failure, witness-tampering, and multisig coverage. Additional
tests cover all networks, wallet derivation, compilation tags, shared live setup,
existing stake registration, delayed indexing, raw invalid submission, spent
collateral, timeouts, interruption, partial artifacts, ordered bundles, and secret
redaction using mocked Blockfrost responses. CI explicitly uses `Custom` and uploads
CLI artifacts even on failure.

Mocked tests are not live-network verification. Actual Preprod verification
requires a funded wallet and Blockfrost credentials; no successful live run is
claimed by the automated suite.

Resume accepts only runs with the v2 manifest and rejects v1 manifests. A
completed v1 Preprod run may be retained as a non-resumable archive. Do not run
two processes against the same run directory concurrently.
