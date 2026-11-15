# Failure validation

Run `validators/failure-validation.ak` against configured builtin invocations.
Every configured vector runs with both direct arguments in a typed withdrawal
redeemer and arguments stored in referenced inline datums. A failed invocation
creates collateral return, which a later transaction consumes to mint a proof. The proof
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
Both argument modes run automatically, direct then referenced for each vector.
The default configuration runs six executions per builtin, 24 in total.
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
The tool needs ADA for reference scripts, one parameters NFT, argument references,
transaction fees, bounded collateral, and any stake registration deposit. Wallet
preparation creates a 2 ADA bootstrap nonce and dedicated setup/proof collateral
sized to the greater of 20 ADA or the conservative script-fee collateral requirement
plus minimum return ADA. Each withdrawal receives newly sized collateral from its
own funding transaction. The remaining ADA stays available for ordinary funding.
Token-bearing outputs and protected resources are excluded from ordinary coin
selection. Unrelated wallet outputs remain outside final cleanup unless explicitly
adopted as transaction inputs. Signed transactions and reclamation batches must fit
the current maximum transaction size. Live runs spend fees and deposits; expected
failures charge collateral. Use a dedicated wallet without concurrent spending.

`Custom` needs no credentials or network service for transaction execution.
It starts at a fixed slot with public deterministic test keys and 1,000 ADA,
uses Scalus's bundled Preview parameters and slot configuration, and gives every
case and mode a fresh emulator with a 2-of-3 parameters configuration. Live networks
use current Blockfrost protocol parameters and a 1-of-1 configuration controlled by
the supplied wallet's payment key. A live run applies that parameters policy once
for the selected builtins; each builtin keeps its own withdrawal and proof
policies and receives its own stake registration only when needed.

## Compilation and builtin cases

Each selected builtin is compiled once into a fresh Plutus V3 blueprint used by
both modes. All selected blueprints are compiled and saved before the first
submission. Compilation uses a
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

// CASES: builtin_name/case-name|outcome|argument-list-CBOR
"bls12_381_g1_uncompress/empty|builtin-error|9f40ff"
```

Use zero through six `ByteArray` arguments and a concrete return type. Each builtin
needs a case; case names use lowercase letters, digits, hyphens, or underscores.
The complete configuration is validated before compilation, including entries
not selected by `--builtin`. Configured arguments must be Data lists of the
declared arity containing only byte strings. The generator keeps argument preparation in the
withdrawal and proof policy consistent.

`DirectArguments` is constructor 0 containing the argument list.
`ReferencedArguments` is constructor 1 containing indexes into the withdrawal's
complete, canonically sorted reference-input list. The indexes select inline
datums in argument order. Repeated argument values receive distinct UTxOs and
distinct indexes. An empty argument list uses no provisioning transaction.

| Outcome | Local invocation | Confirmed transaction effects |
|---|---|---|
| `success` | Returns `True` or completes with a non-Boolean result | Ordinary input pays the fee; zero outputs and no proof |
| `false` | Returns `False`; requires a Boolean builtin | Collateral return is consumed by a proof mint |
| `builtin-error` | Raises a builtin error | Collateral return is consumed by a proof mint |

The 12 configured vectors cover G1/G2 decompression, ECDSA, and Schnorr verification.
Their 24 executions produce eight successful withdrawals without proofs and
sixteen failures with authenticated proof mints.
Vector sources are recorded beside the cases. Unexpected failures, including
budget exhaustion, stop the run. The onchain proof also permits budget exhaustion;
it does not classify the failure cause.

## Setup, funding, and submission

Live runs deploy one shared parameters policy and reference script set for all
selected builtins. The bootstrap consumes one real wallet UTxO as its unique
nonce, mints one `FAILURE_PARAMETERS` NFT, and stores the protocol execution
limits in an inline datum. Each builtin's proof policy is applied to this common
parameters policy. The runner checks each distinct withdrawal stake credential
and registers it once when needed. It packs the NFT bootstrap, reference scripts,
and registration certificates into signed setup transactions that fit the network's
current maximum transaction size. Scripts
created as reference outputs are attached to those transactions directly. Setup
funding includes the actual minimum ADA for each reference script's serialized size.

Before fee calculation, each referenced execution provisions one inline-datum
UTxO per argument in a journaled `02-arguments` transaction. Outputs retain
argument order, including repeated values. The withdrawal references these
outputs together with its withdrawal script, sorted by transaction hash and
numeric output index; its redeemer uses indexes into that complete list.

Each execution has one `03-funding` transaction. Output 0 is the exact withdrawal
fee input; output 1 is dedicated withdrawal collateral; remaining ADA becomes
ordinary change. The fee-convergence loop builds and signs both transactions:

1. Build a canonical withdrawal template with the declared execution budget.
2. Size collateral to `ceil(finalFee * collateralPercentage / 100)` plus its
   return reserve, build funding, and finalize the withdrawal using those actual
   output references, zero ordinary outputs, and collateral return.
3. Calculate the minimum withdrawal fee from the signed bytes, execution units,
   and reference script charges; repeat with the revised fee and collateral.
4. Save the finalized funding and withdrawal CBOR atomically, including the
   `isValid=false` envelope for failure cases. Submit funding, await its outputs,
   then submit the saved withdrawal. Failure to converge within eight passes stops
   before submitting funding.

Successful withdrawals reserve minimum ADA for collateral return. Failure cases
also reserve a conservative proof fee, minimum ADA for ordinary proof change, and
any ADA needed to grow the proof bundle. CML calculates the proof-fee bound using
the protocol's maximum transaction size and execution budget and the actual
applied proof reference-script size, including tiered reference-script charges.
Every script transaction declares exactly the required percentage of its final
fee as total collateral.

A failed withdrawal submits the finalized `isValid=false` envelope and awaits
collateral return at `transactionHash#0`. The proof consumes that authenticated
return and the previous proof bundle, producing one minimum-ADA bundle containing
every accumulated proof NFT. Inputs are sorted canonically and the redeemer's
collateral-return index is recomputed. No tokens are discarded. The proof
references its script, shared parameters NFT, and original argument UTxOs. Its
witness retains the typed withdrawal redeemer and original reference-input order.
The proof token name is the producing transaction's raw 32-byte hash. Proof change
becomes ordinary funding.

The v4 resource inventory records each created or adopted output, its role,
creation transaction, release condition, and confirmed consuming transaction.
Arguments release after a successful withdrawal or confirmed proof mint. Reference
scripts release after their last scheduled execution, accounting for scripts shared
by hash. The parameters resources and setup/proof collateral remain protected until
cleanup. Surviving failed-withdrawal fee inputs and successful-withdrawal collateral
become ordinary funding after execution completes.

The next argument-provisioning or funding transaction collects eligible resources
and consolidates run-created ADA into its change. Reclamation inputs are selected
deterministically and batches are limited by signed transaction size. After all
executions pass, journaled cleanup reclaims remaining arguments, reference scripts,
ordinary remnants, and collateral. Its bytes are saved before submission. The run
passes only after cleanup confirms, leaving at most one ordinary ADA output, one
consolidated proof-NFT output, and the parameters NFT at its contract address.
Stake registrations remain active. Each isolated Custom execution uses the same
lifecycle and wallet-controlled reference outputs.

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
funding or argument outputs. Argument provisioning resumes from its saved bytes.
If inputs are unavailable and the outcome is unclear, it waits for
confirmation and stops on timeout. An accepted transaction can survive a lost
submission response; resume recognizes its hash without minting another proof.
Resume accepts resources consumed by confirmed journaled transactions and requires
all other current resources to remain available. It retains saved funding pairs
and does not recreate released references. Unexpected external spends are errors.
Completed runs verify historical transactions and final outputs without submissions.
`SIGINT` and `SIGTERM` preserve completed writes and stop further submissions.

## Artifacts and verification

CLI runs preserve earlier runs under:

```text
artifacts/failure-validation/<NETWORK>/<timestamp-and-unique-id>/
  manifest.json                         # authoritative v4 run state on live networks
  report.json
  transactions.json
  transaction-status.json
  <builtin>/plutus.json
  setup/                                # shared live setup and bounded collateral
    report.json
    transactions.json
    transaction-status.json
    <transaction>.cbor
    <transaction>.hash
  cleanup/                              # journaled final reclamation on live networks
    report.json
    transactions.json
    transaction-status.json
    <transaction>.cbor
    <transaction>.hash
  <builtin>/<case>/<mode>/               # direct or referenced
    report.json
    producing-protocol.json
    transactions.json
    transaction-status.json
    <transaction>.cbor
    <transaction>.hash
```

Custom setup transactions are recorded in each execution's directory and each Custom
execution uses an isolated emulator. On live networks, `manifest.json` records wallet
identity, complete case selection, compiled scripts and hashes, the shared
parameters NFT, setup and case checkpoints, protocol snapshots, resource lifecycle
and cleanup checkpoints, the current proof bundle, argument modes, argument references, indexes, resolved
argument CBOR, full typed redeemers, and ordered signed transactions. It is saved atomically
before submission.
Integer quantities are decimal strings. Final cleanup references and resource release
and consumption details accompany the original argument, reference-script, and mint
output references, which remain historical evidence. The `.cbor`, `.hash`, reports, and
bundles are generated views of that state. Status files track signing,
submission, and confirmation incrementally and preserve partial results on failure.
`transactions.json` retains the array-of-`{ "cbor": "..." }` format used by
[CIP-103](https://cips.cardano.org/cip/CIP-0103). The run-level bundle contains all
recorded transactions in execution order, including shared setup and any final
transaction whose submission outcome is unknown. Consult `transaction-status.json`
for its status; bundle presence alone does not imply confirmation.

Case reports record mode, resolved arguments, original argument references,
reference-input indexes, the full typed redeemer, expected outcome, ordinary input,
exact fee, script references, parameters NFT, signer hashes, declared and consumed
budgets, collateral, and proof token details. Reports label local Scalus evaluation
separately from observed emulator or confirmed chain effects. Numeric quantities
that require integer precision are decimal strings. Deliberate rejection tests
and assertions over the entire ledger run only in `Custom`.

```sh
pnpm typecheck
NETWORK=Custom pnpm test
```

Tests run all 24 configured executions plus both modes for Ed25519,
`equals_bytearray`, and `new_list`; they cover repeated values, empty lists,
canonical index calculation, proof-reference ordering, missing or substituted
argument references, preparation failures, witness tampering, and multisig
authorization. Additional tests cover all networks, wallet derivation, compilation tags, shared live setup,
existing stake registration, delayed indexing, raw invalid submission, spent
collateral, timeouts, interruption, partial artifacts, ordered bundles, and secret
redaction using mocked Blockfrost responses. CI explicitly uses `Custom` and uploads
CLI artifacts even on failure.

The single-ledger mocked run checks eight successes, sixteen proof NFTs in one
minimum-ADA bundle, and exactly three final outputs. Lifecycle tests cover bounded
collateral with large and fragmented funding, shared reference-script protection,
argument release timing, both canonical proof input indexes, deterministic size
batches, insufficient funds, and cleanup before completion. Recovery tests interrupt
saved and accepted funding, proof consolidation, reclamation, and cleanup; they
require identical saved bytes, one submission per hash, and completed-run checks
without submissions. Each Custom CLI execution also verifies its final resources.

Mocked tests are not live-network verification. Actual Preprod verification
requires a funded wallet and Blockfrost credentials; no successful live run is
claimed by the automated suite.

Resume accepts only runs with the v4 manifest. There is no manifest migration. Do not run
two processes against the same run directory concurrently.
