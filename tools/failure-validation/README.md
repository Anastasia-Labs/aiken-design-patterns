# Failure validation

Run the validators in `validators/failure-validation.ak` against configured
builtin invocations. Arguments are supplied in a withdrawal redeemer. A failed
invocation creates collateral return, which a later transaction consumes to mint
proof. The proof policy reads the exact execution budgets from a live,
multisig-controlled parameters NFT.

Lucid Evolution 0.6.2 builds and signs transactions. Scalus 1.3.0 validates and
applies them to its in-memory ledger through a local Lucid provider.

## Run

Requires Node.js 22.16 or newer, pnpm 9.15.4, and Aiken. From this directory:

```sh
pnpm install --frozen-lockfile
pnpm scenario
pnpm scenario --builtin bls12_381_g1_uncompress
```

The default command runs all configured builtins in array order, compiling one
fresh Plutus V3 blueprint per builtin with `--env testnet`. Each case uses a fresh
emulator. The launcher uses `aiken` from `PATH`; set `AIKEN=/path/to/aiken` to
choose another compiler. Aiken always runs with a TTY, using util-linux `script`
when needed. Compiler failures stop the run.

Compilation uses a temporary project copy. The generator replaces the marked
failure-validation section of that copy's `env/testnet.ak`; repository onchain
sources are never rewritten. Existing downloaded Aiken dependencies are copied
into the isolated project when available. The copy is deleted after the compiler
exits, including on errors and handled `SIGINT`/`SIGTERM`. Independent builds have
separate working directories.

The emulator starts at a fixed slot with public deterministic test keys and
1,000 ADA split between a funding input and a reserved bootstrap nonce. All
balances exist only in memory. It uses Scalus's bundled Preview protocol
parameters and slot configuration. Transaction execution needs no network service
or credentials; dependency installation may require network access.

## Builtins and cases

Edit the `BUILTINS` and `CASES` arrays in `src/builtins.ts`:

```ts
// BUILTINS: builtin_name(argument types) -> result type
"bls12_381_g1_uncompress(ByteArray) -> G1Element"

// CASES: builtin_name/case-name|outcome|withdrawal-redeemer-CBOR
"bls12_381_g1_uncompress/empty|builtin-error|9f40ff"

`bls12_381_g1_uncompress/invalid-encoding|builtin-error|${Data.to(["00".repeat(48)])}`
```

Use Aiken builtin names, zero through six `ByteArray` arguments, and a concrete
result type. Each builtin needs at least one case. Case names contain lowercase
letters, digits, hyphens, or underscores and must be unique within a builtin.
The complete configuration is validated before compilation, even when `--builtin`
selects only one entry.

The redeemer must encode a Data list containing exactly the declared number of
byte strings. The generator derives `builtin_function`, `apply_builtin`, and
`validate_builtin_arguments` from the same signature. Argument preparation checks
arity and types; the builtin checks lengths and contents. Boolean results are
returned directly. Non-Boolean results are forced with `expect _ = ...` and then
return `True`. Proof validation checks preparation without calling the builtin.

| Outcome | Expected invocation | Ledger result |
|---|---|---|
| `success` | Returns `True` or completes with a non-Boolean result | Ordinary funding consumed; no outputs or proof |
| `false` | Returns `False`; requires a `Bool` result type | Collateral return consumed by a successful proof mint |
| `builtin-error` | Raises a builtin error | Collateral return consumed by a successful proof mint |

The configured cases cover G1/G2 decompression, ECDSA verification, and Schnorr
verification. Vector provenance is recorded beside the cases. Unexpected errors,
including exhaustion of the declared budget, stop these scenarios. The onchain
proof itself also permits budget exhaustion; it does not classify the cause of
failure.

## Transactions and parameters

1. Reserve a distinct genesis UTxO as the bootstrap nonce. Parameterize
   `failure_parameters` with that nonce, three deterministic signer hashes, and a
   threshold of two. Its applied hash is both the configuration NFT policy ID and
   its spending credential. Apply `failure_proof` to the withdrawal script hash
   and this parameters policy ID. Deploy all three reference scripts and prepare
   separate 100 ADA collateral UTxOs for the producing and successful transactions.
2. Consume the nonce to mint one `FAILURE_PARAMETERS` NFT at its script address,
   with an inline `FailureParameters { max_mem, max_cpu }` datum and 5 ADA. Register
   the withdrawal credential and create the ordinary wallet input for the
   invocation. Bootstrap requires no multisig required signers. The initial
   budgets equal the bundled protocol's transaction limits: 17,500,000 memory and
   10,000,000,000 CPU steps.
3. Consume that single ordinary wallet input, reference the withdrawal script,
   and make one zero withdrawal at ledger index zero. Its redeemer contains the
   builtin arguments and its declared budget equals the configuration datum.
   There are zero ordinary outputs. A successful invocation consumes its funding
   as the fee. A failed invocation submitted with `isValid=false` preserves the
   ordinary input and creates collateral return at `transactionHash#0`.
4. For a failure, consume that collateral return and reference both the proof
   policy and the live parameters NFT UTxO. Mint exactly one token named with the
   producing transaction's raw 32-byte hash. A separate collateral UTxO protects
   this successful mint. The proof does not require any original ordinary input
   to remain unspent.

The parameters validator trusts the multisig's integer values without numeric
bounds. Configuration budgets and protocol transaction limits are separate
concepts. Updates require at least two distinct authorized required signers and
preserve the NFT at the parameters script with an inline datum. The emulator's
update helper signs and submits real transactions; proof construction looks up
the live NFT UTxO every time.

A proof's budgets must match the live parameters when it mints. An update can
make earlier evidence ineligible if its committed budgets differ. Restoring the
same budgets makes that evidence eligible again, provided its collateral return
is still unspent. This is a budget mismatch, not an age-based expiry.

## Exact minimum fees and collateral

With zero ordinary outputs, ordinary-input lovelace must equal the fee. The tool
calculates that amount before submitting the funding transaction:

1. Build a canonical withdrawal template with its prescribed budget and reference
   script. Its local draft input is used only for construction.
2. Build and sign an unsubmitted setup candidate, then finalize the withdrawal
   body with that candidate's real funding-output reference, an empty outputs
   array, fee, total collateral, and collateral return.
3. Sign the withdrawal candidate and calculate its ledger minimum fee with CML,
   including actual witness bytes, declared execution units, and reference-script
   charges. If the amount changes, rebuild both candidates before submission.
4. Once the fee agrees, verify the complete transaction shape and submit setup.
   Convergence is limited to eight passes; failure stops before setup submission.

Lucid's balancing uses a conservative fee estimate. A small CML finalization
helper assembles the restricted producing body before signing, retaining the
canonical redeemers and script-data hash from the template. The ordinary output
field is exactly CBOR `80`; collateral return has address and value only.

Every script transaction declares total collateral as
`ceil(finalFee * collateralPercentage / 100)` lovelace. Preview requires 150%.
Setup and proof transactions are rebuilt before signing until their collateral
matches the final fee. The failed transaction returns the remainder of its
100 ADA collateral input.

An evaluator hook runs the withdrawal under its configured allowance and supplies
that exact allowance to Lucid. Reports distinguish declared and consumed budgets.
Ledger validation remains enabled for every submission. Failure marked
`isValid=true` must be rejected without changing ledger state. Lucid signs with
that flag, so the tool changes only the transaction envelope to `isValid=false`,
checking that body and witnesses remain byte-identical.

The proof witness contains the finalized fee, ordered ordinary input references,
withdrawal arguments, collateral input reference, total collateral, reference
input list, redeemer encoding, and producing Plutus V3 cost model. Canonical Data
encoding uses definite lists and chunked long byte strings. The proof authenticates
these fields by reconstructing the producing transaction hash. Consuming its
collateral return prevents reuse of the evidence.

## Reports and checks

Runs write to the ignored `artifacts/failure-validation/` directory:

- `report.json`: aggregate status, selected builtins, completed outcomes, report
  paths, and an error if the run fails.
- `<builtin>/plutus.json`: the fresh blueprint.
- `<builtin>/<case>/01-deployment.cbor`,
  `02-parameters-registration-and-funding.cbor`, and either
  `03-successful-withdrawal.cbor` or `03-failed-withdrawal.cbor` plus `04-mint.cbor`:
  signed transaction CBOR as hex text.
- `<builtin>/<case>/transactions.json`: every full signed transaction above, in
  execution order, as a JSON array of `{ "cbor": "..." }` objects conforming to the
  [CIP-103](https://cips.cardano.org/cip/CIP-0103) `TransactionSignatureRequest[]`
  format. This JSON can be imported into wallets such as elm-cardano-wallet
  (Tx Inspector, under **chained txs**).
- `<builtin>/<case>/report.json`: arguments and withdrawal redeemer, expected and
  observed outcome, ordinary input, exact fee and calculation passes, script
  identities and references, parameters NFT and budgets, authorized signer hashes
  and threshold, transaction hashes, declared and consumed budgets, collateral
  charges, and proof NFT details. Integer quantities are decimal strings.

```sh
pnpm typecheck
pnpm test
```

The tests cover all configured cases plus Ed25519, `equals_bytearray`, and the
zero-argument `new_list` builtin; malformed preparation; canonical zero-output
transactions at minimum fees; witness tampering; proof after spending the original
ordinary input; parameters bootstrap, authorized updates, insufficient signatures,
and evidence whose budgets cease to match and later match again. Build tests
check source isolation and cleanup on success, compiler errors, and interruptions.

Scalus documents its [collateral handling](https://scalus.org/docs/testing/emulator)
and [Lucid provider integration](https://scalus.org/docs/testing/js-emulator).
