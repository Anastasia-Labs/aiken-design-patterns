# Failure validation

Run the validators in `validators/failure-validation.ak` through configured
builtin invocations. Arguments committed in a script UTxO's inline datum cause
the selected builtin to succeed, return `False`, or raise a builtin error.
For failed invocations, a later transaction consumes the resulting collateral
return and references that still-unspent UTxO to mint proof. Lucid Evolution 0.6.2 builds and signs
the transactions; Scalus 1.3.0 validates and applies them to its in-memory ledger
through a local Lucid provider.

## Run

Requires Node.js 22.16 or newer, pnpm 9.15.4, and Aiken. From this directory:

```sh
pnpm install --frozen-lockfile
pnpm scenario
pnpm scenario --builtin bls12_381_g1_uncompress
```

The default command runs every configured builtin in array order. It builds one
fresh Plutus V3 blueprint per builtin with `--env testnet`, which sets the
network tag used by the proof policy to zero. Each case gets a fresh emulator.
The launcher uses `aiken` from
`PATH` by default. Set `AIKEN` to override the compiler, for example
`AIKEN=/path/to/aiken pnpm scenario`. Compiler failures stop the run. When stdout
is not a terminal, the launcher uses the util-linux `script` command to give Aiken
a TTY and preserve its diagnostics.

For each build, the launcher replaces the marked failure-validation section of
`env/testnet.ak` with the three generated constants. It restores the original
file bytes before executing the cases, including after compiler errors or
handled `SIGINT`/`SIGTERM` interruptions. The compiler process group stops before
restoration. A lock prevents simultaneous environment updates; builds within a
run are sequential. Other environment content and `env/default.ak` are preserved.

The scenario starts a fresh emulator at a fixed slot with deterministic test
keys and 1,000 ADA in its transaction wallet. All balances exist only in memory.
It uses Scalus's bundled Preview protocol parameters and slot configuration;
running the scenario requires no network service or credentials.

## Adding builtins and cases

Edit only the `BUILTINS` and `CASES` arrays in `src/builtins.ts`:

```ts
// BUILTINS: builtin_name(argument types) -> result type
"bls12_381_g1_uncompress(ByteArray) -> G1Element"

// CASES: builtin_name/case-name|outcome|inline-datum-CBOR
"bls12_381_g1_uncompress/empty|builtin-error|9f40ff"

// Template literals with Data.to keep inputs readable.
`bls12_381_g1_uncompress/invalid-encoding|builtin-error|${Data.to(["00".repeat(48)])}`
```

Use Aiken's builtin names, zero through six `ByteArray` arguments, and a concrete
result type. General argument types are future work. Cases are associated by
builtin name; their positions do not have to match the signature array. Each
builtin needs at least one case. Case names may contain lowercase letters,
digits, hyphens, and underscores and must be unique within a builtin.

The datum must encode a Data list with exactly the declared number of byte
strings. The configuration is validated before any environment update, including
when `--builtin` filters the run. Supported outcomes are:

| Outcome | Expected invocation | Transaction result |
|---|---|---|
| `success` | Returns `True`, or completes with a non-Boolean result | Ordinary inputs consumed; no proof NFT |
| `false` | Returns `False` (requires a `Bool` result type) | Collateral return consumed by a successful proof mint |
| `builtin-error` | The selected builtin raises an error on the supplied bytes | Collateral return consumed by a successful proof mint |

The generator derives `builtin_function`, `apply_builtin`, and
`validate_builtin_arguments` from the same signature. Both helpers check the
exact argument count and byte-string types. They leave lengths and contents to
the selected builtin. Boolean results are returned directly. Other results use
`expect _ = builtin_function(...)` followed by `True`, forcing evaluation without
equality checks or serialization. The proof continuation never calls the
selected builtin.

The initial cases cover G1/G2 decompression, ECDSA verification, and Schnorr
verification, including successful invocations, invalid point encodings and
lengths, and signatures checked against the wrong message. Vector provenance is
recorded beside the cases. Adding a supported builtin requires only its signature
and case entries; the runner and generated checks require no per-builtin branch.

## Transactions

1. Publish two reference-script UTxOs at a dedicated wallet address: the shared
   `builtin_probe` validator and the `failure_proof` mint policy. The spending,
   withdrawal, and registration handlers share one script hash. The mint policy
   takes that hash as its sole parameter. Prepare two separate 100 ADA collateral
   UTxOs.
2. Register the shared script's stake credential using its reference script and
   `publish` handler. Lock 20 ADA at its spending address with the inline Data
   list specified by the case, and create a separate 10 ADA wallet UTxO.
   Decompression takes `[compressed_point]`; signature verification takes
   `[public_key, message, signature]`. Every argument is a byte string, so
   argument preparation succeeds.
3. Spend exactly those two ordinary inputs, reference the shared validator once,
   and include precisely one zero withdrawal. The only redeemers are `Spend`
   and `Withdraw`. Ledger input order determines the spending pointer and its
   Boolean redeemer: `True` selects input 0, `False` selects input 1. The withdrawal
   uses `Void` at index 0. Spending succeeds; withdrawal applies the selected
   builtin to the inline arguments. For failure cases, submit the transaction with
   `isValid=false`: the collateral input is consumed, its return goes to the
   transaction wallet, and both ordinary inputs stay unspent. The ordinary outputs
   are not created.
4. Explicitly consume the collateral-return UTxO and reference both the deployed
   mint policy and the original spending UTxO. Supply the finalized failed
   transaction's witness and the indices selecting those inputs to mint one NFT
   to the transaction wallet. Its asset name is the failed transaction's raw
   32-byte hash, represented as 64 hex characters. A separate UTxO supplies
   collateral for this successful mint.

For successful cases, transaction 3 is submitted with `isValid=true`. Both
ordinary inputs are consumed, their outputs are created, collateral stays
unspent, and no collateral-return output or proof NFT exists. There is no fourth
transaction.

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
parameters. Ledger validation remains enabled for every submission. Every case
must match its configured outcome; budget exhaustion and other unexpected
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
declared budgets. The proof witness contains the ordinary outputs' CBOR, fee,
other ordinary input's reference, collateral input's reference, total collateral,
reference-input list, redeemer encoding, and Plutus V3 cost model. Its transaction
fields come from the finalized producing transaction; its cost model comes from
the emulator parameters used to build and evaluate that transaction.

`outputs_cbor` contains the exact CBOR array at transaction-body key 1, including
its array header and contents and excluding the key. The builder extracts these
bytes from the finalized body with `@harmoniclabs/cbor`'s retained byte references.
The policy inserts them verbatim into reconstruction; the body hash authenticates
the bytes and the ledger validates the outputs. Ordinary outputs can include
inline datums, datum hashes, or reference scripts. Their encodings are preserved,
including indefinite arrays and non-minimal integer encodings. Collateral return
is reconstructed from the actual consumed input with address and value only.

The original script UTxO remains available as a reference input, proving the
producing transaction failed. The policy requires exactly one NFT named with
that transaction's hash; consuming its collateral return prevents reuse of the
evidence. The policy's continuation receives the authenticated inline datum and
checks that it contains exactly the configured number of byte strings. It checks argument
preparation without executing the builtin. Malformed argument structure cannot
produce an accepted proof. Byte-string length errors belong to the builtin
itself and qualify as failure evidence, as do builtin `False` results and
exhaustion of the prescribed withdrawal allowance.

## Results and checks

Runs print progress and write the following under the repository's
ignored `artifacts/failure-validation/` directory:

- `report.json`: aggregate status, selected builtins, completed case outcomes,
  and paths to their reports. On failure it also records the error.
- `<builtin>/plutus.json`: that builtin's fresh blueprint.
- `<builtin>/<case>/01-deployment.cbor`, `02-registration-and-funding.cbor`,
  and either `03-failed-spend.cbor` plus `04-mint.cbor`, or
  `03-successful-spend.cbor`: signed transaction CBOR as hex text.
- `<builtin>/<case>/report.json`: the builtin and case names, expected and
  observed outcome, arguments and inline datum; both ordinary
  input references, spending index and Boolean redeemer; the shared script hash,
  spending and reward addresses, reference UTxOs, and transaction hashes;
  validation results with each endpoint's `declared` and `consumed` execution
  budgets (`memory` and `steps`); the failed
  transaction's fee, collateral percentage, minimum charge, returned amount, and
  the NFT unit for failure cases. Success reports record that ordinary inputs
  were consumed, collateral stayed unspent, and no proof was minted. Integer
  quantities are decimal strings.

The command exits nonzero on an unexpected script result, ledger rejection, or
failed assertion. These local checks compile one blueprint per tested builtin,
exercise provider conversions and credential queries, and verify:

- The complete failure-to-proof flow with the script input at either ledger index.
- All configured cases, and configuration-only extension with `equals_bytearray`
  and the zero-argument `new_list` builtin.
- Exact environment restoration after errors and handled signals, and rejection
  of overlapping builds and invalid configuration.
- Ordinary outputs containing inline datums or reference scripts, at either
  spending-input index, and exact preservation of output CBOR encodings.
- Successful verification of the original empty-message signature: both ordinary
  inputs are consumed, collateral remains unspent, and no collateral return exists.
- Withdrawal failure for a non-list datum, missing or extra argument, or wrong argument
  type, followed by rejection of the proof mint during script evaluation.
- Rejection of a proof witness naming an incorrect other ordinary input.
- Rejection of changed, truncated, or appended output CBOR in the proof witness.
- Prescribed execution budgets, exact minimum collateral, reference-script
  preservation, and the proof NFT's name and quantity.

```sh
pnpm typecheck
pnpm test
```

Scalus documents its [collateral handling](https://scalus.org/docs/testing/emulator)
and [Lucid provider integration](https://scalus.org/docs/testing/js-emulator).
