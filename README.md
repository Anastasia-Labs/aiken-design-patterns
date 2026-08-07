# Table of Contents

<!-- vim-markdown-toc GFM -->

* [Aiken Library for Common Design Patterns in Cardano Smart Contracts](#aiken-library-for-common-design-patterns-in-cardano-smart-contracts)
    * [How to Use](#how-to-use)
    * [How to Run Package Tests](#how-to-run-package-tests)
    * [Provided Patterns](#provided-patterns)
        * [Stake Validator](#stake-validator)
        * [UTxO Indexers](#utxo-indexers)
        * [Transaction Level Validator Minting Policy](#transaction-level-validator-minting-policy)
        * [Validity Range Normalization](#validity-range-normalization)
        * [Merkelized Validator](#merkelized-validator)
        * [Parameter Validation](#parameter-validation)
        * [Linked List](#linked-list)
        * [Governance Validation](#governance-validation)
    * [License](#license)

<!-- vim-markdown-toc -->

# Aiken Library for Common Design Patterns in Cardano Smart Contracts

To help facilitate faster development of Cardano smart contracts, we present a
collection of tried and tested modules and functions for implementing common
design patterns.

Based on our [`design-patterns`](https://github.com/Anastasia-Labs/design-patterns) repository.

## How to Use

Install the package with `aiken`:

```bash
aiken add anastasia-labs/aiken-design-patterns --version v1.7.0
```

And you'll be able to import functions of various patterns:

```rs
use aiken_design_patterns/merkelized_validator
use aiken_design_patterns/multi_utxo_indexer
use aiken_design_patterns/linked_list
use aiken_design_patterns/linked_list/advanced
use aiken_design_patterns/linked_list/nested
use aiken_design_patterns/parameter_validation
use aiken_design_patterns/singular_utxo_indexer
use aiken_design_patterns/stake_validator
use aiken_design_patterns/tx_level_minter
use aiken_design_patterns/governance_validation
```

Check out `validators/examples` to see how the exposed functions can be used.

## How to Run Package Tests

Here are the steps to compile and run the included tests:

1. Clone the repo and navigate inside:

```bash
git clone https://github.com/Anastasia-Labs/aiken-design-patterns
cd aiken-design-patterns
```

2. Run the build command, which both compiles all the functions/examples and
   also runs the included unit tests:

```sh
aiken build
```

3. Execute the test suite:

```sh
aiken check
```

## Provided Patterns

### Stake Validator

This pattern allows for delegating some computations to a given staking script.

The primary application for this is the so-called "withdraw zero trick," which
is most effective for validations against multiple script inputs in the
transaction.

With a minimal spending logic (which is executed for each UTxO), and an
arbitrary withdrawal logic (which is executed only once), a much more optimized
script can be implemented.

The module offers three functions, primarily meant to be implemented under
spending endpoints:
- `validate_withdraw`
- `validate_withdraw_with_amount`
- `validate_withdraw_minimal`

Use `validate_withdraw_minimal` if you don't need to perform any validations on
either the staking script's redeemer or withdrawal Lovelace quantity.

All three functions go over the `withdrawals` list in the transaction. However,
`validate_withdraw` and `validate_withdraw_with_amount` also traverse the
`redeemers` field in order to let you validate against the redeemer (and the
withdrawal quantity in case of the latter).

For a ledger-valid transaction, the presence of a script credential in
`withdrawals` necessarily causes that script witness to execute. Therefore,
`validate_withdraw_minimal` does not need to find the same purpose in
`redeemers` unless the surrounding contract actually needs its redeemer. The
ledger separately validates the legality of the withdrawal amount.

### UTxO Indexers

The primary purpose of this pattern is to offer a more optimized and composable
solution for a unique mapping between one input UTxO to one or many output
UTxOs.

There are a total of 4 variations available:
- Single, one-to-one indexer
- Single, one-to-many indexer
- Multiple, one-to-one indexer, with ignored redeemers
- Multiple, one-to-one indexer, with provided redeemers

> [!NOTE]
> Neither of the singular UTxO indexer patterns provides protection against the
> [double satisfaction](https://github.com/Plutonomicon/plutonomicon/blob/b6906173c3f98fb5d7b40fd206f9d6fe14d0b03b/vulnerabilities.md#double-satisfaction)
> vulnerability, as this can be done in multiple ways depending on the contract.
> However, they require a dedicated argument as a reminder for the potential
> requirement of implementing a protection against this vulnerability.

Depending on the variation, the functions you can provide are:
- One-to-one validator for an input and its corresponding outputs – this is
  always the validation that executes the most times (i.e. for each output)
- One-to-many validator for an input and all of its corresponding outputs – this
  executes only once

### Transaction Level Validator Minting Policy

Very similar to the [stake validator](#stake-validator), this design pattern
couples the spend and minting endpoints of a validator.

In other words, spend logic only ensures the minting endpoint executes. It does
so by looking at the mint field and making sure a non-zero amount of its asset
(i.e. with a policy identical to the provided script hash) are getting
minted/burnt.

The arbitrary logic is passed to the minting policy so that it can be executed
a single time for a given transaction.

### Validity Range Normalization

The datatype that models validity range in Cardano currently allows for values
that are either meaningless, or can have more than one representation. For
example, since the values are integers, the inclusive flag for each end is
redundant for most cases and can be omitted in favor of a predefined convention
(e.g. a value should always be considered inclusive).

In this module we present a custom datatype that essentially reduces the value
domain of the original validity range to a smaller one that eliminates
meaningless instances and redundancies.

The datatype is defined as follows:

```rs
pub type NormalizedTimeRange {
  ClosedRange { lower: Int, upper: Int }
  FromNegInf  {             upper: Int }
  ToPosInf    { lower: Int             }
  Always
  InvalidRange
}
```

The exposed function of the module (`normalize_time_range`), takes a
`ValidityRange` and returns this custom datatype.

### Merkelized Validator

Since transaction size is limited in Cardano, some validators benefit from a
solution which allows them to delegate parts of their logic. This becomes more
prominent in cases where such logic can greatly benefit from optimization
solutions that trade computation resources for script sizes (e.g. table
lookups can take up more space so that costly computations can be averted).

This design pattern offers an interface for off-loading such validations into an
external observer/withdrawal script, so that the sizes of the scripts themselves
can stay within the limits of Cardano.

> [!NOTE]
> Be aware that total size of reference scripts is currently limited to 200KiB
> (204800 bytes), and they also impose additional fees in an exponential manner.
> See [here](https://github.com/IntersectMBO/cardano-ledger/issues/3952) and [here](https://github.com/CardanoSolutions/ogmios/releases/tag/v6.5.0) for
> more info.

The exposed `delegated_compute` function from `merkelized_validator` expects 6
arguments:

1. The arbitrary input value for the underlying computation logic
2. The hash of the withdrawal validator that performs the computation
3. The `Pairs` of all redeemers within the current script context.
4. Positional index of the withdrawal redeemer inside the `redeemers` list
5. Validation function for coercing a `Data` to the format of the input expected
   by the staking script's computation
6. A similar validation function for coercing `Data` to the expected output of
   the computation

This function expects to find the given stake validator in the `redeemers` list,
such that its redeemer is of type `ComputationRedeemer` (which carries the
generic input argument(s) and the expected output(s)), makes sure provided
input(s) match the ones given to the validator through its redeemer, and returns
the output(s) (which are carried inside the withdrawal redeemer) so that you can
safely use them.

For defining a withdrawal logic that carries out the computation, use the
exposed `computation_withdrawal_wrapper` function. It expects 2 arguments:

1. A redeemer of type `ComputationRedeemer<a, b>`. Note that `a` is the type of
   input argument(s), and `b` is the type of output argument(s)
2. The computation itself. It has to take an argument of type `a`, and return
   a value of type `b`

It validates that the given input(s) and output(s) match correctly with the
provided computation logic.

There are also `ValidationRedeemer<a>`, `validation_withdrawal_wrapper` and
`delegated_validation` variants which can be used for validations that don't
return any outputs.

### Parameter Validation

In some cases, validators need to be aware of instances of a parameterized
script in order to have a more robust control over the flow of assets.

As a simple example, consider a minting script that needs to ensure the
destination of its tokens can only be instances of a specific spending script,
e.g. parameterized by users' wallets.

Since each different wallet leads to a different script address, without
verifying instances, instances can only be seen as arbitrary scripts from the
minting script's point of view.

This can be resolved by validating an instance is the result of applying
specific parameters to a given parameterized script.

To allow this validation on-chain, some restrictions are needed:
1. Parameters of the script must have constant lengths, which can be achieved by
   having them hashed
2. Consequently, for each transaction, the resolved value of those parameters
   must be provided through the redeemer
3. The dependent script must be provided with CBOR bytes of instances before and
   after the parameter(s)
4. Wrapping instances' logic in an outer function so that there'll be single
   occurrences of each parameter

This pattern provides two sets of functions. One for applying parameter(s) in
the dependent script (i.e. the minting script in the example above), and one for
wrapping your parameterized scripts with.

After defining your parameterized scripts, you'll need to generate instances of
them with dummy data in order to obtain the required `prefix` value for your
target script to utilize. Note that your prefix should be from a single CBOR
encoded result.

Take a look at `validators/examples/parameter-validation.ak` to see them in use.

### Linked List

Storing lists directly in datums is generally impractical: as the datum grows,
the UTxO can become too expensive or impossible to spend.

A linked list stores the collection across many authenticated UTxOs. Each list
element carries ADA, exactly one list NFT, an inline datum, and a link to its
immediate successor.

Plutonomicon has [a nice write-up](https://github.com/Plutonomicon/plutonomicon/blob/main/assoc.md)
of how this can be implemented with eUTxOs.

To provide an API as user-friendly as possible, the implementation handles
structural linked-list validations and provides the data needed for custom
application validations. This is why the API exposes primary list operations
such as `init`, `insert_ascending`, and `remove`, rather than asking each
contract to reassemble the structural checks from granular helpers.

The linked-list API is split across three modules:
- [`aiken_design_patterns/linked_list`](https://anastasia-labs.github.io/aiken-design-patterns/aiken_design_patterns/linked_list.html)
  provides the default root/node list API. Its mint helpers are strict: they do
  not allow unrelated mint/burn changes under the list NFT policy.
- [`aiken_design_patterns/linked_list/advanced`](https://anastasia-labs.github.io/aiken-design-patterns/aiken_design_patterns/linked_list/advanced.html)
  reuses the default `Element` type and extends the default API for reference
  scripts and callbacks that see spent and continued anchor data. Its structural
  node operations and deinit may expose permitted same-policy mint/burn changes
  and same-policy inputs from other payment credentials; init and non-structural
  updates remain strict. Additional mint/burn names must stay outside both the
  reserved root key and the node-key namespace. Input asset names at other
  credentials are exposed unchanged for application validation. In a correctly
  wired policy, the reserved root token can never be among them: it is the one
  policy-wide singleton minted into the canonical root at initialization.
- [`aiken_design_patterns/linked_list/nested`](https://anastasia-labs.github.io/aiken-design-patterns/aiken_design_patterns/linked_list/nested.html)
  uses its own `Element` type and supports two-level linked lists with `Root`,
  `InnerRoot`, and `Node` elements. Nested currently provides init, deinit,
  insertion helpers, the structural spend gate for add/remove branches, and
  non-structural update spends. Its insertion and deinit callbacks also receive
  permitted non-reserved same-policy mint/burn changes and namespace-classified
  inputs; custom read/remove logic must preserve the same structural invariants.

See the generated docs pages above for module-specific details. They are long
and elaborate many of the soft requirements in order to better guide agents.

List membership is authenticated by an asset under the list NFT policy, never
by the payment credential alone. Anyone can create an output at the list payment
credential without running either the spend script or the minting policy. An
ADA-only UTxO, or a UTxO carrying only foreign-policy assets, is therefore not a
list element even when it sits at that credential. It requires no linked-list
structural validation, and no linked-list invariant may rely on its datum, value,
continuation, or eventual spend. UTxOs at one credential remain independent: a
transaction consumes only the inputs its builder explicitly selects, and an
outside party cannot force another UTxO into a list transition. These UTxOs never
need to be discovered, collected, spent, or cleaned up by the list protocol.
Off-chain list discovery must authenticate the expected structural token and
canonical element shape rather than treating every UTxO at the payment
credential as state. The namespace-aware advanced and nested input scanners
ignore inputs without list-policy assets completely. Only inputs carrying
assets under the list policy enter their structural or
non-structural classification.

Import the base `linked_list` module alongside any variant module you call.
Keep variant-specific operations in their variant modules; in particular,
`nested` datums must not be passed to the base update/read helpers.

```rs
use aiken_design_patterns/linked_list
use aiken_design_patterns/linked_list/advanced
// or: use aiken_design_patterns/linked_list/nested
```

#### Usage Guideline

Contracts using these modules must keep all authenticated list elements
controlled by one spend script/payment credential and one list NFT minting
policy:

1. Define the spend script datum as an applied alias of the module's `Element`
   type. For base and advanced lists this is `Element<RootType, NodeType>`;
   for nested lists this is `Element<RootType, InnerRootType, NodeType>`.
2. Ensure that the UTxO produced by `init` goes to that spend script credential.
3. Implement structural spend branches so they only succeed through
   `spend_for_adding_or_removing_an_element`.
4. Implement non-structural continuation branches through
   `spend_for_updating_elements_data`.
5. Implement the list minting policy so every structural init, insert, remove,
   fold, and deinit mint/burn branch uses the matching linked-list mint helper
   where the module provides one. Custom nested remove logic must prove the same
   structural invariants directly in its minting-policy branch. The spend-side
   structural gate and mint-policy validation are a paired API: the spend gate
   permits the list UTxO spend when a list-policy mint/burn is present, and the
   mint policy proves the exact list transition.
6. Pass the complete, unmodified `ScriptContext.transaction.inputs` list in
   ledger order to every linked-list helper `inputs` argument. Do not pass a
   filtered, reordered, reconstructed, or redeemer-provided list. Exact
   structural-input counts and namespace-aware input collection are guaranteed
   only across the supplied list.
7. Treat the list policy, not the payment credential, as the authentication
   boundary. UTxOs without any asset under that policy are outside the list
   state, including when they are at the list payment credential; do not validate
   or protect them as list elements. Transaction builders select inputs
   explicitly, so hostile outputs at that credential neither participate in nor
   block a valid list transition. They require no cleanup. Off-chain indexers
   must authenticate the structural list token and canonical element shape, not
   infer membership from the address alone.
8. Every `Output` argument passed to a linked-list mint helper must be selected
   from the script context transaction outputs. Helpers authenticate the
   selected outputs as list UTxOs, but intentionally leave the selection method
   to the caller. A contract may pick by redeemer-provided output index, filter
   `ScriptContext.transaction.outputs`, use `list.find`, or use another
   deterministic method. What matters is that the final `Output` value comes
   from the transaction outputs, not from redeemer data or a locally constructed
   value.
9. Reserve the asset `<list_nft_policy_id, root_key>` globally across every
   redeemer branch of the list policy. A one-time `init` is the only branch that
   may mint it, and it mints exactly one into the canonical root at the list
   payment credential. Structural and update continuations keep it there;
   `deinit` is the only branch that may burn it. Every application-specific
   same-policy branch must also reject changes to `root_key`. Under this
   policy-wide invariant, a `root_key` token at another payment credential is
   unreachable and must not be treated as valid external state.
10. Choose root and node NFT names so their namespaces are disjoint: use a
   non-empty node key prefix, non-empty node keys, and a root key that cannot
   equal `node_key_prefix ++ node_key`. The library assumes this convention
   instead of adding repeated on-chain checks to every operation; agents wiring
   a contract must treat this as a deployment precondition, not as something
   recovered by the helpers later.

These rules preserve the invariant that linked-list NFTs cannot leave the list
spend script/payment credential; they make no claim about UTxOs at that
credential which carry no list-policy asset. Continued anchors are checked by
full address equality; newly minted nodes share the anchor payment credential,
which lets callers choose staking parts for new nodes. If a callback does not
receive a produced element address directly, the corresponding `Output` is an
argument the caller supplied to the helper and can be captured by the callback.
The structural spend gate only requires a list-policy mint/burn to occur; it is
not standalone authorization. The paired minting policy must only accept
structural mint/burns through a matching linked-list mint helper where one is
provided, or through custom validation that proves the same invariants. Example
validators in this repository demonstrate API wiring, but they do not replace
contract-specific authorization or state-transition invariants.

### Governance Validation

Many contracts and protocols on Cardano rely on parameters that need to change
over time, or have treasuries whose withdrawals must be governed by custom
rules. Instead of building a separate voting system, this pattern lets a
contract couple its own proposal lifecycle to Cardano governance.

Each proposal is paired with a CIP-1694 protocol parameter change. The approval
signal is a deliberately chosen change to the execution cost of a rarely used
Plutus builtin. The contract records the current and requested costs when the
proposal is created, then recognizes approval once the requested cost appears
in the ledger settings. Cardano's governance process then decides whether the
parameter change is ratified and enacted.

The on-chain passage proof authenticates the complete live cost model for the
selected Plutus language, not the identity or voting history of the governance
action that enacted it. That complete model is the motion and approval signal:
every enacted action that produces exactly the same model is intentionally
equivalent evidence of ratification. The shared list associates the signal with
its application payload and prevents two active proposals from using the same
builtin. Participants are expected to review and support that association. The
pattern does not claim a separate guarantee about which `GovernanceActionId`
produced the approved model.

This hard assumption is practical only with a socially canonical global list.
A future CIP or comparable agreement can establish that convention among
governance participants. An action submitted outside it would have to increment
or decrement exactly one cost-model entry, preserve every other entry, and do
so without the application purpose recorded in the list. It would then still
need enough DRep support to be ratified and enacted before the listed proposal
expires. The pattern assumes that an otherwise purposeless exact duplicate is
sufficiently unlikely to clear those governance thresholds.

A proposal moves through the following lifecycle:

1. `AddProposal` atomically inserts an active proposal and submits its exactly
   matching Cardano governance action. It records the current and requested
   builtin costs, the stable subject withdrawal script, the proposal-specific
   withdrawal script that will enforce the final action, and an expiry.
2. Before that expiry, the governance action's enactment updates the ledger
   settings and provides
   evidence that the proposal passed. Recording passage removes the proposal
   from the active registry and creates an out-of-list `PassedProposal` output
   carrying an authorization token named `"PASS" || subject_script_hash`.
3. Later, finalization burns that token, returns the output's ADA to the
   proposer, and requires both the stable subject withdrawal encoded after
   `PASS` and the dynamic `required_script_for_final_burn` withdrawal. Subject
   spending endpoints delegate authorization to their recognized stable
   withdrawal script. Minting and burning under other policies remain
   unrestricted.
4. After its expiry, the proposer can remove an active proposal that has not
   been recorded as passed.

The PASS token commits to the stable withdrawal script used by the subject
contract for governance authorization. This is separate from
`required_script_for_final_burn`, which is selected per proposal and enforces
that proposal's final action.

This is an intentional responsibility split. The governance policy constrains
its own PASS burn and proposer reimbursement, while the stable subject and
proposal-specific withdrawal scripts inspect the full transaction and enforce
the application rules they need. Unrelated-policy minting, other transaction
effects, and permissionless submission are therefore not generic governance
policy concerns. Likewise, a reimbursement may exceed the protected UTxO's ADA:
the excess is necessarily funded elsewhere in the transaction and cannot reduce
the proposer's recovery.

The proposal's two script-hash fields are not length-checked when admitted.
Finalization authenticates them by requiring those exact ledger withdrawal
credentials to execute, and the stable subject recognizes the full
`"PASS" || subject_script_hash` token name. A malformed hash can only make its
proposal unable to pass or finalize; it cannot impersonate another script. Any
passed-proposal UTxO it strands remains outside the list and cannot block the
corresponding builtin's position.

Withdrawal quantities are deliberately not part of authorization. The example
scripts permit stake-credential registration but reject delegation
certificates, so they are not intended to accrue delegation rewards. Under
current Cardano ledger rules, any script credential present in `withdrawals`
must execute and any nonzero reward-account balance must be withdrawn in full;
callers cannot select a smaller partial amount. Applications that care about
the destination or use of withdrawn rewards can enforce it in the stable or
required withdrawal script. This boundary must be revisited if the ledger
enables partial withdrawals for Plutus-backed credentials.

The proposal registry allows only one active proposal for each selected Plutus
operation. An `AddProposal` transaction has a validity interval of at most ten
minutes. Its `valid_until` is the interval's upper bound plus the lifespan in
the inline datum of the reference UTxO carrying the `GOV_ACTION_LIFESPAN` NFT.
That lifespan is trusted configuration. In the example, the
`governance_parameters` validator mints the NFT once using its bootstrap nonce,
and a configured threshold of distinct authorized signers controls every update
to its integer datum. The governance validator authenticates that UTxO but does
not derive or bound the lifespan. Its baseline must equal the current
governance-action ratification period plus one epoch for enactment, observation,
and minting the `PassedProposal`: a six-epoch ratification period therefore
requires a seven-epoch lifespan. Any assumed delaying-action extension requires
additional allowance. Finalization itself may happen later.

Transaction and script-data digest equality provide the broad authentication
surface used by this pattern. Reconstructing `Transaction.id` binds the complete
transaction body byte-for-byte, including opaque CBOR fragments supplied for
context-omitted fields; reconstructing the script-data hash binds redeemers,
budgets, and language views. The ledger has already checked the syntax and
ledger semantics of those committed bytes. Opaque fields only need additional
decoding when an integrating application assigns them an independent semantic
requirement.

See the generated
[governance validation module documentation](https://anastasia-labs.github.io/aiken-design-patterns/aiken_design_patterns/governance_validation.html)
for the full API and transaction requirements.

## License

[MIT license](./LICENSE):

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
