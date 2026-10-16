//// # Failure validation
////
//// This module records a design for minting evidence that a small withdrawal
//// validator failed on a particular redeemer. The withdrawal isolates a single
//// builtin call. Accepted failure includes a crash, a `False` result, or
//// exhaustion of the withdrawal's prescribed execution budget.
////
//// The proof authenticates the failed transaction and checks the conditions
//// under which its spending validator is expected to succeed. Attribution to
//// the withdrawal relies on the configured spending allowance being sufficient.
////
//// ## Two-transaction proof
////
//// The producing transaction has exactly two redeemers, in ledger order:
//// `Spend`, followed by `Withdraw`. It has exactly one withdrawal, whose script
//// credential identifies the intended builtin validator. The spending validator
//// is a known, small script that checks this shape and the withdrawal's identity.
////
//// The producing transaction is accepted with `isValid = false` after phase-2
//// failure. Its collateral inputs are consumed and its collateral-return output
//// is created. Its ordinary outputs are not created. Phase-1 validation must
//// still succeed; an outright rejected transaction provides no output to use as
//// failure evidence.
////
//// A later proof-minting transaction consumes that collateral return. The proof
//// selects an input by its index in the minting transaction's actual inputs,
//// then reconstructs the transaction that produced it. Hashing the reconstructed
//// body must reproduce the transaction ID in the selected input's output
//// reference. Its output index must equal the reconstructed ordinary-output
//// count: ordinary outputs occupy indices below that count, while collateral
//// return occupies the next index. Together, the authenticated body and the
//// existence of this input establish that the producing transaction failed.
////
//// The input's position in the minting transaction and its output index in the
//// producing transaction are separate indices with separate roles in the proof.
////
//// ## Reconstructing authenticated evidence
////
//// Reconstruction follows the governance-validation module's transaction-body
//// and script-data-hash authentication, reusing its CBOR serialization machinery
//// wherever applicable. The witnesses must reproduce the committed bytes under
//// the supported serialization profile. Transaction-ID equality authenticates
//// those body bytes under the hash's collision resistance.
////
//// Reconstructing the script-data hash also authenticates the complete redeemer
//// collection, including its ledger pointers, redeemer data, execution budgets,
//// and the cost models in its language views. The proof must bind that hash into
//// the reconstructed body. Supplying two claimed redeemers without authenticating
//// the complete collection would not establish the required transaction shape.
////
//// The mint checks the two-redeemer shape, the sole withdrawal credential, and
//// the association of each redeemer with its intended purpose. For the example
//// spending validator, the spending redeemer repeats the withdrawal script hash;
//// it must agree with both the sole withdrawal and the parameter of the known
//// spending-script instance. These checks establish the spending validator's
//// logical acceptance conditions at proof minting.
////
//// The spending-script identity also requires authenticating the output that
//// the producing transaction attempted to spend. Its body contains that output's
//// reference; the address and other resolved output contents belong to the
//// referenced output's own producing transaction. For example, the proof-minting
//// transaction can include the original, still-unspent output as a reference
//// input, match its reference to the reconstructed spending purpose, and check
//// its actual payment script hash. Resolved output contents supplied as witness
//// data require their own authentication before they can establish script identity.
////
//// ## Withdrawal redeemer validation
////
//// The reconstructed withdrawal redeemer is available to the minting validator.
//// The withdrawal can accept raw `Data`, and the mint checks the structure and
//// any application-specific preconditions needed to make the observed failure
//// meaningful for the intended builtin operation.
////
//// Raw `Data` avoids an automatic custom-type decoding requirement at the
//// withdrawal boundary. Preparing arguments for a builtin can still involve
//// extraction or conversion operations. The mint's checks must rule out any
//// failures in that preparation which the application does not intend to count.
//// A crash or `False` result from the intended operation is valid failure
//// evidence. Exhaustion of the withdrawal's full prescribed allowance is also
//// an accepted outcome; the proof does not need to distinguish these causes.
////
//// The known withdrawal script must correctly execute the intended operation
//// under the supported execution rules. Its wrapper and handling of ordinary
//// results must agree with the failure conditions accepted by the mint.
////
//// ## Execution-budget allocation
////
//// Generation measures the spending validator's CPU and memory costs and
//// doubles the estimates to choose a fixed spending allowance. The mint requires
//// the producing transaction's spending redeemer to declare exactly that pair.
//// The withdrawal receives the remainder of the maximum transaction budget,
//// independently for each resource:
////
//// ```text
//// withdrawal_cpu = maximum_transaction_cpu - fixed_spending_cpu
//// withdrawal_memory = maximum_transaction_memory - fixed_spending_memory
//// ```
////
//// The mint verifies both allocations through the reconstructed script-data
//// hash. The two declared allowances together consume the applicable transaction
//// maximum for each resource. The allocation must be feasible under those limits.
////
//// The doubled spending estimate is an accepted engineering compromise. The
//// design assumes it suffices for the authenticated spending script, supported
//// transaction shapes, and applicable cost model and execution rules. This
//// empirical margin does not establish a worst-case upper bound. A spending
//// failure within that allowance would invalidate attribution to the withdrawal.
////
//// Cost models describe the costs of operations. The maximum transaction CPU
//// and memory allowances are separate protocol parameters and cannot be recovered
//// from the cost-model array. The proof therefore needs trustworthy maximum
//// budgets applicable when the failed transaction was accepted. These may differ
//// from the limits in force when the proof is minted. The mechanism supplying
//// and authenticating those maxima is left unspecified by this design.
////
//// The ledger enforces the transaction-wide sum of declared execution budgets:
//// https://github.com/IntersectMBO/cardano-ledger/blob/master/eras/alonzo/impl/src/Cardano/Ledger/Alonzo/Rules/Utxo.hs
////
//// ## Resulting guarantee
////
//// With the intended scripts authenticated, the redeemer and transaction checks
//// satisfied, and the spending allowance sufficient, the collateral-return proof
//// establishes that the intended withdrawal failed on the authenticated redeemer
//// under the prescribed allocation. The withdrawal receives the maximum budget
//// remaining after the fixed spending allowance. Crashes, `False` results, and
//// exhaustion of that remaining budget all qualify as failure for this pattern.
