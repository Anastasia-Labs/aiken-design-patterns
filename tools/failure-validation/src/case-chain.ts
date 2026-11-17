import assert from "node:assert/strict";
import { CML, Data, fromHex, toHex, validatorToScriptHash, type OutRef, type ProtocolParameters, type UTxO } from "@lucid-evolution/lucid";
import type { TransactionRecord } from "./artifacts.ts";
import { LiveProvider, type TransactionObservation } from "./live-provider.ts";
import { assertValidity, observeTransaction, recordResources, referenceKey, resourceInventory, restoreResources, takeSnapshot, type Effects, type Runtime } from "./runtime.ts";
import { transactionProjection } from "./transactions.ts";

export type PreparedTransaction = ReturnType<typeof transactionProjection> & { name: string; cbor: string; effects: Effects; dependencies: string[] };
export type CaseChainCheckpoint = {
  transactions: { name: string; hash: string; dependencies: string[]; valid: boolean }[];
  present: UTxO[]; absent: OutRef[]; addresses: string[];
};
export type PreparedCaseChain = Omit<CaseChainCheckpoint, "transactions"> & {
  scope: string; protocol: ProtocolParameters; transactions: PreparedTransaction[]; initial: UTxO[];
};

export function prepareTransaction(name: string, cbor: string, effects: Effects = {}): PreparedTransaction {
  return { name, cbor, effects, dependencies: [], ...transactionProjection(cbor) };
}

export function makeChain(scope: string, protocol: ProtocolParameters, transactions: PreparedTransaction[], initial: UTxO[] = [], protectedOutputs: UTxO[] = []): PreparedCaseChain {
  const present = new Map(protectedOutputs.map((output) => [referenceKey(output), output]));
  const absent = new Map<string, OutRef>();
  const producers = new Map<string, string>();
  for (const transaction of transactions) {
    transaction.dependencies = [...new Set(transaction.required.flatMap((ref) => producers.get(referenceKey(ref)) ?? []))];
    for (const input of transaction.consumed) { present.delete(referenceKey(input)); absent.set(referenceKey(input), input); }
    for (const output of transaction.created) { present.set(referenceKey(output), output); producers.set(referenceKey(output), transaction.hash); }
  }
  return { scope, protocol, transactions, initial, present: [...present.values()], absent: [...absent.values()],
    addresses: [...new Set([...present.values()].map((output) => output.address).concat(transactions.flatMap((tx) => tx.effects.addresses ?? [])))] };
}

export function savedChain(runtime: Runtime, scope: string): PreparedCaseChain | undefined {
  const checkpoint = runtime.artifacts?.manifest?.cases[scope];
  if (!checkpoint?.chain) return undefined;
  assert(checkpoint.protocol, "Missing producing protocol snapshot.");
  const transactions = checkpoint.chain.transactions.map((entry) => {
    const record = runtime.artifacts!.find(scope, entry.name);
    assert(record && record.hash === entry.hash, "Missing saved case transaction.");
    const transaction = prepareTransaction(record.name, record.cbor, record.effects);
    assert.equal(transaction.valid, entry.valid, "Saved transaction validity changed.");
    transaction.dependencies = entry.dependencies;
    return transaction;
  });
  return { ...checkpoint.chain, scope, protocol: checkpoint.protocol, transactions, initial: [] };
}

export function projectSnapshot(runtime: Runtime, transaction: PreparedTransaction) {
  assert(runtime.snapshot, "Missing preparation snapshot.");
  for (const input of transaction.consumed) runtime.snapshot.delete(referenceKey(input));
  for (const output of transaction.created) runtime.snapshot.set(referenceKey(output), output);
}

export function assertOutput(current: UTxO, expected: UTxO) {
  assert.equal(current.address, expected.address, "Run resource address changed.");
  assert.deepEqual(current.assets, expected.assets, "Run resource assets changed.");
  assert.deepEqual(current.datum ? Data.from(current.datum) : undefined, expected.datum ? Data.from(expected.datum) : undefined, "Run resource datum changed.");
  assert.equal(current.datumHash, expected.datumHash, "Run resource datum hash changed.");
  assert.equal(current.scriptRef ? validatorToScriptHash(current.scriptRef) : undefined,
    expected.scriptRef ? validatorToScriptHash(expected.scriptRef) : undefined, "Run resource reference script changed.");
}

function checkDeadline(runtime: Runtime, hash: string, deadline: number) {
  runtime.signal.throwIfAborted();
  if (runtime.now() >= deadline) throw new Error(`Confirmation timed out for ${hash}; check this hash before another run.`);
}
async function poll(runtime: Runtime, hash: string, deadline: number) {
  checkDeadline(runtime, hash, deadline);
  await runtime.sleep(Math.min(3_000, Math.max(1, deadline - runtime.now())));
}
async function inclusion(runtime: Runtime, hash: string, deadline: number, initial?: TransactionObservation): Promise<TransactionObservation> {
  let observed = initial;
  while (true) {
    checkDeadline(runtime, hash, deadline);
    observed ??= await observeTransaction(runtime, hash);
    if (observed.status === "failed") throw new Error(`Transaction ${hash} was rejected.`);
    if (observed.status === "confirmed") return observed;
    await poll(runtime, hash, deadline);
    observed = undefined;
  }
}

function included(record: TransactionRecord | undefined, observed: TransactionObservation) {
  assert(observed.status === "confirmed");
  if (record) { record.includedAt ??= new Date().toISOString(); record.confirmation = observed.confirmation; }
}

export async function executeChain(runtime: Runtime, chain: PreparedCaseChain, journalCase = true) {
  const deadline = runtime.now() + runtime.confirmationTimeout;
  const timeout = AbortSignal.timeout(runtime.confirmationTimeout);
  const provider = runtime.provider instanceof LiveProvider ? runtime.provider : undefined;
  const previousSignal = provider?.requestSignal;
  if (provider) provider.requestSignal = timeout;
  try { return await executePreparedChain(runtime, chain, journalCase, deadline); }
  catch (error) {
    if (timeout.aborted && !runtime.signal.aborted)
      throw new Error(`Confirmation timed out for ${chain.transactions.at(-1)!.hash}; check this hash before another run.`, { cause: error });
    throw error;
  } finally {
    if (provider) { if (previousSignal) provider.requestSignal = previousSignal; else delete provider.requestSignal; }
  }
}

async function executePreparedChain(runtime: Runtime, chain: PreparedCaseChain, journalCase: boolean, deadline: number) {
  runtime.signal.throwIfAborted();
  runtime.scope = chain.scope;
  await restoreResources(runtime);
  const artifacts = runtime.artifacts;
  const inventory = resourceInventory(runtime);
  const addresses = [...chain.addresses, ...Object.values(inventory).filter((resource) => !resource.consumedBy).map((resource) => resource.output.address)];
  const initial = chain.initial.length ? chain.initial : [...(await takeSnapshot(runtime, addresses)).values()];
  delete runtime.snapshot;
  const available = new Map(initial.map((output) => [referenceKey(output), output]));
  const produced = new Set(chain.transactions.flatMap((tx) => tx.created.map(referenceKey)));
  const save = () => {
    for (const transaction of chain.transactions) {
      for (const ref of transaction.required) {
        const key = referenceKey(ref);
        const output = available.get(key);
        if (!produced.has(key) && !inventory[key] && output) inventory[key] = {
          output, role: "ordinary", scope: chain.scope, createdBy: output.txHash, adopted: true, confirmed: true, release: "immediate",
        };
      }
      recordResources(runtime, transaction.name, transaction.cbor, transaction.hash, false);
    }
    if (journalCase) artifacts?.journalChain(chain);
    else for (const tx of chain.transactions) artifacts?.signed(chain.scope, tx.name, tx.cbor, tx.hash, tx.effects);
    artifacts?.saveManifest();
  };
  if (artifacts) artifacts.batch(save); else save();
  let active: TransactionRecord | undefined;
  try {
    // Verify the whole signed case before the first broadcast.
    for (const tx of chain.transactions) {
      active = artifacts?.find(chain.scope, tx.name);
      assert(tx.cbor.length / 2 <= chain.protocol.maxTxSize,
        `${tx.name}: signed transaction is ${tx.cbor.length / 2} bytes; maximum is ${chain.protocol.maxTxSize}.`);
    }
    const observations = new Map<string, TransactionObservation>();
    const pendingAncestors: PreparedTransaction[] = [];
    for (const tx of chain.transactions) {
      checkDeadline(runtime, tx.hash, deadline);
      active = artifacts?.find(chain.scope, tx.name);
      const reopening = !!active && artifacts!.savedAtOpen.has(active.id);
      let observed = reopening ? runtime.observations.get(tx.hash) ?? await observeTransaction(runtime, tx.hash) : undefined;
      runtime.observations.delete(tx.hash);
      if (observed?.status === "failed") throw new Error(`Transaction ${tx.hash} was rejected.`);
      while (observed?.status === "not_found" && !tx.required.every((ref) => available.has(referenceKey(ref)))) {
        // Refresh confirmed inputs on every indexing retry. Accepted pending
        // ancestors remain a separate local projection throughout recovery.
        await poll(runtime, tx.hash, deadline);
        observed = await observeTransaction(runtime, tx.hash);
        if (observed.status !== "not_found") break;
        const current = await takeSnapshot(runtime, addresses);
        available.clear();
        for (const [key, output] of current) available.set(key, output);
        for (const parent of pendingAncestors) {
          for (const input of parent.consumed) available.delete(referenceKey(input));
          for (const output of parent.created) available.set(referenceKey(output), output);
        }
      }
      if (observed?.status === "failed") throw new Error(`Transaction ${tx.hash} was rejected.`);
      if (observed?.status === "confirmed") {
        assertValidity(observed, tx.valid);
        included(active, observed);
        observations.set(tx.hash, observed);
        continue;
      }
      if (observed?.status !== "pending") {
        if (active) { active.status = "submitting"; delete active.error; artifacts!.flush(active); }
        checkDeadline(runtime, tx.hash, deadline);
        if (!tx.valid && runtime.emulator) {
          const invalid = CML.Transaction.from_cbor_hex(tx.cbor);
          const body = invalid.body();
          const witnesses = invalid.witness_set();
          const valid = CML.Transaction.new(body, witnesses, true);
          try {
            const before = toHex(runtime.emulator.getUtxosCbor());
            const rejected = runtime.emulator.submitTx(fromHex(valid.to_cbor_hex()));
            assert.equal(rejected.isSuccess, false);
            assert.equal(rejected.errorRule, "ScriptFailure", rejected.error);
            assert.equal(toHex(runtime.emulator.getUtxosCbor()), before);
          } finally { valid.free(); witnesses.free(); body.free(); invalid.free(); }
        }
        assert.equal(await runtime.provider.submitTx(tx.cbor), tx.hash, "Ambiguous transaction submission response.");
        if (active) { active.status = "submitted"; active.submittedAt = new Date().toISOString(); artifacts!.flush(active); }
        runtime.signal.throwIfAborted();
      }
      // Only the local projection sees pending outputs, including collateral return.
      for (const input of tx.consumed) available.delete(referenceKey(input));
      for (const output of tx.created) available.set(referenceKey(output), output);
      pendingAncestors.push(tx);
    }
    const terminal = chain.transactions.at(-1)!;
    const terminalObservation = observations.get(terminal.hash) ?? await inclusion(runtime, terminal.hash, deadline);
    observations.set(terminal.hash, terminalObservation);
    for (const tx of chain.transactions) {
      const observed = observations.get(tx.hash) ?? await inclusion(runtime, tx.hash, deadline);
      assertValidity(observed, tx.valid);
      observations.set(tx.hash, observed);
      included(artifacts?.find(chain.scope, tx.name), observed);
    }
    artifacts?.saveManifest();
    const current = await verifyEffects(runtime, chain, deadline);
    const confirm = () => {
      for (const tx of chain.transactions) {
        recordResources(runtime, tx.name, tx.cbor, tx.hash, true);
        const record = artifacts?.find(chain.scope, tx.name);
        if (record) {
          record.status = "confirmed"; record.confirmedAt ??= new Date().toISOString(); delete record.error;
          artifacts!.flush(record);
        }
      }
      if (journalCase && artifacts?.manifest) artifacts.case(chain.scope, { stage: "verified" });
    };
    if (artifacts) artifacts.batch(confirm); else confirm();
    if (!journalCase) artifacts?.renderTransactions();
    return current;
  } catch (error) {
    if (active) { active.status = "stopped"; active.error = error instanceof Error ? error.message : "Transaction stopped."; artifacts!.flush(active); }
    artifacts?.renderTransactions();
    throw error;
  }
}

async function verifyEffects(runtime: Runtime, chain: PreparedCaseChain, deadline: number) {
  const consumed = new Set(chain.absent.map(referenceKey));
  const historical = (ref: OutRef) => !!runtime.resources[referenceKey(ref)]?.consumedBy;
  const expected = chain.present.filter((output) => !historical(output));
  const refs = chain.transactions.flatMap((tx) => tx.effects.present ?? []).filter((ref) => !consumed.has(referenceKey(ref)) && !historical(ref));
  const absent = [...chain.absent, ...chain.transactions.flatMap((tx) => tx.effects.absent ?? [])];
  const rewardAddresses = [...new Set(chain.transactions.flatMap((tx) => tx.effects.stakeRegistered ?? []))];
  while (true) {
    checkDeadline(runtime, chain.transactions.at(-1)!.hash, deadline);
    const current = await takeSnapshot(runtime, chain.addresses);
    const registered = await Promise.all(rewardAddresses.map((address) => runtime.provider.getRewardAccount(address)));
    if (expected.every((output) => current.has(referenceKey(output))) && refs.every((ref) => current.has(referenceKey(ref)))
      && absent.every((ref) => !current.has(referenceKey(ref))) && registered.every((account) => account.registered)) {
      for (const output of expected) assertOutput(current.get(referenceKey(output))!, output);
      return current;
    }
    await poll(runtime, chain.transactions.at(-1)!.hash, deadline);
  }
}
