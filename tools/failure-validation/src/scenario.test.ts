import assert from "node:assert/strict";
import { before, describe, test } from "node:test";
import { CML, Constr, Data, fromHex, sortUTxOs, toUnit } from "@lucid-evolution/lucid";
import { Cbor, CborArray, CborMap, CborUInt } from "@harmoniclabs/cbor";
import { CardanoInfo } from "scalus";
import { buildValidators, type Validators } from "./blueprint.ts";
import { ARGUMENT_MODES, parseBuiltins } from "./builtins.ts";
import { assertProofRejected, assertScriptRejected } from "./test-support.ts";
import { buildProofMint, parametersDatum, prepareScenario, readParameters, runScenario, submitFailure, updateParameters } from "./scenario.ts";
import { inputReferences, minimumCollateral, minimumFee, outRef, outRefData } from "./transactions.ts";
import { ordinaryFunding } from "./runtime.ts";
import { toScalusUtxo } from "./scalus-provider.ts";

// RFC 8032 section 7.1, test 1: a valid signature of the empty message.
const PUBLIC_KEY = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const SIGNATURE = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
const builtin = parseBuiltins(
  ["verify_ed25519_signature(ByteArray, ByteArray, ByteArray) -> Bool"],
  [
    `verify_ed25519_signature/wrong-message|false|${Data.to([PUBLIC_KEY, "01", SIGNATURE])}`,
    `verify_ed25519_signature/valid|success|${Data.to([PUBLIC_KEY, "", SIGNATURE])}`,
  ],
)[0]!;
const failureCase = builtin.cases[0]!;
const successCase = builtin.cases[1]!;

describe("withdrawal evidence and live failure parameters", () => {
  let scripts: Validators;
  before(async () => { scripts = await buildValidators(builtin); });

  for (const mode of ARGUMENT_MODES) describe(mode, () => {
    test("a failed withdrawal at the exact minimum fee mints one authenticated proof", async () => {
      const { report, transactions } = await runScenario(scripts, failureCase, mode);
      assert(report.outcome !== "success");
      assert.deepEqual(report.invocation.arguments, [PUBLIC_KEY, "01", SIGNATURE]);
      assert.equal(report.validation.withdrawal.code, "SCRIPT_FAILURE");
      assert.equal(report.validation.validFlagTrueRejected, "ScriptFailure");
      assert.equal(report.validation.invalidFlagAccepted, true);
      assert.equal(report.collateral.return.outputIndex, 0);
      assert.equal(report.nft.assetName, report.transactions.failed);
      assert.equal(report.nft.quantity, 1n);
      const protocol = CardanoInfo.preview().protocolParams;
      assert.deepEqual(report.validation.withdrawal.declared, { memory: protocol.maxTxExecutionMemory, steps: protocol.maxTxExecutionSteps });
      const transaction = CML.Transaction.from_cbor_hex(transactions["04-failed-withdrawal"]!);
      const body = transaction.body();
      const witnesses = transaction.witness_set();
      const redeemers = witnesses.redeemers()!;
      const entries = redeemers.to_flat_format();
      const entry = entries.get(0);
      const data = entry.data();
      const units = entry.ex_units();
      try {
        assert.equal(transaction.is_valid(), false);
        assert.equal(entries.len(), 1);
        assert.equal(entry.tag(), CML.RedeemerTag.Reward);
        assert.equal(entry.index(), 0n);
        assert.deepEqual(Data.from(data.to_cbor_hex()), new Constr(mode === "direct" ? 0 : 1,
          [mode === "direct" ? Data.from(failureCase.arguments) : report.invocation.argumentIndexes.map(BigInt)]));
        assert.equal(data.to_cbor_hex(), data.to_canonical_cbor_hex());
        assert.equal(units.mem(), protocol.maxTxExecutionMemory);
        assert.equal(units.steps(), protocol.maxTxExecutionSteps);
        assert.equal(witnesses.plutus_datums(), undefined);
        assert.equal(witnesses.plutus_v3_scripts(), undefined);
        const decoded = Cbor.parse(body.to_cbor_bytes(), { keepRef: true });
        assert(decoded instanceof CborMap);
        const outputs = decoded.map.find(({ k }) => k instanceof CborUInt && k.num === 1n)!.v;
        assert(outputs instanceof CborArray && outputs.subCborRef);
        assert.equal(Buffer.from(outputs.subCborRef.toBuffer()).toString("hex"), "80");
        assert.equal(body.fee(), report.fee.lovelace);
        assert.equal(body.total_collateral(), minimumCollateral(body.fee(), protocol.collateralPercentage));
        assert.equal(report.collateral.return.lovelace + report.collateral.chargedLovelace, report.collateral.inputLovelace);
      } finally {
        units.free(); data.free(); entry.free(); entries.free(); redeemers.free(); witnesses.free(); body.free(); transaction.free();
      }
    });

    test("success consumes precisely funded ordinary input without creating any outputs or evidence", async () => {
      const scenario = await prepareScenario(scripts, successCase, mode);
      const { withdrawal, fundingInput, parameters, provider, emulator, failureCollateral } = scenario;
      assert(emulator);
      const core = withdrawal.toTransaction();
      const body = core.body();
      const outputs = body.outputs();
      try {
        assert.equal(outputs.len(), 0);
        assert.equal(body.fee(), minimumFee(core, parameters, [scripts.withdrawal]));
        assert.equal(body.fee(), fundingInput.assets.lovelace);
        assert.deepEqual(emulator.evaluateTx(fromHex(withdrawal.toCBOR())).map(({ tag, index }) => [tag, index]), [["Reward", 0]]);
        const hash = await withdrawal.submit();
        assert.deepEqual(await provider.getUtxosByOutRef([fundingInput]), []);
        assert.deepEqual(await provider.getUtxosByOutRef([{ txHash: hash, outputIndex: 0 }]), []);
        assert.deepEqual(await provider.getUtxosByOutRef([failureCollateral]), [failureCollateral]);
        assert.deepEqual(await provider.getUtxoByUnit(scenario.parametersUnit), scenario.parametersInput);
      } finally { outputs.free(); body.free(); }
    });

    const mutations: { name: string; index: number; change: (value: Data) => Data }[] = [
      { name: "fee", index: 0, change: (value) => (value as bigint) + 1n },
      { name: "ordinary inputs", index: 1, change: () => [outRefData({ txHash: "ab".repeat(32), outputIndex: 0 })] },
      { name: "builtin redeemer", index: 2, change: () => new Constr(0, [[PUBLIC_KEY, "02", SIGNATURE]]) },
      { name: "argument mode", index: 2, change: (value) => new Constr((value as Constr<Data>).index === 0 ? 1 : 0, [[]]) },
      { name: "collateral input", index: 3, change: () => outRefData({ txHash: "cd".repeat(32), outputIndex: 0 }) },
      { name: "total collateral", index: 4, change: (value) => (value as bigint) + 1n },
      { name: "reference inputs", index: 5, change: () => [] },
      { name: "redeemer encoding", index: 6, change: (value) => new Constr((value as Constr<Data>).index === 0 ? 1 : 0, []) },
      { name: "cost model", index: 7, change: () => "80" },
    ];
    for (const { name, index, change } of mutations) {
      test(`proof rejects tampered ${name}`, async () => {
        const scenario = await prepareScenario(scripts, failureCase, mode);
        const evidence = await submitFailure(scenario);
        const fields = [...evidence.witness.fields];
        fields[index] = change(fields[index]!);
        await assertProofRejected("SCRIPT_FAILURE", scenario, evidence, new Constr(0, fields));
      });
    }

    test("proof does not depend on the original ordinary input remaining unspent", async () => {
      const scenario = await prepareScenario(scripts, failureCase, mode);
      const evidence = await submitFailure(scenario);
      const transfer = await scenario.lucid.newTx().collectFrom([scenario.fundingInput]).complete({ coinSelection: false });
      await (await transfer.sign.withWallet().complete()).submit();
      assert.deepEqual(await scenario.provider.getUtxosByOutRef([scenario.fundingInput]), []);
      const mint = await buildProofMint(scenario, evidence);
      const body = mint.toTransaction().body();
      try {
        assert.deepEqual(inputReferences(body.reference_inputs()), sortUTxOs([scenario.mintReference, scenario.parametersInput, ...scenario.argumentReferences], "Canonical").map(outRef));
      } finally { body.free(); }
      await (await mint.sign.withWallet().complete()).submit();
      assert.equal((await scenario.provider.getUtxoByUnit(toUnit(scenario.policyId, evidence.failedHash))).assets[toUnit(scenario.policyId, evidence.failedHash)], 1n);
      assert.deepEqual(await scenario.provider.getUtxosByOutRef([evidence.returnUtxo]), []);
    });

    test("proof rejects a selected reference without the configuration NFT", async () => {
      const scenario = await prepareScenario(scripts, failureCase, mode);
      const evidence = await submitFailure(scenario);
      const funding = (await scenario.provider.getUtxos(scenario.walletAddress))
        .find((u) => u.assets.lovelace! > 100_000_000n);
      assert(funding);
      const fake = await scenario.lucid.newTx().collectFrom([funding])
        .pay.ToAddressWithData(scenario.walletAddress, { kind: "inline", value: parametersDatum(scenario.budget) }, { lovelace: 5_000_000n })
        .complete({ coinSelection: false });
      const hash = await (await fake.sign.withWallet().complete()).submit();
      const [unauthenticated] = await scenario.provider.getUtxosByOutRef([{ txHash: hash, outputIndex: 0 }]);
      assert(unauthenticated);
      assert.deepEqual(readParameters(unauthenticated), scenario.budget);
      await assertProofRejected("SCRIPT_FAILURE", scenario, evidence, evidence.witness, unauthenticated);
    });

    test("bootstrap consumes its nonce and creates the only parameters NFT without multisig required signers", async () => {
      const scenario = await prepareScenario(scripts, failureCase, mode);
      assert.deepEqual(await scenario.provider.getUtxosByOutRef([scenario.nonce]), []);
      assert(scenario.emulator);
      const nfts = scenario.emulator.getUtxos().flatMap((u) => u.value.assets).filter((a) => a.policyId === scenario.parametersPolicy);
      assert.equal(nfts.length, 1);
      assert.equal(nfts[0]!.quantity, 1n);
      assert.deepEqual(readParameters(scenario.parametersInput), scenario.budget);
      const setup = CML.Transaction.from_cbor_hex(scenario.transactions["02-parameters-registration"]!);
      const body = setup.body();
      try {
        assert.equal(body.required_signers(), undefined);
        assert(inputReferences(body.inputs()).some((ref) => ref.txHash === scenario.nonce.txHash && ref.outputIndex === scenario.nonce.outputIndex));
      } finally { body.free(); setup.free(); }
    });

    test("authorized budget changes reject earlier mismatched evidence; restoration makes it eligible again", async () => {
      const scenario = await prepareScenario(scripts, failureCase, mode);
      const evidence = await submitFailure(scenario);
      const updatedBudget = { ...scenario.budget, memory: scenario.budget.memory - 1n };
      const updated = await updateParameters(scenario, updatedBudget, [1, 2]);
      assert.notDeepEqual(outRef(updated), outRef(scenario.parametersInput));
      await assertProofRejected("SCRIPT_FAILURE", scenario, evidence);
      const restored = await updateParameters(scenario, scenario.budget);
      const mint = await buildProofMint(scenario, evidence);
      const body = mint.toTransaction().body();
      try {
        assert.deepEqual(inputReferences(body.reference_inputs()), sortUTxOs([scenario.mintReference, restored, ...scenario.argumentReferences], "Canonical").map(outRef));
      } finally { body.free(); }
      await (await mint.sign.withWallet().complete()).submit();
      assert.deepEqual(await scenario.provider.getUtxoByUnit(scenario.parametersUnit), restored);
    });

    for (const signerIndices of [[], [0], [1]]) {
      test(`parameters update with ${signerIndices.length} authorized signer(s) is rejected without changing the ledger (${signerIndices})`, async () => {
        const scenario = await prepareScenario(scripts, failureCase, mode);
        await assertScriptRejected(scenario, scenario.parametersPolicy, "Spend", "SCRIPT_FAILURE", () =>
          updateParameters(scenario, { ...scenario.budget, steps: scenario.budget.steps - 1n }, signerIndices));
        assert.deepEqual(await scenario.provider.getUtxoByUnit(scenario.parametersUnit), scenario.parametersInput);
      });
    }
  });

  for (const mutation of ["missing", "substituted"] as const) {
    test(`referenced proof rejects ${mutation} original argument references`, async () => {
      const scenario = await prepareScenario(scripts, failureCase, "referenced");
      const evidence = await submitFailure(scenario);
      const argumentReferences = [...scenario.argumentReferences];
      if (mutation === "missing") argumentReferences.shift();
      else {
        const original = argumentReferences[0]!;
        const tx = await scenario.lucid.newTx()
          .pay.ToAddressWithData(scenario.referenceAddress, { kind: "inline", value: original.datum! }, original.assets)
          .complete({ presetWalletInputs: await ordinaryFunding(scenario.runtime) });
        const hash = await (await tx.sign.withWallet().complete()).submit();
        const [replacement] = await scenario.provider.getUtxosByOutRef([{ txHash: hash, outputIndex: 0 }]);
        assert(replacement);
        assert.equal(replacement.datum, original.datum);
        argumentReferences[0] = replacement;
      }
      await assertProofRejected("BUILTIN_FAILURE", { ...scenario, argumentReferences }, evidence);
    });
  }

  test("referenced proof resolves authenticated indexes against original input order", async () => {
    const scenario = await prepareScenario(scripts, failureCase, "referenced");
    const evidence = await submitFailure(scenario);
    // An earlier reference-script UTxO shifts the proof's argument positions.
    const mintReference = { ...scenario.mintReference, txHash: "00".repeat(32), outputIndex: 2 };
    assert(scenario.emulator);
    scenario.emulator.addUtxo(toScalusUtxo(mintReference));
    const proofScenario = { ...scenario, mintReference };
    const mint = await buildProofMint(proofScenario, evidence);
    const transaction = CML.Transaction.from_cbor_hex(mint.toCBOR());
    const body = transaction.body();
    try {
      const references = sortUTxOs([mintReference, scenario.parametersInput, ...scenario.argumentReferences], "Canonical");
      assert.deepEqual(inputReferences(body.reference_inputs()), references.map(outRef));
      const proofIndexes = scenario.argumentReferences.map((argument) => references.findIndex((reference) =>
        reference.txHash === argument.txHash && reference.outputIndex === argument.outputIndex));
      assert.notDeepEqual(proofIndexes, scenario.argumentIndexes);
      assert.deepEqual(evidence.witness.fields[2], new Constr(1, [scenario.argumentIndexes.map(BigInt)]));
      const changed = [...evidence.witness.fields];
      changed[2] = new Constr(1, [[...scenario.argumentIndexes].reverse().map(BigInt)]);
      await assertProofRejected("SCRIPT_FAILURE", proofScenario, evidence, new Constr(0, changed));
    } finally { body.free(); transaction.free(); }
    await (await mint.sign.withWallet().complete()).submit();
    assert.deepEqual(sortUTxOs(await scenario.provider.getUtxosByOutRef(scenario.argumentReferences), "Canonical"),
      sortUTxOs(scenario.argumentReferences, "Canonical"));
  });
});
