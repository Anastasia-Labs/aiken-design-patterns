import { Blockfrost, type OutRef, type UTxO } from "@lucid-evolution/lucid";

export class LiveProvider extends Blockfrost {
  // Blockfrost's out-ref endpoint can return stale consumed_by_tx data. Use it
  // only to discover an address, then prove spendability with current UTxOs.
  async currentUtxosByOutRef(refs: OutRef[], knownAddresses: string[] = []): Promise<UTxO[]> {
    const historical = await super.getUtxosByOutRef(refs);
    const addresses = new Set([...knownAddresses, ...historical.map((u) => u.address)]);
    const current = (await Promise.all([...addresses].map((address) => this.getUtxos(address)))).flat();
    return current.filter((u) => refs.some((ref) => ref.txHash === u.txHash && ref.outputIndex === u.outputIndex));
  }

  override getUtxosByOutRef(refs: OutRef[]): Promise<UTxO[]> {
    return this.currentUtxosByOutRef(refs);
  }
}
