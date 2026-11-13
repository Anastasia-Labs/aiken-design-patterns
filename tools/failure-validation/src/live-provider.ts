import { Blockfrost, type OutRef, type RewardAccountState, type RewardAddress, type UTxO } from "@lucid-evolution/lucid";

export class LiveProvider extends Blockfrost {
  // Lucid 0.6.2 maps Blockfrost's `active` delegation flag to `registered`.
  // Those differ for registered accounts that are not actively delegated.
  override async getRewardAccount(rewardAddress: RewardAddress): Promise<RewardAccountState> {
    const response = await fetch(`${this.url}/accounts/${rewardAddress}`, {
      headers: { project_id: this.projectId },
    });
    if (response.status === 404) return { registered: false, poolId: null, rewards: 0n };
    if (!response.ok) {
      throw new Error(`Could not fetch reward account from Blockfrost. Received status code: ${response.status}`);
    }
    const account = await response.json() as {
      registered?: unknown;
      pool_id?: unknown;
      withdrawable_amount?: unknown;
    };
    if (typeof account.registered !== "boolean" || typeof account.withdrawable_amount !== "string") {
      throw new Error("Blockfrost returned an incomplete reward account state.");
    }
    return {
      registered: account.registered,
      poolId: typeof account.pool_id === "string" ? account.pool_id : null,
      rewards: BigInt(account.withdrawable_amount),
    };
  }

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
