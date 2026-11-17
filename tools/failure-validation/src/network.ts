import { loadEnvFile } from "node:process";
import { fileURLToPath } from "node:url";
import { walletFromSeed } from "@lucid-evolution/lucid";

export function loadEnvironment(path = fileURLToPath(new URL("../.env", import.meta.url))) {
  try { loadEnvFile(path); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw new Error("Could not load the failure-validation .env file.");
  }
}

export const NETWORKS = ["Custom", "Mainnet", "Preprod", "Preview"] as const;
export type Network = typeof NETWORKS[number];
export type LiveNetwork = Exclude<Network, "Custom">;
export const BLOCKFROST_URLS: Record<LiveNetwork, string> = {
  Mainnet: "https://cardano-mainnet.blockfrost.io/api/v0",
  Preprod: "https://cardano-preprod.blockfrost.io/api/v0",
  Preview: "https://cardano-preview.blockfrost.io/api/v0",
};
export type NetworkConfig = { network: "Custom" } | { network: LiveNetwork; apiKey: string; seed: string };

export function readNetworkConfig(env: NodeJS.ProcessEnv = process.env): NetworkConfig {
  const network = env.NETWORK ?? "Custom";
  if (!NETWORKS.includes(network as Network)) throw new Error("NETWORK must be Custom, Mainnet, Preprod, or Preview.");
  if (network === "Custom") return { network };
  const apiKey = env.BLOCKFROST_API_KEY?.trim();
  const seed = env.WALLET_SEED?.trim();
  if (!apiKey) throw new Error("BLOCKFROST_API_KEY is required for live networks.");
  if (!seed) throw new Error("WALLET_SEED is required for live networks.");
  try { walletFromSeed(seed, { network: network as LiveNetwork, accountIndex: 0, addressType: "Base" }); }
  catch { throw new Error("WALLET_SEED must be a valid mnemonic."); }
  return { network: network as LiveNetwork, apiKey, seed };
}

export function redactSecrets(env: NodeJS.ProcessEnv = process.env) {
  const secrets = [env.BLOCKFROST_API_KEY, env.WALLET_SEED].flatMap((s) => s ? [s, s.trim()] : []).filter(Boolean);
  return (message: string) => secrets.reduce((text, secret) => text.replaceAll(secret, "[redacted]"), message);
}
