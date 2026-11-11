import { randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Network } from "./network.ts";

export type TransactionRecord = {
  scope: string; name: string; hash: string; cbor: string;
  status: "signed" | "submitting" | "submitted" | "confirmed" | "stopped";
  signedAt: string; submittedAt?: string; includedAt?: string; confirmedAt?: string;
  confirmation?: unknown; error?: string;
};

export class Artifacts {
  readonly directory: string;
  readonly records: TransactionRecord[] = [];
  #redact: (text: string) => string;
  constructor(root: string, network: Network, redact = (text: string) => text) {
    this.directory = join(root, network, `${new Date().toISOString().replaceAll(":", "-")}-${randomUUID()}`);
    this.#redact = redact;
    mkdirSync(this.directory, { recursive: true });
  }
  write(path: string, value: unknown) {
    const target = join(this.directory, path);
    mkdirSync(join(target, ".."), { recursive: true });
    const text = JSON.stringify(value, (_, v: unknown) => typeof v === "bigint" ? v.toString()
      : typeof v === "string" ? this.#redact(v) : v, 2);
    writeFileSync(`${target}.tmp`, `${text}\n`);
    renameSync(`${target}.tmp`, target);
  }
  report(scope: string, changes: Record<string, unknown>) {
    const path = join(scope, "report.json");
    const previous = existsSync(join(this.directory, path)) ? JSON.parse(readFileSync(join(this.directory, path), "utf8")) : {};
    this.write(path, { ...previous, ...changes });
  }
  signed(scope: string, name: string, cbor: string, hash: string) {
    const directory = join(this.directory, scope);
    mkdirSync(directory, { recursive: true });
    writeFileSync(join(directory, `${name}.cbor`), `${cbor}\n`);
    writeFileSync(join(directory, `${name}.hash`), `${hash}\n`);
    const record: TransactionRecord = { scope, name, cbor, hash, status: "signed", signedAt: new Date().toISOString() };
    this.records.push(record);
    this.flush(record);
    return record;
  }
  flush(record: TransactionRecord) {
    const scoped = this.records.filter((r) => r.scope === record.scope);
    for (const [scope, records] of [["", this.records], [record.scope, scoped]] as const) {
      this.write(join(scope, "transactions.json"), records.map(({ cbor }) => ({ cbor })));
      this.write(join(scope, "transaction-status.json"), records.map(({ cbor: _, ...status }) => status));
    }
  }
}
