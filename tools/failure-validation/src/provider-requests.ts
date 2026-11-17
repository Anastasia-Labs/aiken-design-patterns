import { setTimeout as delay } from "node:timers/promises";

const TRANSIENT_STATUSES = new Set([408, 500, 502, 503, 504]);
const CONNECTION_CODES = new Set([
  "ECONNRESET", "ECONNREFUSED", "EHOSTUNREACH", "ENETUNREACH", "ENOTFOUND", "EAI_AGAIN", "ETIMEDOUT",
  "UND_ERR_CONNECT_TIMEOUT", "UND_ERR_HEADERS_TIMEOUT", "UND_ERR_BODY_TIMEOUT", "UND_ERR_SOCKET",
]);

function transientConnectionError(error: unknown) {
  const pending = [error];
  const visited = new Set<unknown>();
  const codes: string[] = [];
  let networkError = false;
  while (pending.length) {
    const current = pending.pop();
    if (!current || typeof current !== "object" || visited.has(current)) continue;
    visited.add(current);
    const issue = current as { name?: unknown; message?: unknown; code?: unknown; cause?: unknown; errors?: unknown };
    if (typeof issue.code === "string") codes.push(issue.code);
    networkError ||= issue.name === "TimeoutError" || (issue.name === "TypeError"
      && typeof issue.message === "string" && /fetch failed|terminated|network error/i.test(issue.message));
    pending.push(issue.cause);
    if (Array.isArray(issue.errors)) pending.push(...issue.errors);
  }
  return codes.length ? codes.some((code) => CONNECTION_CODES.has(code)) : networkError;
}

// Limit actual HTTP requests, including retries, independently of UTxO counts.
export class ProviderRequests {
  #active = 0;
  #queue: (() => void)[] = [];
  #tokens = 100;
  #updated: number;
  readonly now: () => number;
  readonly sleep: (ms: number, signal?: AbortSignal) => Promise<unknown>;
  readonly random: () => number;
  constructor(
    now = Date.now,
    sleep: (ms: number, signal?: AbortSignal) => Promise<unknown> = (ms, signal) => delay(ms, undefined, { signal }),
    random = Math.random,
  ) { this.now = now; this.sleep = sleep; this.random = random; this.#updated = now(); }

  async #acquire(signal?: AbortSignal) {
    signal?.throwIfAborted();
    if (this.#active < 4) { this.#active++; return; }
    await new Promise<void>((resolve, reject) => {
      const ready = () => { signal?.removeEventListener("abort", abort); resolve(); };
      const abort = () => {
        this.#queue.splice(this.#queue.indexOf(ready), 1);
        reject(signal!.reason);
      };
      this.#queue.push(ready);
      signal?.addEventListener("abort", abort, { once: true });
    });
  }
  #release() {
    const next = this.#queue.shift();
    if (next) next();
    else this.#active--;
  }
  async #token(signal?: AbortSignal) {
    while (true) {
      signal?.throwIfAborted();
      const now = this.now();
      this.#tokens = Math.min(100, this.#tokens + Math.max(0, now - this.#updated) / 100);
      this.#updated = now;
      if (this.#tokens >= 1) { this.#tokens--; return; }
      await this.sleep(Math.ceil((1 - this.#tokens) * 100), signal);
    }
  }
  async request(url: string, init: RequestInit = {}): Promise<Response> {
    const signal = init.signal ?? undefined;
    const method = (init.method ?? "GET").toUpperCase();
    const readOnly = method === "GET" || method === "HEAD";
    for (let attempt = 0; ; attempt++) {
      await this.#acquire(signal);
      let response: Response | undefined;
      try {
        await this.#token(signal);
        signal?.throwIfAborted();
        const received = await fetch(url, { ...init, signal: signal
          ? AbortSignal.any([signal, AbortSignal.timeout(30_000)]) : AbortSignal.timeout(30_000) });
        // Keep the request slot until the body has arrived, too.
        const body = await received.arrayBuffer();
        response = new Response([204, 205, 304].includes(received.status) ? null : body,
          { status: received.status, statusText: received.statusText, headers: received.headers });
      } catch (error) {
        signal?.throwIfAborted();
        // A failed POST may already have been accepted. Its saved bytes need reconciliation.
        if (!readOnly || !transientConnectionError(error)) throw error;
        if (attempt === 3) throw new Error(
          `Connection failed for ${method} ${new URL(url).pathname} after ${attempt + 1} attempts.`, { cause: error });
      } finally { this.#release(); }
      // A 429 explicitly refuses the request; other HTTP retries are read-only.
      if (response && (attempt === 3 || (response.status !== 429 && !(readOnly && TRANSIENT_STATUSES.has(response.status))))) return response;
      const header = response?.headers.get("retry-after") ?? null;
      const seconds = header === null || !header.trim() ? NaN : Number(header);
      const date = header === null ? NaN : Date.parse(header);
      const wait = Number.isFinite(seconds) ? seconds * 1_000
        : Number.isFinite(date) ? date - this.now() : Math.round(1_000 * 2 ** attempt * (0.75 + this.random() / 2));
      await this.sleep(Math.max(0, wait), signal);
    }
  }
}
