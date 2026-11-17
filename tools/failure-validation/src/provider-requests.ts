import { setTimeout as delay } from "node:timers/promises";

// Limit actual HTTP requests, including retries, independently of UTxO counts.
export class ProviderRequests {
  #active = 0;
  #queue: (() => void)[] = [];
  #tokens = 100;
  #updated: number;
  readonly now: () => number;
  readonly sleep: (ms: number, signal?: AbortSignal) => Promise<unknown>;
  constructor(
    now = Date.now,
    sleep: (ms: number, signal?: AbortSignal) => Promise<unknown> = (ms, signal) => delay(ms, undefined, { signal }),
  ) { this.now = now; this.sleep = sleep; this.#updated = now(); }

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
    for (let attempt = 0; ; attempt++) {
      await this.#acquire(signal);
      let response: Response;
      try {
        await this.#token(signal);
        signal?.throwIfAborted();
        const received = await fetch(url, { ...init, signal: signal
          ? AbortSignal.any([signal, AbortSignal.timeout(30_000)]) : AbortSignal.timeout(30_000) });
        // Keep the request slot until the body has arrived, too.
        const body = await received.arrayBuffer();
        response = new Response([204, 205, 304].includes(received.status) ? null : body,
          { status: received.status, statusText: received.statusText, headers: received.headers });
      } finally { this.#release(); }
      // Transport errors and ambiguous submission responses are never retried.
      if (response.status !== 429 || attempt === 3) return response;
      const header = response.headers.get("retry-after");
      const seconds = header === null ? NaN : Number(header);
      const date = header === null ? NaN : Date.parse(header);
      const wait = Number.isFinite(seconds) ? seconds * 1_000
        : Number.isFinite(date) ? date - this.now() : 1_000 * 2 ** attempt;
      await response.arrayBuffer();
      await this.sleep(Math.max(0, wait), signal);
    }
  }
}
