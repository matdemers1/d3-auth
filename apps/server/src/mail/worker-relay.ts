import type { MailDriver, MailMessage } from './adapter.js';

// Cloudflare cannot be called directly from a container: `send_email` is a Workers binding, so a
// tiny Worker relays for us (REQ-106). This driver is the client side of that: POST /send with a
// bearer shared secret.

export interface WorkerRelayOptions {
  url: string;
  secret: string;
  from: string;
  /** Overridable so tests do not reach the network. */
  fetch?: typeof fetch;
  timeoutMs?: number;
}

export function workerRelayDriver(options: WorkerRelayOptions): MailDriver {
  const doFetch = options.fetch ?? fetch;
  const timeoutMs = options.timeoutMs ?? 10_000;

  return {
    name: 'worker',
    async send(message: MailMessage) {
      const res = await doFetch(options.url, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${options.secret}` },
        body: JSON.stringify({ from: options.from, ...message }),
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (!res.ok) {
        const detail = (await res.text().catch(() => '')).slice(0, 200);
        throw new Error(`mail relay answered ${String(res.status)}${detail ? `: ${detail}` : ''}`);
      }
    },
  };
}
