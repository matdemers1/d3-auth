import { EmailMessage } from 'cloudflare:email';
import { createMimeMessage } from 'mimetext';
import { runProbe, type ProbeEnv } from './probe.js';

// The mail relay (REQ-106). Cloudflare can only send through a Worker binding, and D3 Auth is a
// container on someone's shelf — so this Worker is the two-hundred-line bridge between them.
//
// It does exactly one thing: accept POST /send from D3 Auth, authenticated by a shared secret,
// and hand the message to the send_email binding. It stores nothing, logs no message bodies, and
// refuses anything else.

export interface Env extends Partial<Omit<ProbeEnv, 'EMAIL'>> {
  /** The send_email binding, configured in wrangler.toml. */
  EMAIL: { send(message: EmailMessage): Promise<void> };
  /** Shared secret, set with `wrangler secret put RELAY_SECRET`. */
  RELAY_SECRET: string;
  /** Verified sender, e.g. no-reply@no-reply.d3cloud.io */
  DEFAULT_FROM?: string;
}

export interface SendRequest {
  to: string;
  from?: string;
  subject: string;
  text: string;
  html?: string;
}

const json = (status: number, body: Record<string, unknown>): Response =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

/** Constant-time compare, so the secret cannot be guessed a character at a time. */
function secretMatches(expected: string, received: string): boolean {
  const a = new TextEncoder().encode(expected);
  const b = new TextEncoder().encode(received);
  if (a.byteLength !== b.byteLength) return false;
  let diff = 0;
  for (let i = 0; i < a.byteLength; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

const EMAIL_PATTERN = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

export async function handleSend(request: Request, env: Env): Promise<Response> {
  const offered = (request.headers.get('authorization') ?? '').replace(/^Bearer\s+/i, '');
  if (!env.RELAY_SECRET || !secretMatches(env.RELAY_SECRET, offered)) {
    return json(401, { error: 'unauthorized' });
  }

  let payload: Partial<SendRequest>;
  try {
    payload = await request.json();
  } catch {
    return json(400, { error: 'invalid_json' });
  }

  const from = payload.from ?? env.DEFAULT_FROM ?? '';
  if (!EMAIL_PATTERN.test(payload.to ?? '') || !EMAIL_PATTERN.test(from)) return json(400, { error: 'invalid_address' });
  if (!payload.subject || !payload.text) return json(400, { error: 'missing_subject_or_text' });

  const message = createMimeMessage();
  message.setSender(from);
  message.setRecipient(payload.to ?? '');
  message.setSubject(payload.subject ?? '');
  message.addMessage({ contentType: 'text/plain', data: payload.text });
  if (payload.html) message.addMessage({ contentType: 'text/html', data: payload.html });

  try {
    await env.EMAIL.send(new EmailMessage(from, payload.to ?? '', message.asRaw()));
  } catch (err) {
    // The body never appears here: a failure is about addresses and quotas, not content.
    return json(502, { error: 'send_failed', detail: err instanceof Error ? err.message : 'unknown' });
  }

  return json(202, { accepted: true });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === '/healthz') return json(200, { status: 'ok' });
    if (url.pathname !== '/send') return json(404, { error: 'not_found' });
    if (request.method !== 'POST') return json(405, { error: 'method_not_allowed' });
    return handleSend(request, env);
  },

  /** Every minute (wrangler.toml): the readiness probe, when it is configured (T-6.4). */
  async scheduled(_controller: unknown, env: Env): Promise<void> {
    if (!env.READYZ_URL || !env.PROBE_STATE || !env.ALERT_TO) return;
    await runProbe({ ...env, PROBE_STATE: env.PROBE_STATE });
  },
};
