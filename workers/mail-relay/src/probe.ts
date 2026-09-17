import { EmailMessage } from 'cloudflare:email';
import { createMimeMessage } from 'mimetext';

// The readiness probe (T-6.4, REQ-115).
//
// D3 Auth's own alerts cannot report that D3 Auth is down: a stopped container sends nothing. So
// this watches from outside, on Cloudflare's schedule, and sends through Cloudflare's own mail. It
// needs no secret — `/readyz` is public and answers pass or fail only — so it shares nothing with
// the relay's secret, and a compromise of one says nothing about the other.
//
// One email when it has been down for five minutes, one when it comes back. Not one a minute.

export interface ProbeEnv {
  EMAIL: { send(message: EmailMessage): Promise<void> };
  /** Where state lives between runs: when the failure started, and whether anyone was told. */
  PROBE_STATE: { get(key: string): Promise<string | null>; put(key: string, value: string): Promise<void>; delete(key: string): Promise<void> };
  /** e.g. https://auth.d3cloud.io/readyz */
  READYZ_URL?: string;
  /** Comma-separated. */
  ALERT_TO?: string;
  DEFAULT_FROM?: string;
}

interface State {
  firstFailureAt: number;
  lastReason: string;
  alertedAt?: number;
}

const STATE_KEY = 'readyz';
export const DOWN_AFTER_MS = 5 * 60 * 1000;
const TIMEOUT_MS = 10_000;

/** One look at /readyz. Returns why it is not ready, or undefined when it is. */
export async function lookOnce(url: string, fetcher: typeof fetch = fetch): Promise<string | undefined> {
  try {
    const response = await fetcher(url, { signal: AbortSignal.timeout(TIMEOUT_MS), headers: { accept: 'application/json' } });
    const body = (await response.json().catch(() => ({}))) as { status?: string; checks?: Record<string, boolean> };
    if (response.status === 200 && body.status === 'ready') return undefined;
    const failing = Object.entries(body.checks ?? {}).filter(([, ok]) => !ok).map(([name]) => name);
    return `HTTP ${String(response.status)}${failing.length > 0 ? `, failing: ${failing.join(', ')}` : ''}`;
  } catch (err) {
    return err instanceof Error ? `no answer: ${err.message}` : 'no answer';
  }
}

async function tell(env: ProbeEnv, subject: string, text: string): Promise<void> {
  const from = env.DEFAULT_FROM ?? '';
  for (const to of (env.ALERT_TO ?? '').split(',').map((value) => value.trim()).filter(Boolean)) {
    const message = createMimeMessage();
    message.setSender(from);
    message.setRecipient(to);
    message.setSubject(subject);
    message.addMessage({ contentType: 'text/plain', data: text });
    await env.EMAIL.send(new EmailMessage(from, to, message.asRaw()));
  }
}

const when = (ms: number): string => `${new Date(ms).toISOString().slice(0, 16).replace('T', ' ')} UTC`;

export async function runProbe(env: ProbeEnv, now = Date.now(), fetcher: typeof fetch = fetch): Promise<'ready' | 'failing' | 'alerted' | 'recovered'> {
  const url = env.READYZ_URL ?? '';
  const reason = await lookOnce(url, fetcher);
  const raw = await env.PROBE_STATE.get(STATE_KEY);
  const state = raw ? (JSON.parse(raw) as State) : undefined;

  if (!reason) {
    if (!state) return 'ready';
    await env.PROBE_STATE.delete(STATE_KEY);
    if (state.alertedAt === undefined) return 'ready';
    const minutes = Math.round((now - state.firstFailureAt) / 60_000);
    await tell(env, '[D3 Auth] Sign-in is back', `${url} is ready again, after about ${String(minutes)} minutes.\n\nDown since ${when(state.firstFailureAt)}.`);
    return 'recovered';
  }

  const current: State = state ? { ...state, lastReason: reason } : { firstFailureAt: now, lastReason: reason };
  if (current.alertedAt === undefined && now - current.firstFailureAt >= DOWN_AFTER_MS) {
    await tell(
      env,
      '[D3 Auth] Sign-in is down',
      [
        `${url} has not been ready since ${when(current.firstFailureAt)}.`,
        `Last answer: ${reason}.`,
        '',
        'Apps already signed in keep working; new sign-ins do not.',
        'docs/runbooks/deploy.md, "If sign-in is down", has the checks in order.',
      ].join('\n'),
    );
    current.alertedAt = now;
    await env.PROBE_STATE.put(STATE_KEY, JSON.stringify(current));
    return 'alerted';
  }
  await env.PROBE_STATE.put(STATE_KEY, JSON.stringify(current));
  return 'failing';
}
