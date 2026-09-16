import { describe, expect, it, vi } from 'vitest';
import worker, { handleSend, type Env } from '../src/index.js';

// `cloudflare:email` only exists inside the Workers runtime, so the class is stubbed here and the
// message it would have carried is inspected instead. The deployed smoke test is in the runbook.
/** What the stubbed EmailMessage keeps, so the test can read the message that would have gone out. */
interface Sent {
  from: string;
  to: string;
  raw: string;
}

vi.mock('cloudflare:email', () => ({
  EmailMessage: class implements Sent {
    constructor(
      readonly from: string,
      readonly to: string,
      readonly raw: string,
    ) {}
  },
}));

function env(overrides: Partial<Env> = {}): { env: Env; sent: Sent[] } {
  const sent: Sent[] = [];
  return {
    sent,
    env: {
      RELAY_SECRET: 'the-shared-secret',
      DEFAULT_FROM: 'no-reply@no-reply.d3cloud.io',
      EMAIL: {
        send: (message) => {
          sent.push(message as Sent);
          return Promise.resolve();
        },
      },
      ...overrides,
    },
  };
}

const post = (body: unknown, secret = 'the-shared-secret'): Request =>
  new Request('https://relay.test/send', {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${secret}` },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  });

const message = { to: 'guest@example.com', subject: 'Invite', text: 'Open this link' };

describe('mail relay (REQ-106)', () => {
  it('sends a message it accepts', async () => {
    const { env: e, sent } = env();
    const res = await handleSend(post({ ...message, html: '<p>Open this link</p>' }), e);

    expect(res.status).toBe(202);
    expect(await res.json()).toEqual({ accepted: true });
    expect(sent).toHaveLength(1);
    expect(sent[0]).toMatchObject({ from: 'no-reply@no-reply.d3cloud.io', to: 'guest@example.com' });
    // mimetext encodes headers per RFC 2047, so the subject is decoded before comparing.
    const encoded = /Subject: =\?utf-8\?B\?([A-Za-z0-9+/=]+)\?=/.exec(sent[0]?.raw ?? '')?.[1] ?? '';
    expect(atob(encoded)).toBe('Invite');
    expect(sent[0]?.raw).toContain('text/plain');
    expect(sent[0]?.raw).toContain('text/html');
  });

  it.each([
    ['no header', ''],
    ['the wrong secret', 'not-the-secret'],
    ['a prefix of the secret', 'the-shared'],
  ])('refuses %s', async (_case, secret) => {
    const { env: e, sent } = env();
    const res = await handleSend(post(message, secret), e);
    expect(res.status).toBe(401);
    expect(sent).toHaveLength(0);
  });

  it('refuses to send when no secret is configured at all', async () => {
    const { env: e } = env({ RELAY_SECRET: '' });
    expect((await handleSend(post(message, ''), e)).status).toBe(401);
  });

  it.each([
    [{ ...message, to: 'not-an-address' }, 'invalid_address'],
    [{ to: 'a@b.test', subject: '', text: 'x' }, 'missing_subject_or_text'],
    [{ to: 'a@b.test', subject: 'x', text: '' }, 'missing_subject_or_text'],
  ])('rejects a malformed request (%#)', async (body, error) => {
    const { env: e, sent } = env();
    const res = await handleSend(post(body), e);
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error });
    expect(sent).toHaveLength(0);
  });

  it('rejects a body that is not JSON', async () => {
    const { env: e } = env();
    const res = await handleSend(post('{not json'), e);
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: 'invalid_json' });
  });

  it('reports a send failure without echoing the message', async () => {
    const { env: e } = env({
      EMAIL: { send: () => Promise.reject(new Error('daily quota exceeded')) },
    });
    const res = await handleSend(post({ ...message, text: 'secret recovery link' }), e);
    expect(res.status).toBe(502);
    const body: { error?: string; detail?: string } = await res.json();
    expect(body).toMatchObject({ error: 'send_failed' });
    expect(body.detail ?? '').toContain('quota');
    expect(JSON.stringify(body)).not.toContain('secret recovery link');
  });

  it('answers only /send and /healthz, and only POST to send', async () => {
    const { env: e } = env();
    expect((await worker.fetch(new Request('https://relay.test/healthz'), e)).status).toBe(200);
    expect((await worker.fetch(new Request('https://relay.test/'), e)).status).toBe(404);
    expect((await worker.fetch(new Request('https://relay.test/send'), e)).status).toBe(405);
  });
});
