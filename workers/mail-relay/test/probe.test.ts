import { describe, expect, it, vi } from 'vitest';
import { DOWN_AFTER_MS, lookOnce, runProbe, type ProbeEnv } from '../src/probe.js';

// REQ-115: one email after five minutes down, one when it comes back, and never one a minute.

vi.mock('cloudflare:email', () => ({
  EmailMessage: class {
    constructor(
      readonly from: string,
      readonly to: string,
      readonly raw: string,
    ) {}
  },
}));

function harness() {
  const store = new Map<string, string>();
  const sent: { to: string; raw: string }[] = [];
  const env: ProbeEnv = {
    READYZ_URL: 'https://auth.example.test/readyz',
    ALERT_TO: 'owner@example.test, second@example.test',
    DEFAULT_FROM: 'no-reply@example.test',
    EMAIL: {
      send: (message) => {
        sent.push(message as unknown as { to: string; raw: string });
        return Promise.resolve();
      },
    },
    PROBE_STATE: {
      get: (key) => Promise.resolve(store.get(key) ?? null),
      put: (key, value) => {
        store.set(key, value);
        return Promise.resolve();
      },
      delete: (key) => {
        store.delete(key);
        return Promise.resolve();
      },
    },
  };
  return { env, sent };
}

/** The subject as a person reads it: mimetext always writes it as a base64 encoded-word. */
const subjectOf = (raw: string | undefined): string => {
  const encoded = /^Subject: =\?utf-8\?B\?([^?]+)\?=$/m.exec(raw ?? '')?.[1] ?? '';
  return new TextDecoder().decode(Uint8Array.from(atob(encoded), (char) => char.charCodeAt(0)));
};

const ready: typeof fetch = () => Promise.resolve(new Response(JSON.stringify({ status: 'ready', checks: { database: true } }), { status: 200 }));
const notReady: typeof fetch = () =>
  Promise.resolve(new Response(JSON.stringify({ status: 'not_ready', checks: { database: false, signingKeys: true } }), { status: 503 }));
const unreachable: typeof fetch = () => Promise.reject(new Error('connect ECONNREFUSED'));

describe('one look', () => {
  it('names the failing checks, or the lack of an answer', async () => {
    expect(await lookOnce('x', ready)).toBeUndefined();
    expect(await lookOnce('x', notReady)).toBe('HTTP 503, failing: database');
    expect(await lookOnce('x', unreachable)).toBe('no answer: connect ECONNREFUSED');
  });
});

describe('the probe over time', () => {
  it('stays quiet for a blip shorter than five minutes', async () => {
    const { env, sent } = harness();
    const start = Date.parse('2026-09-17T10:00:00Z');
    expect(await runProbe(env, start, unreachable)).toBe('failing');
    expect(await runProbe(env, start + 3 * 60_000, unreachable)).toBe('failing');
    expect(await runProbe(env, start + 4 * 60_000, ready)).toBe('ready');
    expect(sent).toEqual([]);
  });

  it('emails everyone once at five minutes, not again, and once when it recovers', async () => {
    const { env, sent } = harness();
    const start = Date.parse('2026-09-17T10:00:00Z');
    for (let minute = 0; minute < 5; minute += 1) expect(await runProbe(env, start + minute * 60_000, notReady)).toBe('failing');
    expect(await runProbe(env, start + DOWN_AFTER_MS, notReady)).toBe('alerted');
    expect(sent.map((message) => message.to)).toEqual(['owner@example.test', 'second@example.test']);
    expect(subjectOf(sent[0]?.raw)).toBe('[D3 Auth] Sign-in is down');
    expect(sent[0]?.raw).toContain('failing: database');

    for (let minute = 6; minute < 30; minute += 1) expect(await runProbe(env, start + minute * 60_000, unreachable)).toBe('failing');
    expect(sent).toHaveLength(2);

    expect(await runProbe(env, start + 31 * 60_000, ready)).toBe('recovered');
    expect(sent).toHaveLength(4);
    expect(subjectOf(sent[2]?.raw)).toBe('[D3 Auth] Sign-in is back');
    expect(sent[2]?.raw).toContain('about 31 minutes');

    // And the next outage starts its own clock.
    expect(await runProbe(env, start + 40 * 60_000, unreachable)).toBe('failing');
  });
});
