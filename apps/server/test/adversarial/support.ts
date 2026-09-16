import { ISSUER, WEB_CLIENT, authorize, Browser, type Harness } from '../integration/oidc-harness.js';
import type * as client from 'openid-client';

// Shared by the adversarial files. Nothing clever lives here on purpose: an attack that needs a
// helper to be expressed is an attack somebody should be able to read in one place.

export interface TokenAnswer {
  status: number;
  body: Record<string, unknown>;
}

/** A raw token endpoint call, so a test can send exactly the malformed thing it means to. */
export async function tokenRequest(h: Harness, form: Record<string, string>, auth = `${WEB_CLIENT.clientId}:${WEB_CLIENT.secret}`): Promise<TokenAnswer> {
  const res = await h.opFetch(`${ISSUER}/oidc/token`, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      ...(auth ? { authorization: `Basic ${Buffer.from(auth).toString('base64')}` } : {}),
    },
    body: new URLSearchParams(form).toString(),
  });
  return { status: res.status, body: (await res.json().catch(() => ({}))) as Record<string, unknown> };
}

export type Call = (path: string, init?: { body?: unknown; method?: string; headers?: Record<string, string> }) => Promise<Response>;

/** Signs in through the real flow and returns the cookie header that session rides on. */
export async function sessionCookie(h: Harness, config: client.Configuration, credentials?: { email: string; password: string }): Promise<string> {
  const { browser } = await authorize(h, config, {}, new Browser(h.opFetch), credentials);
  return [...browser.cookies].map(([k, v]) => `${k}=${v}`).join('; ');
}

/** Signs in through the real flow and returns a console caller riding that session's cookies. */
export async function consoleCaller(h: Harness, config: client.Configuration, credentials?: { email: string; password: string }): Promise<Call> {
  const cookie = await sessionCookie(h, config, credentials);
  return (path, init = {}) =>
    h.opFetch(`${ISSUER}${path}`, {
      method: init.method ?? (init.body === undefined ? 'GET' : 'POST'),
      headers: {
        cookie,
        accept: 'application/json',
        'sec-fetch-site': 'same-origin',
        ...(init.body === undefined ? {} : { 'content-type': 'application/json' }),
        ...init.headers,
      },
      ...(init.body === undefined ? {} : { body: JSON.stringify(init.body) }),
    });
}
