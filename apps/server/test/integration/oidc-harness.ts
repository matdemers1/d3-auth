import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import * as client from 'openid-client';
import { applyDevSeed } from '../../src/cli/dev-seed.js';
import { createDb } from '../../src/db.js';
import { createSecretHasher } from '../../src/security/hash.js';
import { createLogger, type Logger } from '../../src/log.js';
import { createService, type Service } from '../../src/service.js';

// Runs the real service on a loopback port while every party believes it is talking to
// https://op.d3auth.test behind a TLS-terminating proxy, exactly as it will behind the tunnel.

export const ISSUER = 'https://op.d3auth.test';
export const RP_CALLBACK = 'https://rp.d3auth.test/cb';
export const NATIVE_CALLBACK = 'com.example.app:/cb';
export const USER = { email: 'dev@example.com', username: 'dev', displayName: 'Dev Person', password: 'correct horse battery staple' };
export const WEB_CLIENT = { clientId: 'web-app', secret: randomBytes(32).toString('base64url') };
export const NATIVE_CLIENT = { clientId: 'native-app' };

export interface Harness {
  service: Service;
  /** Every log line the service wrote during the run. */
  logLines: string[];
  port: number;
  opFetch: typeof fetch;
  close(): Promise<void>;
}

export async function startHarness(options: { pkceExemptClientIds?: string[] } = {}): Promise<Harness> {
  const databaseUrl = process.env.DATABASE_URL ?? '';
  const pepper = randomBytes(32);
  const seedDb = createDb(databaseUrl);
  // A fresh KEK per run, so keys sealed by earlier test files must go.
  await seedDb.signingKey.deleteMany();
  await seedDb.oidcPayload.deleteMany();
  await applyDevSeed(seedDb, createSecretHasher(pepper), {
    users: [USER],
    clients: [
      { clientId: WEB_CLIENT.clientId, name: 'Web App', type: 'confidential_web', secret: WEB_CLIENT.secret, redirectUris: [RP_CALLBACK] },
      { clientId: NATIVE_CLIENT.clientId, name: 'Native App', type: 'public_native', redirectUris: [NATIVE_CALLBACK] },
    ],
  });
  await seedDb.$disconnect();

  const logLines: string[] = [];
  const logger: Logger = createLogger({ level: 'debug', destination: { write: (line: string) => { logLines.push(line); } } });
  const service = await createService({
    ISSUER,
    DATABASE_URL: databaseUrl,
    KEK: randomBytes(32),
    PEPPER: pepper,
    COOKIE_KEYS: [randomBytes(32).toString('base64')],
    DEV_LOGIN_ENABLED: true,
    CONFORMANCE_PKCE_EXEMPT_CLIENTS: options.pkceExemptClientIds ?? [],
  }, logger);
  const server: Server = service.app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address() as AddressInfo;

  const opFetch: typeof fetch = (input, init) => {
    const url = new URL(input instanceof Request ? input.url : input.toString());
    if (url.origin !== ISSUER) return fetch(input, init);
    const headers = new Headers(input instanceof Request ? input.headers : init?.headers);
    headers.set('x-forwarded-proto', 'https');
    headers.set('x-forwarded-host', url.host);
    const body = init?.body ?? (input instanceof Request ? input.body : undefined);
    return fetch(`http://127.0.0.1:${port}${url.pathname}${url.search}`, {
      method: init?.method ?? (input instanceof Request ? input.method : 'GET'),
      headers,
      body,
      redirect: 'manual',
      ...(body ? { duplex: 'half' } : {}),
    } as RequestInit);
  };

  return {
    service,
    logLines,
    port,
    opFetch,
    async close() {
      await new Promise<void>((resolve) => server.close(() => { resolve(); }));
      await service.close();
    },
  };
}

/** A user agent with a cookie jar that follows redirects until it leaves the OP. */
export class Browser {
  readonly cookies = new Map<string, string>();
  readonly setCookieHeaders: string[] = [];

  constructor(private readonly opFetch: typeof fetch) {}

  async request(url: string, init: { method?: string; form?: Record<string, string> } = {}): Promise<Response> {
    const headers = new Headers();
    if (this.cookies.size > 0) {
      headers.set('cookie', [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; '));
    }
    let body: string | undefined;
    if (init.form) {
      headers.set('content-type', 'application/x-www-form-urlencoded');
      body = new URLSearchParams(init.form).toString();
    }
    const res = await this.opFetch(url, { method: init.method ?? (body ? 'POST' : 'GET'), headers, ...(body ? { body } : {}) });
    for (const header of res.headers.getSetCookie()) {
      this.setCookieHeaders.push(header);
      const [pair = ''] = header.split(';');
      const eq = pair.indexOf('=');
      const name = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1).trim();
      if (/max-age=0|expires=thu, 01 jan 1970/i.test(header) || value === '') this.cookies.delete(name);
      else this.cookies.set(name, value);
    }
    return res;
  }

  /** Follows redirects on the OP; returns the first response or location outside it. */
  async navigate(url: string, init: { form?: Record<string, string> } = {}): Promise<{ response: Response; leftTo?: URL }> {
    let res = await this.request(url, init);
    let current = new URL(url);
    for (let hops = 0; hops < 10; hops++) {
      const location = res.headers.get('location');
      if (res.status < 300 || res.status >= 400 || !location) return { response: res };
      const next = new URL(location, current);
      if (next.origin !== ISSUER) return { response: res, leftTo: next };
      current = next;
      res = await this.request(next.toString());
    }
    throw new Error('too many redirects');
  }

  /** Completes the dev login form for an interaction page. */
  async login(interaction: Response, credentials = USER): Promise<{ response: Response; leftTo?: URL }> {
    const html = await interaction.text();
    const action = /action="([^"]+)"/.exec(html)?.[1];
    if (!action) throw new Error(`no login form in: ${html.slice(0, 200)}`);
    return this.navigate(new URL(action, ISSUER).toString(), { form: { email: credentials.email, password: credentials.password } });
  }
}

export async function discover(
  h: Harness,
  clientId: string,
  auth: client.ClientAuth,
): Promise<client.Configuration> {
  const viaOp: client.CustomFetch = (url, options) => h.opFetch(url, options as RequestInit);
  const config = await client.discovery(new URL(ISSUER), clientId, undefined, auth, { [client.customFetch]: viaOp });
  config[client.customFetch] = viaOp;
  return config;
}

export function webClientConfig(h: Harness, secret = WEB_CLIENT.secret): Promise<client.Configuration> {
  return discover(h, WEB_CLIENT.clientId, client.ClientSecretBasic(secret));
}

export interface CodeResult {
  callback: URL;
  verifier: string;
  state: string;
  nonce: string;
  browser: Browser;
}

/** Drives a full authorization request through the dev login and returns the callback URL. */
export async function authorize(
  h: Harness,
  config: client.Configuration,
  params: Record<string, string> = {},
  browser = new Browser(h.opFetch),
): Promise<CodeResult> {
  const verifier = client.randomPKCECodeVerifier();
  const state = client.randomState();
  const nonce = client.randomNonce();
  const url = client.buildAuthorizationUrl(config, {
    redirect_uri: RP_CALLBACK,
    scope: 'openid email profile',
    code_challenge: await client.calculatePKCECodeChallenge(verifier),
    code_challenge_method: 'S256',
    state,
    nonce,
    ...params,
  });
  let step = await browser.navigate(url.toString());
  if (!step.leftTo) step = await browser.login(step.response);
  if (!step.leftTo) throw new Error(`authorization did not return to the client: ${step.response.status}`);
  return { callback: step.leftTo, verifier, state, nonce, browser };
}
