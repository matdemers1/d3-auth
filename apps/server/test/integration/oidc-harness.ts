import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import * as client from 'openid-client';
import { applyDevSeed } from '../../src/cli/dev-seed.js';
import { createDb } from '../../src/db.js';
import { createSecretHasher, type SecretHasher } from '../../src/security/hash.js';
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
  /** The same hasher the service uses, so a test can create an account it can sign in as. */
  hasher: SecretHasher;
  /** Counts Argon2id verifications, so a test can prove throttling happens before the work. */
  passwordVerifications: { count: number };
  /** Every log line the service wrote during the run. */
  logLines: string[];
  port: number;
  opFetch: typeof fetch;
  close(): Promise<void>;
}

export async function startHarness(options: { pkceExemptClientIds?: string[] } = {}): Promise<Harness> {
  const passwordVerifications = { count: 0 };
  const databaseUrl = process.env.DATABASE_URL ?? '';
  const pepper = randomBytes(32);
  const seedDb = createDb(databaseUrl);
  // A fresh KEK per run, so keys sealed by earlier test files must go.
  await seedDb.signingKey.deleteMany();
  await seedDb.oidcPayload.deleteMany();
  await applyDevSeed(seedDb, createSecretHasher(pepper), {
    users: [
      {
        ...USER,
        // Access is deny-by-default (REQ-051): without these the fixture user cannot sign in.
        grants: [
          { clientId: WEB_CLIENT.clientId, roles: ['member'] },
          { clientId: NATIVE_CLIENT.clientId, roles: [] },
        ],
      },
    ],
    clients: [
      {
        clientId: WEB_CLIENT.clientId,
        name: 'Web App',
        type: 'confidential_web',
        secret: WEB_CLIENT.secret,
        redirectUris: [RP_CALLBACK],
        roles: [
          { key: 'admin', display: 'Administrator' },
          { key: 'member', display: 'Member', default: true },
        ],
      },
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
    CONFORMANCE_PKCE_EXEMPT_CLIENTS: options.pkceExemptClientIds ?? [],
    OPERATOR_DISPLAY_NAME: 'Matthew',
  }, logger, {
    passwords: (real) => ({
      verify: (hash, password) => {
        passwordVerifications.count += 1;
        return real.verify(hash, password);
      },
    }),
  });
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
    hasher: createSecretHasher(pepper),
    passwordVerifications,
    logLines,
    port,
    opFetch,
    async close() {
      await new Promise<void>((resolve) => server.close(() => { resolve(); }));
      await service.close();
    },
  };
}

/**
 * Access is deny-by-default (REQ-051), so a test that creates a person has to give them a grant
 * before they can sign in to anything — exactly as an admin would in the console.
 */
export async function grantAccess(h: Harness, userId: string, clientId: string = WEB_CLIENT.clientId, roles: string[] = []): Promise<void> {
  const app = await h.service.db.app.findUniqueOrThrow({ where: { clientId }, include: { roles: true } });
  const grant = await h.service.db.grant.upsert({
    where: { userId_appId: { userId, appId: app.id } },
    create: { userId, appId: app.id },
    update: {},
  });
  const wanted = app.roles.filter((role) => roles.includes(role.key));
  await h.service.db.grantRole.deleteMany({ where: { grantId: grant.id } });
  await h.service.db.grantRole.createMany({ data: wanted.map((role) => ({ grantId: grant.id, roleId: role.id })) });
}

/** A user agent with a cookie jar that follows redirects until it leaves the OP. */
export class Browser {
  readonly cookies = new Map<string, string>();
  readonly setCookieHeaders: string[] = [];
  /** The last URL this browser was sent to, so login() can find the interaction uid. */
  lastUrl = ISSUER;

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
    this.lastUrl = url;
    for (let hops = 0; hops < 10; hops++) {
      const location = res.headers.get('location');
      if (res.status < 300 || res.status >= 400 || !location) return { response: res };
      const next = new URL(location, current);
      if (next.origin !== ISSUER) return { response: res, leftTo: next };
      current = next;
      this.lastUrl = next.toString();
      res = await this.request(next.toString());
    }
    throw new Error('too many redirects');
  }

  /**
   * Signs in through the real interaction API, the way the console's form does: fetch the step,
   * post the email, post the password, follow wherever the server sends us.
   */
  async login(
    interaction: Response,
    credentials: { email: string; password: string } = USER,
  ): Promise<{ response: Response; leftTo?: URL; status: number; body: Record<string, unknown> }> {
    const uid = new URL(interaction.url || this.lastUrl).pathname.split('/')[2] ?? '';
    const view = (await (await this.api(uid, '')).json()) as { csrf: string };

    const identify = await this.api(uid, '/identify', { csrf: view.csrf, email: credentials.email });
    if (!identify.ok) {
      return { response: identify, status: identify.status, body: (await identify.json()) as Record<string, unknown> };
    }

    const password = await this.api(uid, '/password', { csrf: view.csrf, password: credentials.password });
    const body = (await password.json()) as Record<string, unknown>;
    if (typeof body.redirectTo !== 'string') {
      return { response: password, status: password.status, body };
    }
    const followed = await this.navigate(body.redirectTo);
    // First sign-in to an app stops on the continue-as interstitial (REQ-059). A person clicks
    // *Continue*; so does this.
    if (!followed.leftTo && (await followed.response.clone().text()).includes('/continue')) {
      const html = await followed.response.text();
      const csrf = /name="csrf" value="([^"]*)"/.exec(html)?.[1] ?? '';
      const interstitialUid = new URL(this.lastUrl).pathname.split('/')[2] ?? uid;
      const continued = await this.api(interstitialUid, '/continue', { csrf });
      const answer = (await continued.json()) as Record<string, unknown>;
      if (typeof answer.redirectTo === 'string') {
        return { ...(await this.navigate(answer.redirectTo)), status: continued.status, body: answer };
      }
      return { response: continued, status: continued.status, body: answer };
    }
    return { ...followed, status: password.status, body };
  }

  /** Calls the interaction API with the cookie jar, as the browser would. */
  async api(uid: string, path: string, body?: Record<string, string>): Promise<Response> {
    const headers = new Headers({ accept: 'application/json' });
    if (this.cookies.size > 0) headers.set('cookie', [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; '));
    if (body) headers.set('content-type', 'application/json');
    const res = await this.opFetch(`${ISSUER}/api/interaction/${uid}${path}`, {
      method: body ? 'POST' : 'GET',
      headers,
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    for (const header of res.headers.getSetCookie()) {
      const [pair = ''] = header.split(';');
      const eq = pair.indexOf('=');
      this.cookies.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
    }
    return res;
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
  credentials: { email: string; password: string } = USER,
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
  if (!step.leftTo) step = await browser.login(step.response, credentials);
  if (!step.leftTo) throw new Error(`authorization did not return to the client: ${step.response.status}`);
  return { callback: step.leftTo, verifier, state, nonce, browser };
}
