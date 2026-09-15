import * as client from 'openid-client';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { authorize, Browser, discover, ISSUER, NATIVE_CALLBACK, NATIVE_CLIENT, RP_CALLBACK, startHarness, USER, WEB_CLIENT, webClientConfig, type Harness } from './oidc-harness.js';

let h: Harness;
let config: client.Configuration;

beforeAll(async () => {
  h = await startHarness();
  config = await webClientConfig(h);
});

afterAll(async () => {
  await h.close();
});

const b64urlJson = (part: string | undefined): Record<string, unknown> =>
  JSON.parse(Buffer.from(part ?? '', 'base64url').toString('utf8')) as Record<string, unknown>;

async function tokenRequest(form: Record<string, string>, auth = `${WEB_CLIENT.clientId}:${WEB_CLIENT.secret}`) {
  const res = await h.opFetch(`${ISSUER}/oidc/token`, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      authorization: `Basic ${Buffer.from(auth).toString('base64')}`,
    },
    body: new URLSearchParams(form).toString(),
  });
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

describe('discovery and JWKS (REQ-002, REQ-006, REQ-014)', () => {
  it('matches the golden discovery document', async () => {
    const res = await h.opFetch(`${ISSUER}/.well-known/openid-configuration`);
    expect(res.status).toBe(200);
    const doc = (await res.json()) as Record<string, unknown>;
    await expect(JSON.stringify(doc, null, 2) + '\n').toMatchFileSnapshot('./__snapshots__/discovery.json');
  });

  it('advertises only the narrowed surface', () => {
    const doc = config.serverMetadata();
    expect(doc.issuer).toBe(ISSUER);
    expect(doc.code_challenge_methods_supported).toEqual(['S256']);
    expect(doc.response_types_supported).toEqual(['code']);
    expect(doc.grant_types_supported).not.toContain('implicit');
    expect(doc.grant_types_supported).not.toContain('password');
    expect(doc.grant_types_supported).not.toContain('client_credentials');
    expect(doc.registration_endpoint).toBeUndefined();
    expect(doc.authorization_response_iss_parameter_supported).toBe(true);
    expect(doc.id_token_signing_alg_values_supported).toEqual(expect.arrayContaining(['ES256', 'RS256']));
    expect(doc.id_token_signing_alg_values_supported).not.toContain('none');
    expect(doc.id_token_signing_alg_values_supported?.some((a) => a.startsWith('HS'))).toBe(false);
    expect(doc.token_endpoint_auth_methods_supported).toEqual(['client_secret_basic', 'none']);
  });

  it('publishes public keys only, each with a kid', async () => {
    const res = await h.opFetch(`${ISSUER}/oidc/jwks`);
    const { keys } = (await res.json()) as { keys: Record<string, unknown>[] };
    expect(keys.map((k) => k.alg)).toEqual(['ES256', 'RS256']);
    for (const key of keys) {
      expect(key.kid).toEqual(expect.any(String));
      for (const priv of ['d', 'p', 'q', 'dp', 'dq', 'qi']) expect(key).not.toHaveProperty(priv);
    }
  });

  it('has no registration or WebFinger endpoint', async () => {
    expect((await h.opFetch(`${ISSUER}/oidc/reg`, { method: 'POST' })).status).toBe(404);
    expect((await h.opFetch(`${ISSUER}/.well-known/webfinger?resource=acct:dev@example.com`)).status).toBe(404);
  });
});

describe('authorization code flow', () => {
  it('signs a user in and issues an ES256 ID token with kid (REQ-001, REQ-006, REQ-007)', async () => {
    const { callback, verifier, state, nonce } = await authorize(h, config);
    expect(callback.searchParams.get('iss')).toBe(ISSUER);

    const tokens = await client.authorizationCodeGrant(config, callback, {
      pkceCodeVerifier: verifier,
      expectedState: state,
      expectedNonce: nonce,
    });
    const [header] = (tokens.id_token ?? '').split('.');
    const jwtHeader = b64urlJson(header);
    expect(jwtHeader.alg).toBe('ES256');
    expect(jwtHeader.kid).toEqual(expect.any(String));

    const claims = tokens.claims();
    expect(claims?.iss).toBe(ISSUER);
    expect(claims?.aud).toBe(WEB_CLIENT.clientId);
    expect(claims?.sub).toMatch(/^[0-9a-f-]{36}$/);

    const userinfo = await client.fetchUserInfo(config, tokens.access_token, claims?.sub ?? '');
    expect(userinfo).toMatchObject({ email: USER.email, email_verified: true, preferred_username: USER.username, name: USER.displayName });
  });

  it('issues opaque access tokens that live 10 minutes (REQ-008)', async () => {
    const { callback, verifier, state, nonce } = await authorize(h, config);
    const tokens = await client.authorizationCodeGrant(config, callback, { pkceCodeVerifier: verifier, expectedState: state, expectedNonce: nonce });
    expect(tokens.access_token.split('.')).toHaveLength(1);
    const introspection = await client.tokenIntrospection(config, tokens.access_token);
    expect(introspection.active).toBe(true);
    expect((introspection.exp ?? 0) - (introspection.iat ?? 0)).toBe(600);
  });

  it('sets __Host- cookies with Secure, HttpOnly, SameSite=Lax and Path=/ (R-10)', async () => {
    const { browser } = await authorize(h, config);
    const hostCookies = browser.setCookieHeaders.filter((c) => c.startsWith('__Host-'));
    expect(hostCookies.length).toBeGreaterThan(0);
    for (const cookie of hostCookies) {
      expect(cookie).toMatch(/;\s*path=\/(;|$)/i);
      expect(cookie).toMatch(/;\s*secure/i);
      expect(cookie).toMatch(/;\s*httponly/i);
      expect(cookie).toMatch(/;\s*samesite=lax/i);
      expect(cookie).not.toMatch(/;\s*domain=/i);
    }
    expect(browser.setCookieHeaders.some((c) => c.startsWith('__Host-d3auth_session='))).toBe(true);
    for (const cookie of browser.setCookieHeaders) {
      expect(cookie).toMatch(/^__(Host|Secure)-d3auth_/);
    }
  });

  it('rejects a wrong password without redirecting', async () => {
    const browser = new Browser(h.opFetch);
    const url = client.buildAuthorizationUrl(config, {
      redirect_uri: RP_CALLBACK,
      scope: 'openid',
      code_challenge: await client.calculatePKCECodeChallenge(client.randomPKCECodeVerifier()),
      code_challenge_method: 'S256',
    });
    const { response } = await browser.navigate(url.toString());
    const result = await browser.login(response, { ...USER, password: 'not the right password' });
    expect(result.leftTo).toBeUndefined();
    expect(result.response.status).toBe(401);
  });

  it('supports a public native client with PKCE and no secret', async () => {
    const native = await discover(h, NATIVE_CLIENT.clientId, client.None());
    const { callback, verifier, state, nonce } = await authorize(h, native, { redirect_uri: NATIVE_CALLBACK });
    expect(callback.protocol).toBe('com.example.app:');
    const tokens = await client.authorizationCodeGrant(native, callback, { pkceCodeVerifier: verifier, expectedState: state, expectedNonce: nonce });
    expect(tokens.id_token).toBeTruthy();
  });
});

describe('PKCE is required (REQ-003)', () => {
  const base = (extra: Record<string, string>) => {
    const url = new URL(`${ISSUER}/oidc/auth`);
    for (const [k, v] of Object.entries({ client_id: WEB_CLIENT.clientId, response_type: 'code', scope: 'openid', redirect_uri: RP_CALLBACK, ...extra })) {
      url.searchParams.set(k, v);
    }
    return url.toString();
  };

  it('rejects an authorization request without code_challenge', async () => {
    const { leftTo } = await new Browser(h.opFetch).navigate(base({}));
    expect(leftTo?.searchParams.get('error')).toBe('invalid_request');
  });

  it('rejects code_challenge_method=plain', async () => {
    const { leftTo } = await new Browser(h.opFetch).navigate(base({ code_challenge: 'a'.repeat(43), code_challenge_method: 'plain' }));
    expect(leftTo?.searchParams.get('error')).toBe('invalid_request');
  });

  it('rejects a token request without code_verifier', async () => {
    const { callback } = await authorize(h, config);
    const res = await tokenRequest({ grant_type: 'authorization_code', code: callback.searchParams.get('code') ?? '', redirect_uri: RP_CALLBACK });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_grant');
  });
});

describe('redirect_uri is matched exactly (REQ-005)', () => {
  const mutations = [
    `${RP_CALLBACK}/`,
    `${RP_CALLBACK}x`,
    'https://rp.d3auth.test/CB',
    'https://RP.d3auth.test.evil.test/cb',
    'https://rp.d3auth.test@evil.test/cb',
    'https://rp.d3auth.test/cb?extra=1',
    'http://rp.d3auth.test/cb',
  ];

  it.each(mutations)('never redirects to %s', async (redirectUri) => {
    const url = client.buildAuthorizationUrl(config, {
      redirect_uri: redirectUri,
      scope: 'openid',
      code_challenge: await client.calculatePKCECodeChallenge(client.randomPKCECodeVerifier()),
      code_challenge_method: 'S256',
    });
    const { response, leftTo } = await new Browser(h.opFetch).navigate(url.toString());
    expect(leftTo).toBeUndefined();
    expect(response.status).toBe(400);
  });
});

describe('single-use codes and rotating refresh tokens (REQ-004, REQ-009)', () => {
  it('a replayed code fails and revokes tokens issued from it', async () => {
    const { callback, verifier } = await authorize(h, config);
    const form = { grant_type: 'authorization_code', code: callback.searchParams.get('code') ?? '', redirect_uri: RP_CALLBACK, code_verifier: verifier };
    const first = await tokenRequest(form);
    expect(first.status).toBe(200);
    const accessToken = String(first.body.access_token);
    expect((await client.tokenIntrospection(config, accessToken)).active).toBe(true);

    const replay = await tokenRequest(form);
    expect(replay.body.error).toBe('invalid_grant');
    expect((await client.tokenIntrospection(config, accessToken)).active).toBe(false);
  });

  it('rotates refresh tokens, and reuse revokes the whole family', async () => {
    const { callback, verifier, state, nonce } = await authorize(h, config);
    const tokens = await client.authorizationCodeGrant(config, callback, { pkceCodeVerifier: verifier, expectedState: state, expectedNonce: nonce });
    const original = tokens.refresh_token ?? '';
    expect(original).toBeTruthy();

    const rotated = await tokenRequest({ grant_type: 'refresh_token', refresh_token: original });
    expect(rotated.status).toBe(200);
    const next = String(rotated.body.refresh_token);
    expect(next).not.toBe(original);

    const reuse = await tokenRequest({ grant_type: 'refresh_token', refresh_token: original });
    expect(reuse.body.error).toBe('invalid_grant');

    const afterReuse = await tokenRequest({ grant_type: 'refresh_token', refresh_token: next });
    expect(afterReuse.body.error).toBe('invalid_grant');
    expect((await client.tokenIntrospection(config, String(rotated.body.access_token))).active).toBe(false);
  });

  it('keeps an absolute 30-day refresh lifetime across rotation', async () => {
    const { callback, verifier, state, nonce } = await authorize(h, config);
    const tokens = await client.authorizationCodeGrant(config, callback, { pkceCodeVerifier: verifier, expectedState: state, expectedNonce: nonce });
    const first = await client.tokenIntrospection(config, tokens.refresh_token ?? '');
    const rotated = await tokenRequest({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token ?? '' });
    const second = await client.tokenIntrospection(config, String(rotated.body.refresh_token));
    expect((first.exp ?? 0) - (first.iat ?? 0)).toBe(30 * 24 * 60 * 60);
    expect(Math.abs((second.exp ?? 0) - (first.exp ?? 0))).toBeLessThanOrEqual(1);
  });
});

describe('client authentication (REQ-015, REQ-014)', () => {
  it('rejects a wrong client secret', async () => {
    const { callback, verifier } = await authorize(h, config);
    const res = await tokenRequest(
      { grant_type: 'authorization_code', code: callback.searchParams.get('code') ?? '', redirect_uri: RP_CALLBACK, code_verifier: verifier },
      `${WEB_CLIENT.clientId}:wrong-secret-wrong-secret-wrong-secret`,
    );
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('invalid_client');
  });

  it('stores only a hash of the client secret', async () => {
    const app = await h.service.db.app.findUniqueOrThrow({ where: { clientId: WEB_CLIENT.clientId } });
    expect(app.clientSecretHash).toMatch(/^\$argon2id\$v=19\$m=19456,p=1,t=2\$/);
    expect(app.clientSecretHash).not.toContain(WEB_CLIENT.secret);
  });

  it.each(['password', 'client_credentials', 'implicit'])('refuses grant_type=%s', async (grantType) => {
    const res = await tokenRequest({ grant_type: grantType, username: USER.email, password: USER.password });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('unsupported_grant_type');
  });

  it('refuses response_type=token', async () => {
    const url = new URL(`${ISSUER}/oidc/auth`);
    for (const [k, v] of Object.entries({ client_id: WEB_CLIENT.clientId, response_type: 'token', scope: 'openid', redirect_uri: RP_CALLBACK })) url.searchParams.set(k, v);
    const { leftTo } = await new Browser(h.opFetch).navigate(url.toString());
    expect(leftTo?.searchParams.get('error') ?? leftTo?.hash).toMatch(/unsupported_response_type/);
  });
});
