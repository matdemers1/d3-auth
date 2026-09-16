import { exportJWK, generateKeyPair, SignJWT, UnsecuredJWT, type JWK } from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';
import { createAuthClient, identityKey, isSameIdentity, verifyLogoutToken } from '../src/index.js';
import { ALLOWED_ALGORITHMS, LOGOUT_EVENT } from '../src/logout-token.js';

// Attack class: lying to the app (REQ-093, REQ-094, REQ-095, REQ-096).
//
// The provider can be perfect and a consumer still gets fooled, because the consumer is where a
// token is finally believed. So this file stands up a provider that lies — in-process, through
// the SDK's own `fetch` seam — and hands the SDK every forged token worth trying: unsigned, signed
// with the client's own secret as an HMAC key (the classic public/symmetric confusion), signed by
// a stranger's key wearing the real key's `kid`, for the wrong issuer, audience or nonce, or
// expired. Each must be refused. One honest token must be accepted, or the refusals prove nothing.

const ISSUER = 'https://liar.example.test';
const CLIENT_ID = 'victim-app';
const CLIENT_SECRET = 'a-client-secret-that-is-long-enough-to-be-an-hmac-key';
const REDIRECT = 'https://victim.example.test/callback';
const KID = 'the-real-kid';

let real: Awaited<ReturnType<typeof generateKeyPair>>;
let stranger: Awaited<ReturnType<typeof generateKeyPair>>;
let publicJwk: JWK;

/** The token endpoint will return whatever this is set to. */
let nextIdToken = '';

const provider: typeof fetch = (input, init) => {
  const url = new URL(input instanceof Request ? input.url : input.toString());
  const json = (body: unknown): Response => new Response(JSON.stringify(body), { headers: { 'content-type': 'application/json' } });
  void init;
  switch (url.pathname) {
    case '/.well-known/openid-configuration':
      return Promise.resolve(
        json({
          issuer: ISSUER,
          authorization_endpoint: `${ISSUER}/oidc/auth`,
          token_endpoint: `${ISSUER}/oidc/token`,
          jwks_uri: `${ISSUER}/oidc/jwks`,
          userinfo_endpoint: `${ISSUER}/oidc/me`,
          end_session_endpoint: `${ISSUER}/oidc/session/end`,
          response_types_supported: ['code'],
          subject_types_supported: ['public'],
          id_token_signing_alg_values_supported: ['ES256', 'HS256', 'none'],
          code_challenge_methods_supported: ['S256'],
        }),
      );
    case '/oidc/jwks':
      return Promise.resolve(json({ keys: [publicJwk] }));
    case '/oidc/token':
      return Promise.resolve(json({ access_token: 'at', token_type: 'Bearer', expires_in: 600, id_token: nextIdToken }));
    case '/oidc/me':
      return Promise.resolve(json({ sub: 'person-1', roles: ['member'] }));
    default:
      return Promise.resolve(new Response('not found', { status: 404 }));
  }
};

interface Claims {
  iss?: string;
  aud?: string | string[];
  sub?: string;
  nonce?: string;
  exp?: number;
  email?: string;
  azp?: string;
}

const claimsFor = (nonce: string, overrides: Claims = {}): Record<string, unknown> => ({
  iss: ISSUER,
  aud: CLIENT_ID,
  sub: 'person-1',
  nonce,
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 300,
  roles: ['member'],
  ...overrides,
});

async function signedBy(key: CryptoKey, claims: Record<string, unknown>, alg = 'ES256', kid = KID): Promise<string> {
  return new SignJWT(claims).setProtectedHeader({ alg, kid }).sign(key);
}

/** Runs a whole sign-in against the lying provider with whatever ID token it is told to return. */
async function signInWith(mint: (nonce: string) => Promise<string> | string) {
  const sdk = await createAuthClient({ issuer: ISSUER, clientId: CLIENT_ID, clientSecret: CLIENT_SECRET, redirectUri: REDIRECT, fetch: provider });
  const start = await sdk.beginSignIn();
  nextIdToken = await mint(start.nonce);
  const callback = `${REDIRECT}?code=a-code&state=${encodeURIComponent(start.state)}&iss=${encodeURIComponent(ISSUER)}`;
  return sdk.completeSignIn(callback, start);
}

beforeAll(async () => {
  real = await generateKeyPair('ES256', { extractable: true });
  stranger = await generateKeyPair('ES256', { extractable: true });
  publicJwk = { ...(await exportJWK(real.publicKey)), kid: KID, alg: 'ES256', use: 'sig' };
});

describe('the control', () => {
  it('an honest token is accepted, so the refusals below mean something', async () => {
    const session = await signInWith((nonce) => signedBy(real.privateKey, claimsFor(nonce)));
    expect(session.identity).toMatchObject({ iss: ISSUER, sub: 'person-1' });
  });
});

describe('a forged ID token', () => {
  it('unsigned (alg=none) is refused', async () => {
    await expect(signInWith((nonce) => new UnsecuredJWT(claimsFor(nonce)).encode())).rejects.toThrow();
  });

  it('signed with the client secret as an HMAC key is refused', async () => {
    // The public/symmetric confusion as it actually bites an OIDC client: anybody who learns the
    // client secret — a leaked config, a log — could mint "ID tokens" a naive client accepts.
    const secret = new TextEncoder().encode(CLIENT_SECRET);
    await expect(signInWith((nonce) => new SignJWT(claimsFor(nonce)).setProtectedHeader({ alg: 'HS256', kid: KID }).sign(secret))).rejects.toThrow();
  });

  it('signed with the public key itself as an HMAC key is refused', async () => {
    const secret = new TextEncoder().encode(JSON.stringify(publicJwk));
    await expect(signInWith((nonce) => new SignJWT(claimsFor(nonce)).setProtectedHeader({ alg: 'HS256', kid: KID }).sign(secret))).rejects.toThrow();
  });

  it('signed by a stranger wearing the real kid is refused', async () => {
    await expect(signInWith((nonce) => signedBy(stranger.privateKey, claimsFor(nonce)))).rejects.toThrow();
  });

  it.each([
    ['another issuer', { iss: 'https://evil.example.test' }],
    ['another app', { aud: 'some-other-app' }],
    ['several audiences with another app as the authorised party', { aud: [CLIENT_ID, 'some-other-app'], azp: 'some-other-app' }],
    ['a nonce from a different sign-in', { nonce: 'not-the-nonce' }],
    ['an expiry in the past', { exp: Math.floor(Date.now() / 1000) - 600 }],
  ])('for %s is refused', async (_label, overrides) => {
    await expect(signInWith((nonce) => signedBy(real.privateKey, claimsFor(nonce, overrides as Claims)))).rejects.toThrow();
  });
});

describe('the algorithm pin', () => {
  it('is ES256 and RS256 and nothing else, matching what the provider signs with', () => {
    expect([...ALLOWED_ALGORITHMS].sort()).toEqual(['ES256', 'RS256']);
  });
});

describe('a forged logout token', () => {
  const jwks = async () => {
    const { createLocalJWKSet } = await import('jose');
    return createLocalJWKSet({ keys: [publicJwk] });
  };
  const logoutClaims = { events: { [LOGOUT_EVENT]: {} }, jti: 'j-1', sid: 'a-session', sub: 'person-1' };

  it('unsigned is refused', async () => {
    const token = new UnsecuredJWT(logoutClaims).setIssuer(ISSUER).setAudience(CLIENT_ID).setIssuedAt().encode();
    await expect(verifyLogoutToken(token, { issuer: ISSUER, clientId: CLIENT_ID, jwks: await jwks() })).rejects.toThrow();
  });

  it('signed with an HMAC key is refused', async () => {
    const token = await new SignJWT(logoutClaims)
      .setProtectedHeader({ alg: 'HS256', typ: 'logout+jwt', kid: KID })
      .setIssuer(ISSUER)
      .setAudience(CLIENT_ID)
      .setIssuedAt()
      .sign(new TextEncoder().encode(CLIENT_SECRET));
    await expect(verifyLogoutToken(token, { issuer: ISSUER, clientId: CLIENT_ID, jwks: await jwks() })).rejects.toThrow();
  });
});

describe('linking accounts (REQ-093)', () => {
  it('an email match is never an identity match', async () => {
    // A local account somebody pre-registered with the victim's address, never verified.
    const squatter = { email: 'victim@example.test', linked: undefined as string | undefined };

    const session = await signInWith((nonce) => signedBy(real.privateKey, claimsFor(nonce, { email: squatter.email })));
    // The only question an app may ask is "is this the (iss, sub) I stored?" — and nothing was stored.
    expect(squatter.linked === undefined || !isSameIdentity(squatter.linked, session.identity)).toBe(true);

    // Two people who share an address are still two people; one person who changes it is still one.
    expect(identityKey({ iss: ISSUER, sub: 'a' })).not.toBe(identityKey({ iss: ISSUER, sub: 'b' }));
    expect(identityKey({ iss: ISSUER, sub: 'a' })).not.toBe(identityKey({ iss: 'https://other.example.test', sub: 'a' }));
  });

  it('offers no way to look anybody up by email', async () => {
    const surface = Object.keys(await import('../src/index.js'));
    expect(surface.filter((name) => /email/i.test(name))).toEqual([]);
  });
});
