import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT, type JWK } from 'jose';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import { createBackchannelHandler, LOGOUT_EVENT, verifyLogoutToken, type LogoutTokenOptions } from '../src/logout-token.js';

// REQ-098, REQ-099, REQ-095.
//
// A logout token arrives unauthenticated, from anybody who can reach the endpoint, and asks an
// app to sign somebody out. Every one of these rules is the difference between that being a
// feature and being a denial-of-service with extra steps.

const ISSUER = 'https://auth.example.test';
const CLIENT_ID = 'an-app';

let signer: Awaited<ReturnType<typeof generateKeyPair>>;
let jwks: NonNullable<LogoutTokenOptions['jwks']>;
let publicKey: JWK;

/** Mints a logout token, with any rule deliberately broken. */
interface Overrides {
  events?: unknown;
  // `undefined` is meaningful here: it means "leave this claim out entirely".
  jti?: string | undefined;
  sub?: string | undefined;
  sid?: string | undefined;
  nonce?: string | undefined;
  iss?: string | undefined;
  aud?: string | undefined;
}

async function mint(overrides: Overrides = {}, options: { alg?: string; typ?: string } = {}): Promise<string> {
  const full: Overrides = {
    events: { [LOGOUT_EVENT]: {} },
    jti: `jti-${Math.random().toString(36).slice(2)}`,
    sub: 'a-person',
    sid: 'a-session',
    ...overrides,
  };
  // An explicit `undefined` means "leave this claim out", which is how each rule gets broken.
  const payload = Object.fromEntries(
    Object.entries(full).filter(([key, value]) => value !== undefined && key !== 'iss' && key !== 'aud'),
  );

  return new SignJWT(payload)
    .setProtectedHeader({ alg: options.alg ?? 'ES256', typ: options.typ ?? 'logout+jwt' })
    .setIssuedAt()
    .setIssuer(overrides.iss ?? ISSUER)
    .setAudience(overrides.aud ?? CLIENT_ID)
    .setExpirationTime('2m')
    .sign(signer.privateKey);
}

beforeAll(async () => {
  signer = await generateKeyPair('ES256', { extractable: true });
  publicKey = await exportJWK(signer.publicKey);
  publicKey.alg = 'ES256';
  jwks = createLocalJWKSet({ keys: [publicKey] });
});

const verify = (token: string) => verifyLogoutToken(token, { issuer: ISSUER, clientId: CLIENT_ID, jwks });

describe('verifying a logout token', () => {
  it('accepts a real one and says which session to end', async () => {
    const verified = await verify(await mint());
    expect(verified).toMatchObject({ sub: 'a-person', sid: 'a-session' });
    expect(verified.jti).toEqual(expect.any(String));
  });

  it('refuses one signed by somebody else', async () => {
    const other = await generateKeyPair('ES256', { extractable: true });
    const forged = await new SignJWT({ events: { [LOGOUT_EVENT]: {} }, jti: 'x', sub: 'a-person' })
      .setProtectedHeader({ alg: 'ES256', typ: 'logout+jwt' })
      .setIssuedAt()
      .setIssuer(ISSUER)
      .setAudience(CLIENT_ID)
      .setExpirationTime('2m')
      .sign(other.privateKey);
    await expect(verify(forged)).rejects.toThrow(/logout token rejected/);
  });

  it('refuses the wrong issuer and the wrong audience', async () => {
    await expect(verify(await mint({ iss: 'https://somewhere.else.test' }))).rejects.toThrow(/rejected/);
    await expect(verify(await mint({ aud: 'a-different-app' }))).rejects.toThrow(/rejected/);
  });

  it('refuses a token carrying a nonce, which would be an ID token replayed', async () => {
    await expect(verify(await mint({ nonce: 'from-a-sign-in' }))).rejects.toThrow(/must not carry a nonce/);
  });

  it('refuses anything that is not a back-channel logout event', async () => {
    await expect(verify(await mint({ events: { 'http://example.test/other': {} } }))).rejects.toThrow(/not a back-channel logout/);
    await expect(verify(await mint({ events: undefined }))).rejects.toThrow(/not a back-channel logout/);
  });

  it('refuses one with no jti, because it could not be applied once', async () => {
    await expect(verify(await mint({ jti: undefined }))).rejects.toThrow(/no jti/);
  });

  it('refuses one that names neither a subject nor a session', async () => {
    await expect(verify(await mint({ sub: undefined, sid: undefined }))).rejects.toThrow(/neither a subject nor a session/);
  });

  it('refuses one that is too old to be about now', async () => {
    vi.useFakeTimers();
    try {
      const token = await mint();
      vi.setSystemTime(new Date(Date.now() + 5 * 60 * 1000));
      await expect(verify(token)).rejects.toThrow(/too old|rejected/);
    } finally {
      vi.useRealTimers();
    }
  });

  it('refuses a token that is not typed as a logout token', async () => {
    await expect(verify(await mint({}, { typ: 'JWT' }))).rejects.toThrow(/rejected/);
  });
});

describe('the handler an app mounts (REQ-099)', () => {
  it('ends the session once, however many times the same event arrives', async () => {
    const ended: string[] = [];
    const handle = createBackchannelHandler({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      jwks,
      endSession: (logout) => {
        ended.push(logout.sid ?? logout.sub);
      },
    });

    const token = await mint();
    expect(await handle(token)).toEqual({ ok: true });
    // The provider retries three times; the second and third must be no-ops.
    expect(await handle(token)).toEqual({ ok: true, repeated: true });
    expect(await handle(token)).toEqual({ ok: true, repeated: true });
    expect(ended).toEqual(['a-session']);
  });

  it('says no without throwing, so a bad token is not an outage', async () => {
    const handle = createBackchannelHandler({ issuer: ISSUER, clientId: CLIENT_ID, jwks, endSession: () => undefined });
    expect(await handle('not.a.token')).toMatchObject({ ok: false });
    expect(await handle(await mint({ nonce: 'x' }))).toMatchObject({ ok: false, reason: expect.stringContaining('nonce') as string });
  });

  it('applies two different events to two different sessions', async () => {
    const ended: string[] = [];
    const handle = createBackchannelHandler({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      jwks,
      endSession: (logout) => {
        ended.push(logout.sid ?? '');
      },
    });
    await handle(await mint({ sid: 'one' }));
    await handle(await mint({ sid: 'two' }));
    expect(ended).toEqual(['one', 'two']);
  });
});
