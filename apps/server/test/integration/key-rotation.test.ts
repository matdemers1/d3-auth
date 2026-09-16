import * as client from 'openid-client';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { generateNext, KeyError, listKeys, MINIMUM_OVERLAP_MS, promoteNext, retire } from '../../src/oidc/keys.js';
import { authorize, Browser, ISSUER, startHarness, testKek, USER, webClientConfig, type Harness } from './oidc-harness.js';

// REQ-118: the key lifecycle, and the two waits that make it safe (R-04).
//
// The failure this is built to prevent is quiet and total: promote a key before consumers have
// seen it, and every token you issue is rejected by apps holding a stale key set. Retire one too
// early and tokens signed minutes ago stop verifying. Both waits are enforced, and both can be
// overridden — but only deliberately, for a key somebody else is holding.

let h: Harness;
let config: client.Configuration;

const jwks = async (): Promise<{ kid: string }[]> => {
  const response = await h.opFetch(`${ISSUER}/oidc/jwks`);
  const body = (await response.json()) as { keys: { kid: string }[] };
  return body.keys;
};

beforeAll(async () => {
  h = await startHarness();
  config = await webClientConfig(h);
  // Keys are owner-only, like everything that decides what the whole system trusts.
  await h.service.db.user.updateMany({ where: { email: USER.email }, data: { kind: 'owner' } });
});

afterAll(async () => {
  await h.close();
});

beforeEach(async () => {
  await h.service.db.throttleCounter.deleteMany();
  // Back to one current key per algorithm.
  await h.service.db.signingKey.deleteMany({ where: { status: { in: ['next', 'retiring', 'retired'] } } });
});

describe('a new key', () => {
  it('is published the moment it exists, and signs nothing', async () => {
    const before = await jwks();
    const key = await generateNext(h.service.db, testKek(h), 'ES256');

    // Published immediately: the wait cannot start until consumers can see it.
    const after = await jwks();
    expect(after.map((jwk) => jwk.kid)).toContain(key.kid);
    expect(after.length).toBe(before.length + 1);

    // Still signed by the old one, because signing is what the process loaded at boot.
    const code = await authorize(h, config, {}, new Browser(h.opFetch));
    const tokens = await client.authorizationCodeGrant(config, code.callback, {
      pkceCodeVerifier: code.verifier,
      expectedState: code.state,
      expectedNonce: code.nonce,
    });
    const header = JSON.parse(Buffer.from((tokens.id_token ?? '').split('.')[0] ?? '', 'base64url').toString()) as { kid: string };
    expect(header.kid).not.toBe(key.kid);
  });

  it('refuses a second one while the first is still waiting', async () => {
    await generateNext(h.service.db, testKek(h), 'ES256');
    await expect(generateNext(h.service.db, testKek(h), 'ES256')).rejects.toBeInstanceOf(KeyError);
  });
});

describe('promoting', () => {
  it('refuses before consumers have had time to see the key (R-04)', async () => {
    await generateNext(h.service.db, testKek(h), 'ES256');
    await expect(promoteNext(h.service.db, 'ES256')).rejects.toThrow(/not been published long enough/);

    // The key is untouched by a refusal.
    const keys = await listKeys(h.service.db);
    expect(keys.find((key) => key.status === 'next')).toBeDefined();
    expect(keys.filter((key) => key.status === 'current')).toHaveLength(2);
  });

  it('goes through once the window has passed, and the old key keeps verifying', async () => {
    const next = await generateNext(h.service.db, testKek(h), 'ES256');
    const later = new Date(Date.now() + MINIMUM_OVERLAP_MS + 1000);

    const { promoted, retiring } = await promoteNext(h.service.db, 'ES256', { now: later });
    expect(promoted.kid).toBe(next.kid);
    expect(retiring).toEqual(expect.any(String));

    // Both are still published: the old one has tokens out there that must keep verifying.
    const published = (await jwks()).map((jwk) => jwk.kid);
    expect(published).toContain(promoted.kid);
    expect(published).toContain(retiring);
  });

  it('can be forced, for a key somebody else is holding', async () => {
    await generateNext(h.service.db, testKek(h), 'ES256');
    const { promoted } = await promoteNext(h.service.db, 'ES256', { force: true });
    expect(promoted.status).toBe('current');

    const audited = await h.service.db.auditEvent.findFirstOrThrow({ where: { event: 'key.promoted' }, orderBy: { id: 'desc' } });
    // The audit row says it was forced, because that is the part somebody will want to know later.
    expect(JSON.stringify(audited.detail)).toContain('"forced":true');
  });

  it('refuses when there is nothing waiting', async () => {
    await expect(promoteNext(h.service.db, 'ES256')).rejects.toThrow(/no next ES256 key/);
  });
});

describe('retiring', () => {
  it('refuses while tokens signed by that key could still be in use', async () => {
    await generateNext(h.service.db, testKek(h), 'ES256');
    await promoteNext(h.service.db, 'ES256', { force: true });
    await expect(retire(h.service.db)).rejects.toThrow(/may still be in use/);
  });

  it('removes the key from the set once the window has passed', async () => {
    await generateNext(h.service.db, testKek(h), 'ES256');
    const { retiring } = await promoteNext(h.service.db, 'ES256', { force: true });
    const later = new Date(Date.now() + MINIMUM_OVERLAP_MS + 1000);

    const retired = await retire(h.service.db, { now: later });
    expect(retired.map((key) => key.kid)).toContain(retiring);
    expect((await jwks()).map((jwk) => jwk.kid)).not.toContain(retiring);
  });

  it('refuses when nothing is retiring', async () => {
    await expect(retire(h.service.db)).rejects.toThrow(/No key is retiring/);
  });
});

describe('what the console is told', () => {
  it('says a restart is needed while the database and the process disagree', async () => {
    await generateNext(h.service.db, testKek(h), 'ES256');
    await promoteNext(h.service.db, 'ES256', { force: true });

    const { browser } = await authorize(h, config, {}, new Browser(h.opFetch));
    const cookie = [...browser.cookies].map(([k, v]) => `${k}=${v}`).join('; ');
    const answer = await h.opFetch(`${ISSUER}/api/admin/keys`, {
      headers: { cookie, accept: 'application/json', 'sec-fetch-site': 'same-origin' },
    });
    expect(answer.status).toBe(200);
    const body = (await answer.json()) as { restartRequired: boolean; keys: { kid: string; alg: string; signingNow: boolean; status: string }[] };

    // The promoted key is current in the table and is not what this process signs with.
    expect(body.restartRequired).toBe(true);
    expect(body.keys.find((key) => key.status === 'current' && key.alg === 'ES256')?.signingNow).toBe(false);
  });
});
