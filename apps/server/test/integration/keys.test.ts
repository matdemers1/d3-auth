import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import { loadSigningKeys } from '../../src/oidc/keys.js';
import { KekError } from '../../src/security/kek.js';
import { testDb, testKek } from './helpers.js';

const db = testDb();

beforeEach(async () => {
  await db.signingKey.deleteMany();
});

afterAll(async () => {
  await db.$disconnect();
});

describe('signing key bootstrap (REQ-006, REQ-117)', () => {
  it('generates one current ES256 and one current RS256 key, ES256 first', async () => {
    const keys = await loadSigningKeys(db, testKek());
    expect(keys.map((k) => k.alg)).toEqual(['ES256', 'RS256']);
    for (const key of keys) {
      expect(key.kid).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(key.d).toBeTruthy();
    }
  });

  it('keeps the same kids across restarts', async () => {
    const kek = testKek();
    const first = await loadSigningKeys(db, kek);
    const second = await loadSigningKeys(db, kek);
    expect(second.map((k) => k.kid)).toEqual(first.map((k) => k.kid));
    expect(await db.signingKey.count()).toBe(2);
  });

  it('stores private keys sealed, never as plaintext', async () => {
    const keys = await loadSigningKeys(db, testKek());
    const rows = await db.signingKey.findMany();
    for (const row of rows) {
      const d = keys.find((k) => k.kid === row.kid)?.d ?? '';
      expect(Buffer.from(row.privateJwkEncrypted).toString('utf8')).not.toContain(d);
      expect(JSON.stringify(row.publicJwk)).not.toContain('"d"');
    }
  });

  it('generates concurrently without duplicating keys', async () => {
    const kek = testKek();
    await Promise.all([loadSigningKeys(db, kek), loadSigningKeys(db, kek), loadSigningKeys(db, kek)]);
    expect(await db.signingKey.count({ where: { status: 'current' } })).toBe(2);
  });

  it('fails loudly under the wrong KEK', async () => {
    await loadSigningKeys(db, testKek());
    await expect(loadSigningKeys(db, testKek())).rejects.toThrow(KekError);
  });
});
