import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createAdapterFactory } from '../../src/oidc/adapter.js';
import { testDb, unique } from './helpers.js';

const db = testDb();
const factory = createAdapterFactory(db);

// Every model oidc-provider 9 persists through an adapter.
const KINDS = [
  'Session',
  'AccessToken',
  'AuthorizationCode',
  'RefreshToken',
  'DeviceCode',
  'ClientCredentials',
  'Client',
  'InitialAccessToken',
  'RegistrationAccessToken',
  'Interaction',
  'ReplayDetection',
  'PushedAuthorizationRequest',
  'Grant',
  'BackchannelAuthenticationRequest',
] as const;

beforeEach(async () => {
  await db.oidcPayload.deleteMany();
  vi.useRealTimers();
});

afterAll(async () => {
  await db.$disconnect();
});

describe.each(KINDS)('adapter contract: %s (REQ-001)', (kind) => {
  const adapter = factory(kind);

  it('upsert then find returns the payload', async () => {
    const id = unique();
    await adapter.upsert(id, { jti: id, kind, clientId: 'c1', grantId: 'g1' }, 60);
    expect(await adapter.find(id)).toEqual({ jti: id, kind, clientId: 'c1', grantId: 'g1' });
  });

  it('upsert replaces an existing payload', async () => {
    const id = unique();
    await adapter.upsert(id, { jti: id, accountId: 'a' }, 60);
    await adapter.upsert(id, { jti: id, accountId: 'b' }, 60);
    expect(await adapter.find(id)).toMatchObject({ accountId: 'b' });
  });

  it('find of an unknown id is undefined', async () => {
    expect(await adapter.find('missing')).toBeUndefined();
  });

  it('does not return expired payloads', async () => {
    const id = unique();
    await adapter.upsert(id, { jti: id }, 1);
    vi.useFakeTimers({ now: Date.now() + 2_000, toFake: ['Date'] });
    expect(await adapter.find(id)).toBeUndefined();
  });

  it('keeps payloads without an expiry', async () => {
    const id = unique();
    await adapter.upsert(id, { jti: id });
    expect(await adapter.find(id)).toMatchObject({ jti: id });
  });

  it('consume marks the payload consumed', async () => {
    const id = unique();
    await adapter.upsert(id, { jti: id }, 60);
    await adapter.consume(id);
    const found = await adapter.find(id);
    expect(found?.consumed).toEqual(expect.any(Number));
  });

  it('destroy removes the payload', async () => {
    const id = unique();
    await adapter.upsert(id, { jti: id }, 60);
    await adapter.destroy(id);
    expect(await adapter.find(id)).toBeUndefined();
  });

  it('findByUid and findByUserCode look up secondary keys', async () => {
    const id = unique();
    await adapter.upsert(id, { jti: id, uid: `uid-${id}`, userCode: `UC-${id}` }, 60);
    expect(await adapter.findByUid(`uid-${id}`)).toMatchObject({ jti: id });
    expect(await adapter.findByUserCode(`UC-${id}`)).toMatchObject({ jti: id });
    expect(await adapter.findByUid('nope')).toBeUndefined();
  });
});

describe('adapter isolation and revocation', () => {
  it('the same id under two kinds does not collide', async () => {
    const id = unique();
    await factory('AccessToken').upsert(id, { jti: id, accountId: 'access' }, 60);
    await factory('RefreshToken').upsert(id, { jti: id, accountId: 'refresh' }, 60);
    expect(await factory('AccessToken').find(id)).toMatchObject({ accountId: 'access' });
    expect(await factory('RefreshToken').find(id)).toMatchObject({ accountId: 'refresh' });
  });

  it('revokeByGrantId removes the whole family across kinds and nothing else', async () => {
    const grantId = unique();
    const ids = { code: unique(), access: unique(), refresh: unique(), other: unique() };
    await factory('AuthorizationCode').upsert(ids.code, { grantId }, 60);
    await factory('AccessToken').upsert(ids.access, { grantId }, 60);
    await factory('RefreshToken').upsert(ids.refresh, { grantId }, 60);
    await factory('AccessToken').upsert(ids.other, { grantId: 'someone-else' }, 60);

    await factory('RefreshToken').revokeByGrantId(grantId);

    expect(await factory('AuthorizationCode').find(ids.code)).toBeUndefined();
    expect(await factory('AccessToken').find(ids.access)).toBeUndefined();
    expect(await factory('RefreshToken').find(ids.refresh)).toBeUndefined();
    expect(await factory('AccessToken').find(ids.other)).toMatchObject({ grantId: 'someone-else' });
  });
});
