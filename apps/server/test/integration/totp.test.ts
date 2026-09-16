import { randomBytes } from 'node:crypto';
import { Secret, TOTP } from 'otpauth';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import { createKekCrypto } from '../../src/security/kek.js';
import { createTotp, PERIOD_SECONDS, type Totp } from '../../src/security/totp.js';
import { testDb, unique } from './helpers.js';

// REQ-033: enrol, confirm, verify — and the same code never twice.

const db = testDb();
const kek = createKekCrypto(randomBytes(32));
let totp: Totp;
let userId: string;

const codeFor = (uri: string, at: Date): string => {
  const parsed = URI.parse(uri);
  return parsed.generate({ timestamp: at.getTime() });
};

// otpauth exposes the parser on the module; this keeps the test honest by generating codes the
// same way a phone would, from the URI the user is shown.
const URI = {
  parse(uri: string): TOTP {
    const url = new URL(uri.replace('otpauth://', 'https://'));
    return new TOTP({
      issuer: url.searchParams.get('issuer') ?? '',
      label: decodeURIComponent(url.pathname.slice(1)),
      algorithm: url.searchParams.get('algorithm') ?? 'SHA1',
      digits: Number(url.searchParams.get('digits') ?? 6),
      period: Number(url.searchParams.get('period') ?? 30),
      secret: Secret.fromBase32(url.searchParams.get('secret') ?? ''),
    });
  },
};

beforeEach(async () => {
  totp = createTotp(db, kek, 'D3 Auth');
  const user = await db.user.create({
    data: { email: `totp-${unique()}@example.com`, username: `totp${unique()}`, displayName: 'TOTP Person', status: 'active' },
  });
  userId = user.id;
});

afterAll(async () => {
  await db.$disconnect();
});

describe('TOTP enrolment', () => {
  it('hands back a scannable URI and a key to type, and seals the secret', async () => {
    const enrolment = await totp.begin({ userId, accountName: 'person@example.com' });

    expect(enrolment.uri).toMatch(/^otpauth:\/\/totp\//);
    expect(enrolment.uri).toContain('issuer=D3%20Auth');
    expect(enrolment.uri).toContain(`secret=${enrolment.manualKey}`);
    expect(enrolment.manualKey).toMatch(/^[A-Z2-7]{32}$/);

    const row = await db.totpCredential.findUniqueOrThrow({ where: { id: enrolment.credentialId } });
    expect(Buffer.from(row.secretEncrypted).toString('utf8')).not.toContain(enrolment.manualKey);
    expect(row.confirmedAt).toBeNull();
  });

  it('only counts once confirmed with a real code', async () => {
    const enrolment = await totp.begin({ userId, accountName: 'person@example.com' });
    const at = new Date();

    expect(await totp.verify({ userId, code: codeFor(enrolment.uri, at), at })).toBe(false);
    expect(await totp.confirm({ userId, credentialId: enrolment.credentialId, code: '000000', at })).toBe(false);
    expect(await totp.confirm({ userId, credentialId: enrolment.credentialId, code: codeFor(enrolment.uri, at), at })).toBe(true);

    const row = await db.totpCredential.findUniqueOrThrow({ where: { id: enrolment.credentialId } });
    expect(row.confirmedAt).not.toBeNull();
  });

  it('will not confirm somebody else\'s enrolment', async () => {
    const enrolment = await totp.begin({ userId, accountName: 'person@example.com' });
    const other = await db.user.create({
      data: { email: `other-${unique()}@example.com`, username: `other${unique()}`, displayName: 'Other', status: 'active' },
    });
    const at = new Date();
    expect(
      await totp.confirm({ userId: other.id, credentialId: enrolment.credentialId, code: codeFor(enrolment.uri, at), at }),
    ).toBe(false);
  });
});

describe('TOTP verification', () => {
  const enrol = async (): Promise<{ uri: string; at: Date }> => {
    const at = new Date();
    const enrolment = await totp.begin({ userId, accountName: 'person@example.com' });
    await totp.confirm({ userId, credentialId: enrolment.credentialId, code: codeFor(enrolment.uri, at), at });
    return { uri: enrolment.uri, at };
  };

  it('accepts the current code', async () => {
    const { uri } = await enrol();
    const later = new Date(Date.now() + PERIOD_SECONDS * 1000);
    expect(await totp.verify({ userId, code: codeFor(uri, later), at: later })).toBe(true);
  });

  it('refuses the same code a second time (REQ-033)', async () => {
    const { uri } = await enrol();
    const at = new Date(Date.now() + PERIOD_SECONDS * 1000);
    const code = codeFor(uri, at);

    expect(await totp.verify({ userId, code, at })).toBe(true);
    expect(await totp.verify({ userId, code, at })).toBe(false);
  });

  it('refuses an older code even if it is still inside the window', async () => {
    const { uri } = await enrol();
    const now = new Date(Date.now() + PERIOD_SECONDS * 2000);
    const previous = new Date(now.getTime() - PERIOD_SECONDS * 1000);

    expect(await totp.verify({ userId, code: codeFor(uri, now), at: now })).toBe(true);
    expect(await totp.verify({ userId, code: codeFor(uri, previous), at: now })).toBe(false);
  });

  it('allows one step either side, for a phone with a slightly wrong clock', async () => {
    const { uri } = await enrol();
    const at = new Date(Date.now() + PERIOD_SECONDS * 3000);
    const aStepAhead = new Date(at.getTime() + PERIOD_SECONDS * 1000);
    expect(await totp.verify({ userId, code: codeFor(uri, aStepAhead), at })).toBe(true);
  });

  it('refuses a code from far outside the window, and nonsense', async () => {
    const { uri } = await enrol();
    const at = new Date(Date.now() + PERIOD_SECONDS * 5000);
    const longAgo = new Date(at.getTime() - PERIOD_SECONDS * 10_000);

    expect(await totp.verify({ userId, code: codeFor(uri, longAgo), at })).toBe(false);
    expect(await totp.verify({ userId, code: '000000', at })).toBe(false);
    expect(await totp.verify({ userId, code: 'not-a-code', at })).toBe(false);
  });

  it('ignores spaces, because people type what they see', async () => {
    const { uri } = await enrol();
    const at = new Date(Date.now() + PERIOD_SECONDS * 7000);
    const code = codeFor(uri, at);
    expect(await totp.verify({ userId, code: `${code.slice(0, 3)} ${code.slice(3)}`, at })).toBe(true);
  });

  it('verifies against any confirmed credential the person has', async () => {
    const first = await enrol();
    const at = new Date(Date.now() + PERIOD_SECONDS * 9000);
    const second = await totp.begin({ userId, accountName: 'person@example.com', label: 'Backup phone' });
    await totp.confirm({ userId, credentialId: second.credentialId, code: codeFor(second.uri, at), at });

    const later = new Date(at.getTime() + PERIOD_SECONDS * 1000);
    expect(await totp.verify({ userId, code: codeFor(second.uri, later), at: later })).toBe(true);
    expect(await totp.verify({ userId, code: codeFor(first.uri, later), at: later })).toBe(true);
  });

  it('lists and removes credentials', async () => {
    const enrolment = await totp.begin({ userId, accountName: 'person@example.com' });
    expect(await totp.list(userId)).toHaveLength(1);
    expect(await totp.remove({ userId, credentialId: enrolment.credentialId })).toBe(true);
    expect(await totp.list(userId)).toHaveLength(0);
    expect(await totp.remove({ userId, credentialId: enrolment.credentialId })).toBe(false);
  });
});
