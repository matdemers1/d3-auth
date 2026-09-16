import { randomBytes } from 'node:crypto';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import { createInvites, INVITE_TTL_HOURS, type Invites } from '../../src/admin/invites.js';
import { createAuditWriter } from '../../src/audit/writer.js';
import { createLogger } from '../../src/log.js';
import { createMailAdapter, type MailDriver, type MailMessage } from '../../src/mail/adapter.js';
import { createAdapterFactory } from '../../src/oidc/adapter.js';
import { createSecretHasher } from '../../src/security/hash.js';
import { testDb, unique } from './helpers.js';

// REQ-065, REQ-078, REQ-040, REQ-108.

const db = testDb();
const hasher = createSecretHasher(randomBytes(32));
const logger = createLogger({ level: 'silent', destination: { write: () => undefined } });
const template = { operatorDisplayName: 'Matthew', issuer: 'https://op.d3auth.test' };

let outbox: MailMessage[];
let invites: Invites;
let admin: { id: string };

/** A driver that can be told to fail, which is how the copy-link fallback gets tested. */
function outboxDriver(failing = false): MailDriver {
  return {
    name: 'test',
    send: (message) => {
      if (failing) return Promise.reject(new Error('relay answered 429: quota exceeded'));
      outbox.push(message);
      return Promise.resolve();
    },
  };
}

const build = (failing = false): Invites =>
  createInvites({
    db,
    mail: createMailAdapter(outboxDriver(failing), logger),
    hasher,
    audit: createAuditWriter(db, logger),
    template,
  });

const tokenFrom = (url: string): string => url.split('/').pop() ?? '';

beforeEach(async () => {
  outbox = [];
  invites = build();
  await db.invite.deleteMany();
  admin = await db.user.create({
    data: { email: `admin-${unique()}@example.com`, username: `admin${unique()}`, displayName: 'Admin', kind: 'owner', status: 'active' },
  });
});

afterAll(async () => {
  await db.$disconnect();
});

describe('creating an invite', () => {
  it('emails a one-time link and stores only its hash', async () => {
    const email = `guest-${unique()}@example.com`;
    const created = await invites.create({ email, invitedByUserId: admin.id });

    expect(created.url).toContain('https://op.d3auth.test/login/invite/');
    expect(created.mail.delivered).toBe(true);
    expect(outbox).toHaveLength(1);
    expect(outbox[0]?.to).toBe(email);
    expect(outbox[0]?.text).toContain(created.url);

    const row = await db.invite.findFirstOrThrow({ where: { email } });
    const token = tokenFrom(created.url);
    expect(row.tokenHash).not.toContain(token);
    expect(row.tokenHash).toMatch(/^[0-9a-f]{64}$/);
    expect(row.expiresAt.getTime()).toBeGreaterThan(Date.now() + (INVITE_TTL_HOURS - 1) * 60 * 60 * 1000);
  });

  it('keeps the invite and reports the failure when mail is down (REQ-108)', async () => {
    const email = `guest-${unique()}@example.com`;
    const created = await build(true).create({ email, invitedByUserId: admin.id });

    expect(created.mail.delivered).toBe(false);
    expect(created.mail.error).toMatch(/quota/);
    // The link still came back, which is what the console shows to copy.
    expect(created.url).toContain('/login/invite/');
    expect(await db.invite.count({ where: { email } })).toBe(1);
    expect(await invites.describe(tokenFrom(created.url))).toMatchObject({ valid: true, email });
  });

  it('refuses to invite someone who already has an account', async () => {
    const email = `existing-${unique()}@example.com`;
    await db.user.create({ data: { email, username: `u${unique()}`, displayName: 'Existing', status: 'active' } });
    await expect(invites.create({ email, invitedByUserId: admin.id })).rejects.toThrow(/already has an account/);
  });

  it('audits who invited whom, without the token', async () => {
    const email = `guest-${unique()}@example.com`;
    const created = await invites.create({ email, invitedByUserId: admin.id, ip: '203.0.113.9' });
    const event = await db.auditEvent.findFirstOrThrow({ where: { event: 'invite.created' }, orderBy: { id: 'desc' } });
    expect(event).toMatchObject({ actorUserId: admin.id });
    expect(JSON.stringify(event.detail)).toContain(email);
    expect(JSON.stringify(event.detail)).not.toContain(tokenFrom(created.url));
  });
});

describe('accepting an invite', () => {
  const details = { username: `guest${unique()}`, displayName: 'A Guest', password: 'otter parade lantern' };

  it('creates an active account with a verified email (REQ-040)', async () => {
    const email = `guest-${unique()}@example.com`;
    const created = await invites.create({ email, invitedByUserId: admin.id });
    const username = `guest${unique()}`;

    const result = await invites.accept({ ...details, username, token: tokenFrom(created.url) });
    expect(result).toMatchObject({ ok: true });

    const user = await db.user.findUniqueOrThrow({ where: { email } });
    expect(user).toMatchObject({ status: 'active', kind: 'guest', emailVerified: true, username });
    const credential = await db.passwordCredential.findFirstOrThrow({ where: { userId: user.id } });
    expect(await hasher.verify(credential.argon2idHash, details.password)).toBe(true);

    const audited = await db.auditEvent.findFirstOrThrow({ where: { event: 'invite.accepted' }, orderBy: { id: 'desc' } });
    expect(audited.actorUserId).toBe(user.id);
  });

  it('works once', async () => {
    const created = await invites.create({ email: `guest-${unique()}@example.com`, invitedByUserId: admin.id });
    const token = tokenFrom(created.url);
    expect(await invites.accept({ ...details, username: `guest${unique()}`, token })).toMatchObject({ ok: true });
    expect(await invites.accept({ ...details, username: `guest${unique()}`, token })).toMatchObject({
      ok: false,
      error: 'invalid_or_expired',
    });
    expect(await invites.describe(token)).toEqual({ valid: false });
  });

  it('lets only one of two simultaneous acceptances win', async () => {
    const created = await invites.create({ email: `guest-${unique()}@example.com`, invitedByUserId: admin.id });
    const token = tokenFrom(created.url);
    const results = await Promise.all([
      invites.accept({ ...details, username: `guest${unique()}`, token }),
      invites.accept({ ...details, username: `guest${unique()}`, token }),
    ]);
    expect(results.filter((r) => r.ok)).toHaveLength(1);
  });

  it('refuses an expired invite and an unknown token', async () => {
    const created = await invites.create({ email: `guest-${unique()}@example.com`, invitedByUserId: admin.id });
    const token = tokenFrom(created.url);
    await db.invite.updateMany({ where: { tokenHash: { not: '' } }, data: { expiresAt: new Date(Date.now() - 1000) } });

    expect(await invites.describe(token)).toEqual({ valid: false });
    expect(await invites.accept({ ...details, username: `guest${unique()}`, token })).toMatchObject({ error: 'invalid_or_expired' });
    expect(await invites.accept({ ...details, username: `guest${unique()}`, token: 'nonsense' })).toMatchObject({
      error: 'invalid_or_expired',
    });
  });

  it('applies the password policy and username rules', async () => {
    const created = await invites.create({ email: `guest-${unique()}@example.com`, invitedByUserId: admin.id });
    const token = tokenFrom(created.url);

    const weak = await invites.accept({ ...details, username: `guest${unique()}`, token, password: 'passwordpassword' });
    expect(weak).toMatchObject({ ok: false, error: 'invalid' });
    const bad = await invites.accept({ ...details, username: 'has spaces', token });
    expect(bad).toMatchObject({ ok: false, error: 'invalid' });
    // Still usable afterwards: a rejected attempt must not burn the invite.
    expect(await invites.describe(token)).toMatchObject({ valid: true });
  });

  it('refuses a username somebody else already has', async () => {
    const taken = `taken${unique()}`;
    await db.user.create({ data: { email: `other-${unique()}@example.com`, username: taken, displayName: 'Other', status: 'active' } });
    const created = await invites.create({ email: `guest-${unique()}@example.com`, invitedByUserId: admin.id });
    expect(await invites.accept({ ...details, username: taken, token: tokenFrom(created.url) })).toMatchObject({
      ok: false,
      error: 'taken',
    });
  });
});

describe('re-enrol links (REQ-039)', () => {
  it('keeps the same account and sub, with a new password', async () => {
    const email = `reset-${unique()}@example.com`;
    const user = await db.user.create({
      data: { email, username: `reset${unique()}`, displayName: 'Before', status: 'active', emailVerified: true },
    });
    await db.passwordCredential.create({ data: { userId: user.id, argon2idHash: await hasher.hash('the old password here') } });

    const link = await invites.createReEnrol({ userId: user.id, email, actorUserId: admin.id });
    expect(outbox.at(-1)?.subject).toBe('Set up your account again');

    const result = await invites.accept({
      token: tokenFrom(link.url),
      username: user.username,
      displayName: 'After',
      password: 'brand new passphrase here',
    });
    expect(result).toMatchObject({ ok: true, userId: user.id });

    const after = await db.user.findUniqueOrThrow({ where: { id: user.id } });
    expect(after.displayName).toBe('After');
    const credentials = await db.passwordCredential.findMany({ where: { userId: user.id } });
    expect(credentials).toHaveLength(1);
    expect(await hasher.verify(credentials[0]?.argon2idHash ?? '', 'brand new passphrase here')).toBe(true);
    expect(await hasher.verify(credentials[0]?.argon2idHash ?? '', 'the old password here')).toBe(false);
  });
});
