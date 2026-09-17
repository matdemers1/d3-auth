import type * as client from 'openid-client';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { alertRules, evaluateAlerts, FAILED_LOGIN_SPIKE, type AlertDeps } from '../../src/audit/alerts.js';
import { createLogger } from '../../src/log.js';
import type { MailMessage } from '../../src/mail/adapter.js';
import { authorize, Browser, startHarness, USER, WEB_CLIENT, webClientConfig, type Harness } from './oidc-harness.js';
import { tokenRequest } from '../adversarial/support.js';
import { prepareTestDatabase, siblingDatabase } from './test-database.js';

// Alerts (T-6.3, REQ-114). The rules read the audit trail, so each test writes the rows a real
// event would — or, for refresh reuse, commits the real event — and checks what arrives, and that it
// arrives once an hour rather than once per event.
//
// It runs against a database of its own: the tests move a clock forward and write audit rows at
// those times, and the audit table refuses deletes, so in the shared database every later file that
// asks "what happened since I started?" would see them.

let h: Harness;
let config: client.Configuration;
const logger = createLogger({ level: 'silent' });
let sent: MailMessage[] = [];

const deps = (overrides: Partial<AlertDeps> = {}): AlertDeps => ({
  db: h.service.db,
  mail: {
    driver: 'fake',
    send: (message) => {
      sent.push(message);
      return Promise.resolve({ delivered: true, driver: 'fake' });
    },
  },
  settings: { alerts: () => Promise.resolve({ recipients: ['owner@example.com'] }) },
  logger,
  operatorDisplayName: 'Matthew',
  rules: alertRules({ backupsConfigured: true }),
  ...overrides,
});

/** The audit table refuses deletes, so each test starts its clock after everything before it. */
let now: Date;
const later = (minutes: number): Date => new Date(now.getTime() + minutes * 60_000);

const shared = process.env.DATABASE_URL ?? '';

beforeAll(async () => {
  const own = siblingDatabase(shared, 'alerts');
  await prepareTestDatabase(own);
  process.env.DATABASE_URL = own;
  h = await startHarness();
  config = await webClientConfig(h);
});

afterAll(async () => {
  await h.close();
  process.env.DATABASE_URL = shared;
});

beforeEach(async () => {
  sent = [];
  await h.service.db.throttleCounter.deleteMany();
  // Well past every quiet period any earlier test could have started, and after every row so far.
  const last = await h.service.db.auditEvent.findFirst({ orderBy: { at: 'desc' }, select: { at: true } });
  now = new Date(Math.max(Date.now(), last?.at.getTime() ?? 0) + 3 * 24 * 60 * 60_000);
  // Rules look back from the last alert; record one per rule "now" so earlier tests' rows are behind us.
  for (const rule of alertRules({ backupsConfigured: true })) {
    await h.service.db.auditEvent.create({ data: { event: 'alert.sent', at: new Date(now.getTime() - 25 * 60 * 60_000), detail: { rule: rule.name, seed: true } } });
  }
  // And a recent backup, so the overdue rule stays out of tests that are not about it.
  await h.service.db.auditEvent.create({ data: { event: 'backup.created', at: now, detail: { seed: true } } });
});

const rulesFired = (names: string[], name: string): boolean => names.includes(name);

describe('a refresh token used twice', () => {
  it('is recorded when it really happens, and sends one alert', async () => {
    const flow = await authorize(h, config, { scope: 'openid offline_access', prompt: 'consent' }, new Browser(h.opFetch));
    const code = await tokenRequest(h, { grant_type: 'authorization_code', code: flow.callback.searchParams.get('code') ?? '', redirect_uri: 'https://rp.d3auth.test/cb', code_verifier: flow.verifier });
    const refresh = String(code.body.refresh_token);
    await tokenRequest(h, { grant_type: 'refresh_token', refresh_token: refresh });
    const reused = await tokenRequest(h, { grant_type: 'refresh_token', refresh_token: refresh });
    expect(reused.body.error).toBe('invalid_grant');

    const row = await h.service.db.auditEvent.findFirstOrThrow({ where: { event: 'token.refresh_reused' }, orderBy: { id: 'desc' } });
    expect(row.detail).toMatchObject({ clientId: WEB_CLIENT.clientId });
    // Move the reuse into this test's clock.
    await h.service.db.auditEvent.create({ data: { event: 'token.refresh_reused', at: later(1), detail: { clientId: WEB_CLIENT.clientId } } });

    const fired = await evaluateAlerts(deps(), later(2));
    expect(rulesFired(fired, 'refresh_reuse')).toBe(true);
    expect(sent.find((message) => message.subject === '[D3 Auth] A refresh token was used twice')?.text).toContain(WEB_CLIENT.clientId);
  });
});

describe('somebody made an admin', () => {
  it('alerts, naming who and by whom', async () => {
    const person = await h.service.db.user.findUniqueOrThrow({ where: { email: USER.email } });
    await h.service.db.auditEvent.create({ data: { event: 'person.kind_changed', at: later(1), actorUserId: person.id, targetId: person.id, detail: { from: 'guest', to: 'admin' } } });
    const fired = await evaluateAlerts(deps(), later(2));
    expect(rulesFired(fired, 'privilege_change')).toBe(true);
    expect(sent[0]?.text).toContain(`${USER.email} → admin`);
  });

  it('says nothing when somebody is made a guest', async () => {
    await h.service.db.auditEvent.create({ data: { event: 'person.kind_changed', at: later(1), detail: { from: 'admin', to: 'guest' } } });
    expect(rulesFired(await evaluateAlerts(deps(), later(2)), 'privilege_change')).toBe(false);
  });
});

describe('failed sign-ins', () => {
  it('alert past the spike threshold, not below it', async () => {
    const fail = (n: number, minute: number) =>
      h.service.db.auditEvent.createMany({ data: Array.from({ length: n }, () => ({ event: 'login.failure', at: later(minute), ip: '203.0.113.9', detail: {} })) });

    await fail(FAILED_LOGIN_SPIKE - 1, 1);
    expect(rulesFired(await evaluateAlerts(deps(), later(2)), 'failed_login_spike')).toBe(false);

    await fail(1, 2);
    const fired = await evaluateAlerts(deps(), later(3));
    expect(rulesFired(fired, 'failed_login_spike')).toBe(true);
    expect(sent.find((message) => message.subject.includes('failed sign-ins'))?.text).toContain('203.0.113.9');
  });
});

describe('the quiet period', () => {
  it('sends once an hour however many events arrive, then summarises what it held back', async () => {
    const reuse = (minute: number) => h.service.db.auditEvent.create({ data: { event: 'mail.failed', at: later(minute), detail: { error: `relay said no at ${String(minute)}` } } });

    await reuse(1);
    expect(rulesFired(await evaluateAlerts(deps(), later(2)), 'mail_failure')).toBe(true);
    await reuse(10);
    await reuse(20);
    expect(rulesFired(await evaluateAlerts(deps(), later(30)), 'mail_failure')).toBe(false);

    sent = [];
    const fired = await evaluateAlerts(deps(), later(70));
    expect(rulesFired(fired, 'mail_failure')).toBe(true);
    // Both held-back failures are in the one email.
    expect(sent[0]?.text).toContain('relay said no at 10');
    expect(sent[0]?.text).toContain('relay said no at 20');
  });
});

describe('backups', () => {
  it('alert when a drill fails, with the reason', async () => {
    await h.service.db.auditEvent.create({ data: { event: 'backup.drill_failed', at: later(1), detail: { failure: 'the KEK on this host is not the one that sealed this bundle' } } });
    const fired = await evaluateAlerts(deps(), later(2));
    expect(rulesFired(fired, 'backup_failure')).toBe(true);
    expect(sent.find((message) => message.subject.includes('restore drill'))?.text).toContain('the KEK on this host');
  });

  it('alert when none has been taken for a day and a half — only when backups are configured', async () => {
    const quiet = later(37 * 60);
    expect(rulesFired(await evaluateAlerts(deps({ rules: alertRules({ backupsConfigured: false }) }), quiet), 'backup_overdue')).toBe(false);
    expect(rulesFired(await evaluateAlerts(deps(), quiet), 'backup_overdue')).toBe(true);
  });
});

describe('with nobody to tell', () => {
  it('sends nothing and records no alert, so the first recipient added still hears about it', async () => {
    await h.service.db.auditEvent.create({ data: { event: 'backup.failed', at: later(1), detail: { error: 'bucket gone' } } });
    const fired = await evaluateAlerts(deps({ settings: { alerts: () => Promise.resolve({ recipients: [] }) } }), later(2));
    expect(fired).toEqual([]);
    expect(rulesFired(await evaluateAlerts(deps(), later(3)), 'backup_failure')).toBe(true);
  });
});

describe('the sealed admin', () => {
  it('alerts the moment the envelope account signs in, and not for anybody else', async () => {
    const person = await h.service.db.user.create({ data: { email: `sealed-alert-${String(Date.now())}@example.com`, username: `sealedalert${String(Date.now())}`, displayName: 'Sealed admin', kind: 'admin', status: 'active' } });
    await h.service.db.setting.upsert({ where: { key: 'sealed_admin' }, create: { key: 'sealed_admin', value: { userId: person.id } }, update: { value: { userId: person.id } } });

    await h.service.db.auditEvent.create({ data: { event: 'login.success', at: later(1), detail: {} } });
    expect(rulesFired(await evaluateAlerts(deps(), later(2)), 'sealed_admin_used')).toBe(false);

    await h.service.db.auditEvent.create({ data: { event: 'login.success', at: later(3), actorUserId: person.id, ip: '203.0.113.9', detail: {} } });
    expect(rulesFired(await evaluateAlerts(deps(), later(4)), 'sealed_admin_used')).toBe(true);
    expect(sent.find((message) => message.subject.includes('sealed admin'))?.text).toContain('203.0.113.9');
  });
});
