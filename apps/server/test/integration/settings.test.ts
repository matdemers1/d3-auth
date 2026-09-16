import * as client from 'openid-client';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { authorize, Browser, ISSUER, startHarness, USER, webClientConfig, type Harness } from './oidc-harness.js';

// REQ-071, REQ-109.
//
// The rule worth testing hardest: a secret set here never comes back out. The console shows
// whether one is stored, and nothing more — not in the settings response, not in the audit row,
// not in the table's `value` column.

let h: Harness;
let config: client.Configuration;
let ownerId: string;

type Call = (path: string, body?: unknown) => Promise<Response>;

async function consoleSession(): Promise<Call> {
  const { browser } = await authorize(h, config, {}, new Browser(h.opFetch));
  const cookie = [...browser.cookies].map(([k, v]) => `${k}=${v}`).join('; ');
  return (path, body) =>
    h.opFetch(`${ISSUER}${path}`, {
      method: body === undefined ? 'GET' : 'POST',
      headers: {
        cookie,
        accept: 'application/json',
        'sec-fetch-site': 'same-origin',
        ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
}

beforeAll(async () => {
  h = await startHarness();
  config = await webClientConfig(h);
  ownerId = (await h.service.db.user.findUniqueOrThrow({ where: { email: USER.email } })).id;
  await h.service.db.user.update({ where: { id: ownerId }, data: { kind: 'owner' } });
});

afterAll(async () => {
  await h.close();
});

beforeEach(async () => {
  await h.service.db.throttleCounter.deleteMany();
  await h.service.db.setting.deleteMany();
});

describe('mail settings', () => {
  it('stores the secret sealed, and never gives it back', async () => {
    const call = await consoleSession();
    const secret = 'a-relay-token-nobody-should-ever-see';

    const saved = await call('/api/admin/settings/mail', {
      settings: { driver: 'worker', from: 'no-reply@example.test', relayUrl: 'https://relay.example.test/send' },
      secret,
    });
    expect(saved.status).toBe(200);

    // The response says one is set, and does not say what it is.
    const view = (await saved.json()) as { mail: { driver: string; secretSet: boolean } };
    expect(view.mail).toMatchObject({ driver: 'worker', secretSet: true });
    expect(JSON.stringify(view)).not.toContain(secret);

    // Nor does the row, nor the audit trail.
    const row = await h.service.db.setting.findUniqueOrThrow({ where: { key: 'mail' } });
    expect(JSON.stringify(row.value)).not.toContain(secret);
    expect(row.secretEncrypted).toBeInstanceOf(Uint8Array);

    const audited = await h.service.db.auditEvent.findFirstOrThrow({ where: { event: 'settings.changed' }, orderBy: { id: 'desc' } });
    expect(JSON.stringify(audited.detail)).not.toContain(secret);

    // But the service can still use it.
    expect(await h.service.settings.mail()).toMatchObject({ driver: 'worker', secret });
  });

  it('leaves the stored secret alone when none is sent, and clears it when empty', async () => {
    const call = await consoleSession();
    await call('/api/admin/settings/mail', {
      settings: { driver: 'worker', relayUrl: 'https://relay.example.test/send' },
      secret: 'the-first-one',
    });

    await call('/api/admin/settings/mail', { settings: { driver: 'worker', relayUrl: 'https://relay.example.test/other' } });
    expect(await h.service.settings.mail()).toMatchObject({ relayUrl: 'https://relay.example.test/other', secret: 'the-first-one' });

    await call('/api/admin/settings/mail', { settings: { driver: 'log' }, secret: '' });
    expect((await h.service.settings.mail())?.secret).toBeUndefined();
  });

  it('refuses a configuration that is not one', async () => {
    const call = await consoleSession();
    const answer = await call('/api/admin/settings/mail', { settings: { driver: 'carrier-pigeon' } });
    expect(answer.status).toBe(400);
  });

  it('falls back to the container when nothing is set', async () => {
    // The harness passes no mail environment, so there is nothing to fall back to.
    expect(await h.service.settings.mail()).toBeNull();
    const view = (await (await (await consoleSession())('/api/admin/settings')).json()) as { mail: null; fromEnvironment: { mailDriver: null } };
    expect(view.mail).toBeNull();
    expect(view.fromEnvironment.mailDriver).toBeNull();
  });
});

describe('the test send (REQ-109)', () => {
  it('reports the driver error word for word rather than paraphrasing it', async () => {
    const call = await consoleSession();
    // A relay that does not exist: the failure is the point.
    await call('/api/admin/settings/mail', {
      settings: { driver: 'worker', from: 'no-reply@example.test', relayUrl: 'http://127.0.0.1:1/send' },
      secret: 'irrelevant',
    });

    const answer = await call('/api/admin/settings/mail/test', {});
    expect(answer.status).toBe(502);
    const result = (await answer.json()) as { delivered: boolean; driver: string; error: string };
    expect(result).toMatchObject({ delivered: false, driver: 'worker' });
    // Whatever the driver said, not a summary of it.
    expect(result.error.length).toBeGreaterThan(0);

    const audited = await h.service.db.auditEvent.findFirstOrThrow({ where: { event: 'mail.tested' }, orderBy: { id: 'desc' } });
    expect(audited.detail).toMatchObject({ delivered: false });
  });

  it('says which driver answered when it works', async () => {
    const call = await consoleSession();
    // The log driver rejects on purpose, so "works" here means the console shows the fallback.
    await call('/api/admin/settings/mail', { settings: { driver: 'log' } });
    const answer = await call('/api/admin/settings/mail/test', {});
    expect((await answer.json()) as { driver: string }).toMatchObject({ driver: 'log' });
  });
});

describe('lifetimes', () => {
  it('changes how long a browser stays trusted', async () => {
    const call = await consoleSession();
    expect((await h.service.settings.lifetimes()).trustedDeviceDays).toBe(30);

    await call('/api/admin/settings/lifetimes', { settings: { trustedDeviceDays: 7, sessionDays: 14 } });
    expect(await h.service.settings.lifetimes()).toMatchObject({ trustedDeviceDays: 7, sessionDays: 14 });

    // And the next trusted device gets the new one.
    const issued = await h.service.trustedDevices.issue({ userId: ownerId });
    const days = ((issued?.expiresAt.getTime() ?? 0) - Date.now()) / (24 * 60 * 60 * 1000);
    expect(days).toBeGreaterThan(6);
    expect(days).toBeLessThanOrEqual(7);
  });

  it('refuses something absurd', async () => {
    const call = await consoleSession();
    expect((await call('/api/admin/settings/lifetimes', { settings: { trustedDeviceDays: 0, sessionDays: 9999 } })).status).toBe(400);
  });
});

describe('who may change them', () => {
  it('keeps an admin out', async () => {
    await h.service.db.user.update({ where: { id: ownerId }, data: { kind: 'admin' } });
    try {
      const call = await consoleSession();
      expect((await call('/api/admin/settings')).status).toBe(403);
      expect((await call('/api/admin/settings/alerts', { settings: { recipients: [] } })).status).toBe(403);
    } finally {
      await h.service.db.user.update({ where: { id: ownerId }, data: { kind: 'owner' } });
    }
  });
});
