import * as client from 'openid-client';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { AUDIT_EVENTS } from '../../src/audit/events.js';
import { searchAudit, toCsv } from '../../src/admin/audit-query.js';
import { authorize, Browser, grantAccess, ISSUER, startHarness, USER, webClientConfig, type Harness } from './oidc-harness.js';

// REQ-069 (the screen behind it) and REQ-110 (that there is anything to show).
//
// The second one is the one worth guarding: an audit trail is only as good as the events nobody
// forgot to write. The coverage test below names the events this system promises, and fails when
// one of them stops being written.

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
});

describe('searching the trail', () => {
  it('filters by one event, and by a family of them', async () => {
    const call = await consoleSession();

    const one = (await (await call(`/api/admin/audit?event=${AUDIT_EVENTS.loginSuccess}`)).json()) as { events: { event: string }[] };
    expect(one.events.length).toBeGreaterThan(0);
    expect(one.events.every((row) => row.event === AUDIT_EVENTS.loginSuccess)).toBe(true);

    // A trailing dot means the whole family.
    const family = (await (await call('/api/admin/audit?event=session.')).json()) as { events: { event: string }[] };
    expect(family.events.every((row) => row.event.startsWith('session.'))).toBe(true);
  });

  it('pages newest first, without repeating a row', async () => {
    const first = await searchAudit(h.service.db, { limit: 5 });
    expect(first.events).toHaveLength(5);
    expect(first.nextCursor).toEqual(expect.any(String));

    const second = await searchAudit(h.service.db, { limit: 5, cursor: first.nextCursor });
    const ids = new Set([...first.events, ...second.events].map((row) => row.id));
    expect(ids.size).toBe(first.events.length + second.events.length);
    // Newest first, so every id on the second page is older than every id on the first.
    expect(Number(second.events[0]?.id)).toBeLessThan(Number(first.events.at(-1)?.id));
  });

  it('names the actor, and says so plainly when the account is gone', async () => {
    const page = await searchAudit(h.service.db, { actorUserId: ownerId, limit: 1 });
    expect(page.events[0]?.actor).toMatchObject({ id: ownerId, email: USER.email });

    // An account can be deleted; its audit rows stay, because the trail is append-only.
    const gone = '01a0aa3c-0000-4000-8000-000000000000';
    await h.service.db.auditEvent.create({ data: { event: 'login.success', actorUserId: gone } });
    const found = await searchAudit(h.service.db, { actorUserId: gone, limit: 1 });
    expect(found.events[0]?.actor).toMatchObject({ id: gone, displayName: 'Deleted account' });
  });

  it('exports what is showing, as a spreadsheet can read it', async () => {
    const call = await consoleSession();
    const answer = await call(`/api/admin/audit/export?event=${AUDIT_EVENTS.loginSuccess}`);
    expect(answer.headers.get('content-type')).toContain('text/csv');
    expect(answer.headers.get('content-disposition')).toContain('attachment');

    const csv = await answer.text();
    const [header, ...lines] = csv.split('\n');
    expect(header).toBe('at,event,actor,actor_email,target_type,target_id,ip,detail');
    expect(lines.length).toBeGreaterThan(0);
    expect(lines[0]).toContain('login.success');
  });

  it('quotes a detail containing a comma, so the columns survive', () => {
    const csv = toCsv({
      events: [
        {
          id: '1',
          at: new Date('2026-01-01T00:00:00Z'),
          event: 'app.updated',
          actor: null,
          targetType: 'app',
          targetId: 'x',
          ip: null,
          detail: { changed: ['name', 'redirect_uris'], note: 'a "quoted", comma-ridden thing' },
        },
      ],
    });
    const [, row = ''] = csv.split('\n');
    // Eight fields, whatever the detail contains — the commas inside it stay inside it, which is
    // the entire reason every cell is quoted.
    const fields = [...row.matchAll(/"((?:[^"]|"")*)"/g)].map((match) => match[1]?.replace(/""/g, '"') ?? '');
    expect(fields).toHaveLength(8);
    expect(fields[0]).toBe('2026-01-01T00:00:00.000Z');
    expect(fields[1]).toBe('app.updated');
    // The detail survives as JSON somebody can parse back.
    expect(JSON.parse(fields[7] ?? '{}')).toMatchObject({ note: 'a "quoted", comma-ridden thing' });
  });

  it('is refused to a guest', async () => {
    await h.service.db.user.update({ where: { id: ownerId }, data: { kind: 'guest' } });
    try {
      const call = await consoleSession();
      expect((await call('/api/admin/audit')).status).toBe(403);
    } finally {
      await h.service.db.user.update({ where: { id: ownerId }, data: { kind: 'owner' } });
    }
  });
});

describe('what gets written (REQ-110)', () => {
  /** Runs the action, then says which audit events it appended. */
  async function eventsFrom(action: () => Promise<unknown>): Promise<string[]> {
    const before = await h.service.db.auditEvent.aggregate({ _max: { id: true } });
    await action();
    const after = await h.service.db.auditEvent.findMany({
      where: { id: { gt: before._max.id ?? 0n } },
      select: { event: true },
    });
    return after.map((row) => row.event);
  }

  it('records the mutations the console can make', async () => {
    const call = await consoleSession();
    const clientId = `audited-${Date.now()}`;
    const manifest = {
      client_id: clientId,
      name: 'Audited App',
      client_type: 'confidential_web',
      redirect_uris: [`https://${clientId}.d3auth.test/cb`],
      roles: [{ key: 'member', display: 'Member' }],
    };

    expect(await eventsFrom(() => call('/api/admin/apps', { manifest }))).toContain(AUDIT_EVENTS.appRegistered);
    expect(await eventsFrom(() => call(`/api/admin/people/${ownerId}/access`, { clientId, roles: ['member'] }))).toContain(
      AUDIT_EVENTS.grantCreated,
    );
    expect(await eventsFrom(() => call(`/api/admin/people/${ownerId}/access/revoke`, { clientId }))).toContain(AUDIT_EVENTS.grantRevoked);
    expect(await eventsFrom(() => call(`/api/admin/apps/${clientId}/secret`, {}))).toContain(AUDIT_EVENTS.appSecretRotated);
    expect(await eventsFrom(() => call(`/api/admin/apps/${clientId}/enabled`, { enabled: false }))).toContain(AUDIT_EVENTS.appDisabled);
    expect(await eventsFrom(() => call('/api/admin/groups', { name: `Audited ${Date.now()}` }))).toContain(AUDIT_EVENTS.groupCreated);
    expect(await eventsFrom(() => call('/api/admin/keys/generate', { alg: 'ES256' }))).toContain(AUDIT_EVENTS.keyGenerated);

    await h.service.db.signingKey.deleteMany({ where: { status: 'next' } });
    await h.service.db.app.deleteMany({ where: { clientId } });
  });

  it('records a sign-in, a refusal, and access denied', async () => {
    // A real sign-in, which is the one event everything else is measured against.
    expect(await eventsFrom(() => authorize(h, config, {}, new Browser(h.opFetch)))).toEqual(
      expect.arrayContaining([AUDIT_EVENTS.loginSuccess, AUDIT_EVENTS.sessionStarted]),
    );

    const failed = await eventsFrom(async () => {
      const browser = new Browser(h.opFetch);
      await authorize(h, config, {}, browser, { email: USER.email, password: 'not the password' }).catch(() => undefined);
    });
    expect(failed).toContain(AUDIT_EVENTS.loginFailure);

    // And a refusal by the grant check, which is the invariant this project is built on.
    const denied = await eventsFrom(async () => {
      await h.service.db.grant.deleteMany({ where: { userId: ownerId } });
      await authorize(h, config, {}, new Browser(h.opFetch)).catch(() => undefined);
    });
    expect(denied).toContain(AUDIT_EVENTS.accessDenied);
    await grantAccess(h, ownerId, 'web-app', ['member']);
  });

  it('never writes a secret into the trail', async () => {
    const recent = await h.service.db.auditEvent.findMany({ orderBy: { id: 'desc' }, take: 200, select: { detail: true } });
    const text = JSON.stringify(recent.map((row) => row.detail));
    // The words that would mean somebody had put a credential in a log line.
    expect(text).not.toMatch(/argon2|BEGIN [A-Z ]*PRIVATE KEY|"password"|"secret"|"token"/i);
  });
});
