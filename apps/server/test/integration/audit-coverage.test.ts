import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as client from 'openid-client';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { AUDIT_EVENTS } from '../../src/audit/events.js';
import { authorize, Browser, ISSUER, startHarness, USER, webClientConfig, type Harness } from './oidc-harness.js';

// REQ-110, the coverage half: every event this system declares must actually be written by
// something, and every mutation the console can make must write one.
//
// The trap this guards against is a name that reads like coverage and is not. It is easy to add
// `somethingImportant: 'something.important'` to the registry, feel covered, and never emit it —
// and then to go looking for it in the trail one day when it matters. So the first test compares
// the registry against the source, and an event that is deliberately not emitted has to say so
// here, out loud, with a reason.

const SRC = fileURLToPath(new URL('../../src/', import.meta.url));

/** Declared but never written, each with the reason it is allowed to stay. */
const NOT_EMITTED: Record<string, string> = {
  'dev.seed.user': 'the dev seeder writes rows directly; it never runs on a real instance',
  'dev.seed.app': 'same — the dev seeder, not a path any operator reaches',
};

async function sourceFiles(dir: string): Promise<string[]> {
  const entries = await readdir(dir, { withFileTypes: true });
  const found = await Promise.all(
    entries.map(async (entry) => {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) return entry.name === 'generated' ? [] : sourceFiles(path);
      return entry.name.endsWith('.ts') ? [path] : [];
    }),
  );
  return found.flat();
}

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
  await h.service.db.group.deleteMany({});
  await h.close();
});

beforeEach(async () => {
  await h.service.db.throttleCounter.deleteMany();
});

describe('the registry', () => {
  it('declares nothing that no code ever writes', async () => {
    const files = await sourceFiles(SRC);
    const text = (await Promise.all(files.filter((path) => !path.endsWith('events.ts')).map((path) => readFile(path, 'utf8')))).join('\n');

    const emitted = new Set([...text.matchAll(/AUDIT_EVENTS\.([A-Za-z]+)/g)].map((match) => match[1]));
    const orphans = Object.entries(AUDIT_EVENTS)
      .filter(([key]) => !emitted.has(key))
      .map(([, value]) => value)
      .filter((value) => !(value in NOT_EMITTED));

    expect(orphans, 'declared audit events that nothing writes — emit them or excuse them in NOT_EMITTED').toEqual([]);
  });

  it('keeps no stale excuses', () => {
    const declared = new Set<string>(Object.values(AUDIT_EVENTS));
    expect(Object.keys(NOT_EMITTED).filter((name) => !declared.has(name))).toEqual([]);
  });
});

describe('the newer mutations write their row (REQ-110)', () => {
  /** Runs the action, then says which audit events it appended. */
  async function eventsFrom(action: () => Promise<unknown>): Promise<string[]> {
    const before = await h.service.db.auditEvent.aggregate({ _max: { id: true } });
    await action();
    const after = await h.service.db.auditEvent.findMany({ where: { id: { gt: before._max.id ?? 0n } }, select: { event: true } });
    return after.map((row) => row.event);
  }

  it('records settings, a mail test, an export and an import', async () => {
    const call = await consoleSession();

    expect(await eventsFrom(() => call('/api/admin/settings/alerts', { settings: { recipients: [] } }))).toContain(
      AUDIT_EVENTS.settingsChanged,
    );
    expect(await eventsFrom(() => call('/api/admin/settings/mail/test', {}))).toContain(AUDIT_EVENTS.mailTested);
    expect(await eventsFrom(() => call('/api/admin/state/export'))).toContain(AUDIT_EVENTS.stateExported);

    const clientId = `coverage-${Date.now()}`;
    const state = {
      version: 1,
      apps: [
        {
          client_id: clientId,
          name: 'Coverage App',
          client_type: 'public_native',
          redirect_uris: [`https://${clientId}.d3auth.test/cb`],
          roles: [{ key: 'member', display: 'Member' }],
        },
      ],
      people: [],
      groups: [],
      settings: {},
    };
    expect(await eventsFrom(() => call('/api/admin/state/import', { state }))).toContain(AUDIT_EVENTS.stateImported);
    await h.service.db.app.deleteMany({ where: { clientId } });
  });

  it('records the whole life of a group', async () => {
    const call = await consoleSession();
    const name = `Coverage ${Date.now()}`;
    const group = (await (await call('/api/admin/groups', { name })).json()) as { id: string };

    expect(await eventsFrom(() => call(`/api/admin/groups/${group.id}`, { name, description: 'Changed' }))).toContain(
      AUDIT_EVENTS.groupUpdated,
    );
    expect(await eventsFrom(() => call(`/api/admin/groups/${group.id}/members`, { userIds: [ownerId] }))).toContain(
      AUDIT_EVENTS.groupMembersChanged,
    );
    expect(await eventsFrom(() => call(`/api/admin/groups/${group.id}/access`, { clientId: 'web-app', roles: ['member'] }))).toContain(
      AUDIT_EVENTS.groupGrantChanged,
    );
    expect(await eventsFrom(() => call(`/api/admin/groups/${group.id}/access/revoke`, { clientId: 'web-app' }))).toContain(
      AUDIT_EVENTS.groupGrantRevoked,
    );
    expect(await eventsFrom(() => call(`/api/admin/groups/${group.id}/remove`, {}))).toContain(AUDIT_EVENTS.groupRemoved);
  });

  it('records what happens to a person', async () => {
    const call = await consoleSession();
    const person = await h.service.db.user.upsert({
      where: { email: 'coverage@example.com' },
      create: { email: 'coverage@example.com', username: 'coverage', displayName: 'Coverage Person', status: 'active' },
      update: { status: 'active', kind: 'guest' },
    });

    expect(await eventsFrom(() => call(`/api/admin/people/${person.id}/suspend`, {}))).toContain(AUDIT_EVENTS.personSuspended);
    expect(await eventsFrom(() => call(`/api/admin/people/${person.id}/reactivate`, {}))).toContain(AUDIT_EVENTS.personReactivated);
    expect(await eventsFrom(() => call(`/api/admin/people/${person.id}/reset`, {}))).toContain(AUDIT_EVENTS.personReset);
    expect(await eventsFrom(() => call('/api/admin/invites', { email: `coverage-${Date.now()}@example.com` }))).toContain(
      AUDIT_EVENTS.inviteCreated,
    );
  });
});
