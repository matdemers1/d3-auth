import type { Settings } from '../admin/settings.js';
import type { Db } from '../db.js';
import type { Logger } from '../log.js';
import type { MailAdapter } from '../mail/adapter.js';
import { SEALED_ADMIN_KEY } from '../admin/sealed-admin.js';
import { AUDIT_EVENTS } from './events.js';

// Alerts (T-6.3, REQ-114).
//
// The audit trail is already the record of everything that happens, so the rules read it rather
// than being told: nothing has to remember to raise an alert, and a restart loses nothing. Each rule
// is a question about recent audit rows. When the answer is yes, and that rule has not sent an alert
// in its quiet period, the owner's alert recipients get one email that lists everything since the
// last one. The alert is itself an audit row (`alert.sent`), which is how the quiet period is known.
//
// What this cannot do is report that mail is down *through mail*. That is the Worker probe's job
// (T-6.4): it watches from outside and sends from Cloudflare.

const MINUTE = 60 * 1000;
const HOUR = 60 * MINUTE;

export interface AlertFinding {
  /** One line each, newest first, already in words a person reads. */
  lines: string[];
}

export interface AlertRule {
  name: string;
  subject: string;
  /** How long after an alert this rule stays quiet. */
  quietFor: number;
  /** Returns a finding when there is something to say about the period since `since`. */
  check(db: Db, since: Date, now: Date): Promise<AlertFinding | undefined>;
}

const when = (date: Date): string => `${date.toISOString().slice(0, 16).replace('T', ' ')} UTC`;

/** Rows of these events after `since`, newest first, up to a sensible number for one email. */
async function eventsSince(db: Db, events: string[], since: Date) {
  return db.auditEvent.findMany({
    where: { event: { in: events }, at: { gt: since } },
    orderBy: { id: 'desc' },
    take: 50,
    select: { event: true, at: true, detail: true, actorUserId: true, targetId: true, ip: true },
  });
}

export const FAILED_LOGIN_SPIKE = 25;
export const SPIKE_WINDOW = 10 * MINUTE;
export const BACKUP_OVERDUE = 36 * HOUR;

export function alertRules(options: { backupsConfigured: boolean }): AlertRule[] {
  const rules: AlertRule[] = [
    {
      name: 'refresh_reuse',
      subject: 'A refresh token was used twice',
      quietFor: HOUR,
      async check(db, since) {
        const rows = await eventsSince(db, [AUDIT_EVENTS.tokenRefreshReused], since);
        if (rows.length === 0) return undefined;
        return {
          lines: [
            'A refresh token that had already been exchanged was presented again. Either an app has a bug, or the token was copied.',
            'D3 Auth has already revoked every token in that grant. Check the app, and whether the person should be reset.',
            '',
            ...rows.map((row) => `${when(row.at)}  app ${(row.detail as { clientId?: string }).clientId ?? '?'}  person ${row.actorUserId ?? '?'}`),
          ],
        };
      },
    },
    {
      name: 'privilege_change',
      subject: 'Somebody was made an admin or owner',
      quietFor: HOUR,
      async check(db, since) {
        const rows = (await eventsSince(db, [AUDIT_EVENTS.personKindChanged, AUDIT_EVENTS.ownerClaimed], since)).filter(
          (row) => row.event === AUDIT_EVENTS.ownerClaimed || ['owner', 'admin'].includes(String((row.detail as { to?: string }).to)),
        );
        if (rows.length === 0) return undefined;
        const people = await db.user.findMany({ where: { id: { in: rows.flatMap((row) => [row.targetId ?? '', row.actorUserId ?? '']) } }, select: { id: true, email: true } });
        const name = (id: string | null): string => people.find((person) => person.id === id)?.email ?? id ?? '?';
        return {
          lines: [
            'If you did not do this, sign in and check People now: an admin can grant access to every app.',
            '',
            ...rows.map((row) =>
              row.event === AUDIT_EVENTS.ownerClaimed
                ? `${when(row.at)}  ${name(row.actorUserId)} claimed the owner account`
                : `${when(row.at)}  ${name(row.targetId)} → ${String((row.detail as { to?: string }).to)} (by ${name(row.actorUserId)})`,
            ),
          ],
        };
      },
    },
    {
      name: 'failed_login_spike',
      subject: 'Many failed sign-ins',
      quietFor: HOUR,
      async check(db, since, now) {
        const from = new Date(Math.max(since.getTime(), now.getTime() - SPIKE_WINDOW));
        const count = await db.auditEvent.count({ where: { event: AUDIT_EVENTS.loginFailure, at: { gt: from } } });
        if (count < FAILED_LOGIN_SPIKE) return undefined;
        const byIp = await db.auditEvent.groupBy({
          by: ['ip'],
          where: { event: AUDIT_EVENTS.loginFailure, at: { gt: from } },
          _count: { _all: true },
          orderBy: { _count: { ip: 'desc' } },
          take: 5,
        });
        return {
          lines: [
            `${String(count)} failed sign-ins in the last ${String(Math.round((now.getTime() - from.getTime()) / MINUTE))} minutes. The throttle is already slowing them; nobody is locked out.`,
            'If it keeps up, check the WAF rate rules (docs/runbooks/deploy.md §5).',
            '',
            'Busiest addresses:',
            ...byIp.map((row) => `  ${row.ip ?? 'unknown'}  ${String(row._count._all)}`),
          ],
        };
      },
    },
    {
      name: 'mail_failure',
      subject: 'Mail is failing',
      quietFor: HOUR,
      async check(db, since) {
        const rows = await eventsSince(db, [AUDIT_EVENTS.mailFailed], since);
        if (rows.length === 0) return undefined;
        return {
          lines: [
            'Invites and reset links are not being delivered. People can still be given the copy-link fallback from the console.',
            'Send a test from Settings to see the driver\'s own error.',
            '',
            ...rows.map((row) => `${when(row.at)}  ${(row.detail as { error?: string }).error ?? 'no error given'}`),
          ],
        };
      },
    },
    {
      name: 'backup_failure',
      subject: 'A backup or restore drill failed',
      quietFor: HOUR,
      async check(db, since) {
        const rows = await eventsSince(db, [AUDIT_EVENTS.backupFailed, AUDIT_EVENTS.drillFailed], since);
        if (rows.length === 0) return undefined;
        return {
          lines: [
            'Last night\'s backup cannot be relied on until this is fixed. docs/runbooks/backup-restore.md has the checks.',
            '',
            ...rows.map((row) => {
              const detail = row.detail as { failure?: string; error?: string; key?: string };
              return `${when(row.at)}  ${row.event === AUDIT_EVENTS.drillFailed ? 'drill' : 'backup'}: ${detail.failure ?? detail.error ?? '?'}${detail.key ? `  (${detail.key})` : ''}`;
            }),
          ],
        };
      },
    },
    {
      name: 'sealed_admin_used',
      subject: 'The sealed admin account was used',
      quietFor: HOUR,
      async check(db, since) {
        const sealed = await db.setting.findUnique({ where: { key: SEALED_ADMIN_KEY } });
        const userId = (sealed?.value as { userId?: string } | null)?.userId;
        if (!userId) return undefined;
        const rows = await db.auditEvent.findMany({
          where: { event: AUDIT_EVENTS.loginSuccess, actorUserId: userId, at: { gt: since } },
          orderBy: { id: 'desc' },
          take: 20,
          select: { at: true, ip: true },
        });
        if (rows.length === 0) return undefined;
        return {
          lines: [
            'Somebody signed in with the credentials from the sealed envelope.',
            'If that was you, finish what you needed and then rotate them: node dist/cli/seal-admin.js --email <address> --rotate',
            'If it was not, suspend that account now and rotate the owner\'s credentials.',
            '',
            ...rows.map((row) => `${when(row.at)}  from ${row.ip ?? 'unknown address'}`),
          ],
        };
      },
    },
  ];

  if (options.backupsConfigured) {
    rules.push({
      name: 'backup_overdue',
      subject: 'No backup for a day and a half',
      quietFor: 24 * HOUR,
      async check(db, _since, now) {
        const last = await db.auditEvent.findFirst({ where: { event: AUDIT_EVENTS.backupCreated }, orderBy: { id: 'desc' }, select: { at: true } });
        // A brand-new instance has not had its first night yet.
        const firstEvent = await db.auditEvent.findFirst({ orderBy: { id: 'asc' }, select: { at: true } });
        if (!firstEvent || now.getTime() - firstEvent.at.getTime() < BACKUP_OVERDUE) return undefined;
        if (last && now.getTime() - last.at.getTime() < BACKUP_OVERDUE) return undefined;
        return {
          lines: [
            last ? `The last backup was taken ${when(last.at)}.` : 'No backup has ever been taken.',
            'The nightly job may not be running — was the container down at the scheduled time? Take one now: node dist/cli/backup.js --now',
          ],
        };
      },
    });
  }
  return rules;
}

export interface AlertDeps {
  db: Db;
  mail: MailAdapter;
  settings: Pick<Settings, 'alerts'>;
  logger: Logger;
  operatorDisplayName: string;
  rules: AlertRule[];
}

/** Checks every rule once. Returns the names of the rules that sent an alert. */
export async function evaluateAlerts(deps: AlertDeps, now = new Date()): Promise<string[]> {
  const { db, mail, settings, logger, rules } = deps;
  const sent: string[] = [];
  const { recipients } = await settings.alerts();

  for (const rule of rules) {
    const last = await db.auditEvent.findFirst({
      where: { event: AUDIT_EVENTS.alertSent, detail: { path: ['rule'], equals: rule.name } },
      orderBy: { id: 'desc' },
      select: { at: true },
    });
    if (last && now.getTime() - last.at.getTime() < rule.quietFor) continue;

    // Everything since the last alert, or the last day when there has never been one.
    const since = last?.at ?? new Date(now.getTime() - 24 * HOUR);
    const finding = await rule.check(db, since, now);
    if (!finding) continue;

    if (recipients.length === 0) {
      logger.warn({ rule: rule.name }, 'an alert rule fired but no alert recipients are set (Settings → Alerts)');
      continue;
    }

    const text = [...finding.lines, '', `— ${deps.operatorDisplayName}'s D3 Auth`].join('\n');
    const results = await Promise.all(recipients.map((to) => mail.send({ to, subject: `[D3 Auth] ${rule.subject}`, text })));
    const delivered = results.filter((result) => result.delivered).length;
    // Stamped with the evaluation time, which is the clock the quiet period is measured on.
    await db.auditEvent.create({ data: { event: AUDIT_EVENTS.alertSent, at: now, detail: { rule: rule.name, recipients: recipients.length, delivered } } });
    logger.warn({ rule: rule.name, delivered, recipients: recipients.length }, 'alert sent');
    sent.push(rule.name);
  }
  return sent;
}

export const ALERT_INTERVAL = 5 * MINUTE;

/** Evaluates the rules every five minutes for as long as the process runs. */
export function startAlerts(deps: AlertDeps): { stop(): void } {
  const timer = setInterval(() => {
    evaluateAlerts(deps).catch((err: unknown) => {
      deps.logger.error({ err }, 'alert evaluation failed');
    });
  }, ALERT_INTERVAL);
  timer.unref();
  return {
    stop() {
      clearInterval(timer);
    },
  };
}
