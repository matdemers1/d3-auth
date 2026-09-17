import type { Db } from '../db.js';
import { searchAudit, type AuditRow } from './audit-query.js';
import type { ReadinessProbe } from '../health.js';
import { MINIMUM_OVERLAP_MS } from '../oidc/keys.js';

// The console's front page (REQ-073).
//
// A home screen that only says "everything is fine" is worthless, because the one time it matters
// is the time it is wrong. So each tile here is derived from the same thing the service itself
// acts on — the readiness probe, the key rows, the last real mail send — rather than from a
// separate cheerful summary that can drift.
//
// The first-run checklist is the other half. A fresh instance is not broken, it is empty, and the
// difference should be obvious at a glance.

export interface Tile {
  key: 'database' | 'keys' | 'mail' | 'migrations' | 'backups';
  ok: boolean;
  /** One line a person can act on. Never a stack trace. */
  detail: string;
}

export interface OverviewStep {
  key: 'owner' | 'app' | 'person' | 'mail';
  done: boolean;
  label: string;
  href: string;
}

export interface Overview {
  tiles: Tile[];
  counts: { people: number; apps: number; groups: number; signInsToday: number };
  /** The last ten things that happened, resolved the same way the Audit screen resolves them. */
  recent: AuditRow[];
  /** Absent once the instance is past its first day: it is scaffolding, not furniture. */
  checklist: OverviewStep[] | null;
}

const ago = (date: Date): string => {
  const minutes = Math.round((Date.now() - date.getTime()) / 60_000);
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${String(minutes)} minutes ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${String(hours)} hours ago`;
  return `${String(Math.round(hours / 24))} days ago`;
};

/** A backup older than this is late: the job runs nightly (ADR-004). */
const BACKUP_LATE_MS = 36 * 60 * 60 * 1000;

export async function overview(db: Db, readiness: ReadinessProbe, options: { backupsConfigured?: boolean } = {}): Promise<Overview> {
  const startOfDay = new Date();
  startOfDay.setHours(0, 0, 0, 0);

  const [checks, people, apps, groups, signInsToday, keys, lastMail, recent, owners] = await Promise.all([
    readiness(),
    db.user.count(),
    db.app.count(),
    db.group.count(),
    db.auditEvent.count({ where: { event: 'login.success', at: { gte: startOfDay } } }),
    db.signingKey.findMany({ where: { status: { in: ['current', 'next', 'retiring'] } }, select: { alg: true, status: true, createdAt: true } }),
    db.auditEvent.findFirst({ where: { event: 'mail.tested' }, orderBy: { id: 'desc' } }),
    searchAudit(db, { limit: 10 }),
    db.user.count({ where: { kind: 'owner' } }),
  ]);
  const [lastBackup, lastBackupFailure, lastDrill] = await Promise.all([
    db.auditEvent.findFirst({ where: { event: 'backup.created' }, orderBy: { id: 'desc' }, select: { at: true } }),
    db.auditEvent.findFirst({ where: { event: 'backup.failed' }, orderBy: { id: 'desc' }, select: { at: true } }),
    db.auditEvent.findFirst({ where: { event: { in: ['backup.drill_passed', 'backup.drill_failed'] } }, orderBy: { id: 'desc' }, select: { at: true, event: true, detail: true } }),
  ]);

  const current = keys.filter((key) => key.status === 'current');
  const pending = keys.filter((key) => key.status === 'next');
  const readyPending = pending.filter((key) => Date.now() - key.createdAt.getTime() >= MINIMUM_OVERLAP_MS);
  const delivered = (lastMail?.detail as { delivered?: boolean } | null)?.delivered === true;

  const tiles: Tile[] = [
    {
      key: 'database',
      ok: checks.database === true,
      detail: checks.database === true ? 'Answering.' : 'Not answering. Nothing can sign in.',
    },
    {
      key: 'keys',
      ok: checks.signingKeys === true,
      detail:
        checks.signingKeys === true
          ? readyPending.length > 0
            ? `${current.map((key) => key.alg).join(' and ')} signing. ${String(readyPending.length)} key(s) waited long enough to be promoted.`
            : `${current.map((key) => key.alg).join(' and ')} signing.`
          : 'No current key for one of the algorithms. New sign-ins will fail.',
    },
    {
      key: 'migrations',
      ok: checks.migrations === true,
      detail: checks.migrations === true ? 'The schema matches this build.' : 'This build expects a migration that has not run.',
    },
    {
      key: 'mail',
      ok: delivered,
      detail: lastMail
        ? delivered
          ? `Last test delivered ${ago(lastMail.at)}.`
          : `Last test failed ${ago(lastMail.at)}. Invites and recovery links are not arriving.`
        : 'Never tested. Send one from Settings before anybody needs an invite.',
    },
    backupTile(options.backupsConfigured === true, lastBackup?.at, lastBackupFailure?.at, lastDrill ?? undefined),
  ];

  // The checklist earns its place only while something on it is undone.
  const steps: OverviewStep[] = [
    { key: 'owner', done: owners > 0, label: 'Claim the owner account', href: '/admin/people' },
    { key: 'app', done: apps > 0, label: 'Register your first app', href: '/admin/apps/new' },
    { key: 'person', done: people > 1, label: 'Invite somebody', href: '/admin/people' },
    { key: 'mail', done: delivered, label: 'Send a test message', href: '/admin/settings' },
  ];

  return {
    tiles,
    counts: { people, apps, groups, signInsToday },
    recent: recent.events,
    checklist: steps.every((step) => step.done) ? null : steps,
  };
}

/**
 * Backups are fine only when the last one is recent, nothing has failed since, and the last drill
 * of one passed. A backup nobody has restored is a hope, so the drill counts as much as the upload.
 */
function backupTile(
  configured: boolean,
  lastBackup: Date | undefined,
  lastFailure: Date | undefined,
  lastDrill: { at: Date; event: string; detail: unknown } | undefined,
): Tile {
  if (!configured) {
    return { key: 'backups', ok: false, detail: 'Not set up. Nothing leaves this host; see docs/runbooks/backup-restore.md.' };
  }
  if (lastFailure && (!lastBackup || lastFailure > lastBackup)) {
    return { key: 'backups', ok: false, detail: `Last backup failed ${ago(lastFailure)}. The alert email has the reason.` };
  }
  if (!lastBackup) return { key: 'backups', ok: false, detail: 'None taken yet. The first runs tonight, or take one now with the backup command.' };
  if (Date.now() - lastBackup.getTime() > BACKUP_LATE_MS) {
    return { key: 'backups', ok: false, detail: `Last backup ${ago(lastBackup)} — the nightly job has not run.` };
  }
  if (lastDrill?.event === 'backup.drill_failed') {
    const failure = (lastDrill.detail as { failure?: string } | null)?.failure;
    return { key: 'backups', ok: false, detail: `Backed up ${ago(lastBackup)}, but the restore drill failed ${ago(lastDrill.at)}${failure ? `: ${failure}` : ''}.` };
  }
  if (!lastDrill) return { key: 'backups', ok: true, detail: `Backed up ${ago(lastBackup)}. Not yet restored by a drill.` };
  return { key: 'backups', ok: true, detail: `Backed up ${ago(lastBackup)}; restored and checked ${ago(lastDrill.at)}.` };
}
