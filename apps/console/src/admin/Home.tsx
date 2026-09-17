import { Alert, Badge, Card, PageHeader, Skeleton } from '@d3cloud/ui';
import { useEffect, useState } from 'react';
import { api } from '../api';

// C-0: the console's front page (REQ-073).
//
// Five tiles, and each one says what to do rather than just what is wrong: "never tested" is more
// useful than a green tick that means nothing, and "invites are not arriving" is what an operator
// actually needs to hear when a mail test failed last week.

interface Tile {
  key: 'database' | 'keys' | 'mail' | 'migrations' | 'backups';
  ok: boolean;
  detail: string;
}

interface Overview {
  tiles: Tile[];
  counts: { people: number; apps: number; groups: number; signInsToday: number };
  recent: { id: string; at: string; event: string; actor: { displayName: string } | null; targetId: string | null }[];
  checklist: { key: string; done: boolean; label: string; href: string }[] | null;
}

const TILE_LABEL: Record<Tile['key'], string> = {
  database: 'Database',
  keys: 'Signing keys',
  migrations: 'Schema',
  mail: 'Mail',
  backups: 'Backups',
};

const when = (iso: string): string => new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });

export function Home() {
  const [view, setView] = useState<Overview | undefined>();
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    api
      .get<Overview>('/api/admin/overview')
      .then(setView)
      .catch(() => {
        setFailed(true);
      });
  }, []);

  if (failed) {
    return (
      <main className="shell">
        <Alert tone="danger" title="This page could not load">
          The console could not reach the server. If sign-in still works, this is the console, not the provider.
        </Alert>
      </main>
    );
  }
  if (!view) return <Skeleton height="16rem" />;

  return (
    <main className="shell">
      <PageHeader title="Home" description="How this instance is doing, and what has happened lately." />

      {view.checklist ? (
        <Card padding="lg">
          <h2 className="section-title">Getting started</h2>
          <ul className="rows">
            {view.checklist.map((step) => (
              <li key={step.key} className="row">
                <span>
                  {step.done ? '✓ ' : '○ '}
                  {step.done ? step.label : <a href={step.href}>{step.label}</a>}
                </span>
                {step.done ? <span className="muted">Done</span> : <Badge tone="attention">To do</Badge>}
              </li>
            ))}
          </ul>
        </Card>
      ) : null}

      <div className="tiles">
        {view.tiles.map((tile) => (
          <Card key={tile.key} padding="lg">
            <div className="row-meta">
              <h2 className="section-title">{TILE_LABEL[tile.key]}</h2>
              {tile.ok ? <span className="muted">OK</span> : <Badge tone="danger">Attention</Badge>}
            </div>
            <p className="muted">{tile.detail}</p>
          </Card>
        ))}
      </div>

      <Card padding="lg">
        <h2 className="section-title">Counts</h2>
        <ul className="rows">
          <li className="row">
            <a href="/admin/people">People</a>
            <strong>{view.counts.people}</strong>
          </li>
          <li className="row">
            <a href="/admin/apps">Apps</a>
            <strong>{view.counts.apps}</strong>
          </li>
          <li className="row">
            <a href="/admin/groups">Groups</a>
            <strong>{view.counts.groups}</strong>
          </li>
          <li className="row">
            <span>Sign-ins today</span>
            <strong>{view.counts.signInsToday}</strong>
          </li>
        </ul>
      </Card>

      <Card padding="lg">
        <div className="row-meta">
          <h2 className="section-title">Lately</h2>
          <a href="/admin/audit">All of it</a>
        </div>
        {view.recent.length === 0 ? (
          <p className="muted">Nothing has happened yet.</p>
        ) : (
          <ul className="rows">
            {view.recent.map((row) => (
              <li key={row.id} className="row">
                <span>
                  <code>{row.event}</code> {row.actor ? `· ${row.actor.displayName}` : ''}
                </span>
                <span className="muted">{when(row.at)}</span>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </main>
  );
}
