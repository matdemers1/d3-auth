import { Button, Card, EmptyState, FormField, Input, PageHeader, Select, Skeleton } from '@d3cloud/ui';
import { useEffect, useState } from 'react';
import { api } from '../api';

// C-8: the audit trail (REQ-069).
//
// "What happened" is unanswerable at ten thousand rows. "What did this person do to that app
// last Tuesday" is a question somebody actually has, so the filters come first and the list
// second.

interface AuditRow {
  id: string;
  at: string;
  event: string;
  actor: { id: string; displayName: string; email: string } | null;
  targetType: string | null;
  targetId: string | null;
  ip: string | null;
  detail: unknown;
}

const when = (iso: string): string => new Date(iso).toLocaleString();

export function Audit() {
  const [rows, setRows] = useState<AuditRow[] | undefined>();
  const [events, setEvents] = useState<string[]>([]);
  const [nextCursor, setNextCursor] = useState<string | undefined>();
  const [event, setEvent] = useState('');
  const [from, setFrom] = useState('');
  const [failed, setFailed] = useState(false);

  const query = (cursor?: string): string => {
    const params = new URLSearchParams();
    if (event) params.set('event', event);
    if (from) params.set('from', new Date(from).toISOString());
    if (cursor) params.set('cursor', cursor);
    return params.toString();
  };

  const load = (cursor?: string) => {
    api
      .get<{ events: AuditRow[]; nextCursor?: string }>(`/api/admin/audit?${query(cursor)}`)
      .then((answer) => {
        setRows((previous) => (cursor ? [...(previous ?? []), ...answer.events] : answer.events));
        setNextCursor(answer.nextCursor);
      })
      .catch(() => {
        setFailed(true);
      });
  };

  useEffect(() => {
    load();
    api
      .get<{ events: string[] }>('/api/admin/audit/events')
      .then((answer) => {
        setEvents(answer.events);
      })
      .catch(() => {
        setEvents([]);
      });
    // Re-runs when a filter changes, which is the only thing that changes the question.
  }, [event, from]);

  if (failed) {
    return (
      <main className="shell">
        <EmptyState kind="no-access" size="page" headingLevel={2} heading="The audit trail is for admins">
          It records who did what, which is not everybody's business.
        </EmptyState>
      </main>
    );
  }

  return (
    <main className="shell">
      <PageHeader title="Audit" description="Every mutation and every sign-in, oldest kept forever." />

      <Card padding="lg">
        <div className="stack">
          <FormField label="Event" help="Pick one, or a family like grant.">
            <Select
              value={event}
              onValueChange={setEvent}
              options={[
                { value: '', label: 'Everything' },
                // Families first — "every grant event" is usually the question.
                ...[...new Set(events.map((name) => `${name.split('.')[0] ?? ''}.`))].map((family) => ({
                  value: family,
                  label: `${family} (all)`,
                })),
                ...events.map((name) => ({ value: name, label: name })),
              ]}
            />
          </FormField>
          <FormField label="Since">
            <Input
              name="from"
              type="date"
              value={from}
              onChange={(e) => {
                setFrom(e.target.value);
              }}
            />
          </FormField>
          <Button
            variant="secondary"
            onClick={() => {
              window.location.assign(`/api/admin/audit/export?${query()}`);
            }}
          >
            Export what is showing
          </Button>
        </div>
      </Card>

      {!rows ? (
        <Skeleton height="12rem" />
      ) : rows.length === 0 ? (
        <Card padding="lg">
          <EmptyState kind="empty" size="inline" headingLevel={2} heading="Nothing matches">
            Widen the filter, or pick an earlier date.
          </EmptyState>
        </Card>
      ) : (
        <Card padding="lg">
          <ul className="rows">
            {rows.map((row) => (
              <li key={row.id} className="row">
                <div>
                  <strong>{row.event}</strong>
                  <div className="muted">
                    {row.actor ? `${row.actor.displayName} · ` : ''}
                    {row.targetType ? `${row.targetType} ${row.targetId?.slice(0, 8) ?? ''} · ` : ''}
                    {when(row.at)}
                    {row.ip ? ` · ${row.ip.replace(/^::ffff:/, '')}` : ''}
                  </div>
                  {JSON.stringify(row.detail) === '{}' ? null : <code className="copy-link">{JSON.stringify(row.detail)}</code>}
                </div>
              </li>
            ))}
          </ul>
          {nextCursor ? (
            <Button
              variant="secondary"
              onClick={() => {
                load(nextCursor);
              }}
            >
              Show more
            </Button>
          ) : null}
        </Card>
      )}
    </main>
  );
}
