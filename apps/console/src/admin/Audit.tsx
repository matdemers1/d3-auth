import { Button, Card, Cluster, DataList, DataListRow, EmptyState, FilterBar, FormField, Input, Page, PageHeader, Select } from '@d3cloud/ui';
import { Download } from 'lucide-react';
import { useEffect, useState } from 'react';
import { api } from '../api';
import { icon } from '../shared/icons';
import { failureOf, type Loaded } from '../shared/load';
import { useMe } from '../shared/me';
import { Denied, LoadFailed, RowsSkeleton } from '../shared/states';

// C-8: the audit trail (REQ-069).
//
// "What happened" is unanswerable at ten thousand rows. "What did this person do to that app last
// Tuesday" is a question somebody actually has, so the filters come first and the list second.

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

/** A Select option cannot be empty, so "everything" has a name of its own. */
const EVERYTHING = 'all';

const when = (iso: string): string => new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'medium' });

const DESCRIPTION = 'Every change and every sign-in, kept for good.';

export function Audit() {
  const me = useMe();
  const [state, setState] = useState<Loaded<{ rows: AuditRow[]; nextCursor?: string | undefined }>>({ status: 'loading' });
  const [events, setEvents] = useState<string[]>([]);
  const [event, setEvent] = useState(EVERYTHING);
  const [from, setFrom] = useState('');
  const [attempt, setAttempt] = useState(0);
  const [more, setMore] = useState(false);

  const query = (cursor?: string): string => {
    const params = new URLSearchParams();
    if (event !== EVERYTHING) params.set('event', event);
    if (from) params.set('from', new Date(from).toISOString());
    if (cursor) params.set('cursor', cursor);
    return params.toString();
  };

  const load = (cursor?: string) => {
    api
      .get<{ events: AuditRow[]; nextCursor?: string }>(`/api/admin/audit?${query(cursor)}`)
      .then((answer) => {
        setState((previous) => ({
          status: 'ready',
          data: {
            rows: cursor && previous.status === 'ready' ? [...previous.data.rows, ...answer.events] : answer.events,
            nextCursor: answer.nextCursor,
          },
        }));
      })
      .catch((err: unknown) => {
        setState(failureOf(err));
      })
      .finally(() => {
        setMore(false);
      });
  };

  useEffect(() => {
    load();
    // Re-runs when a filter changes, which is the only thing that changes the question.
  }, [event, from, attempt]);

  useEffect(() => {
    api
      .get<{ events: string[] }>('/api/admin/audit/events')
      .then((answer) => {
        setEvents(answer.events);
      })
      .catch(() => {
        // The trail itself decides what this page shows; without the list the filter offers "Everything".
        setEvents([]);
      });
  }, []);

  if (state.status === 'denied') {
    return (
      <Page>
        <PageHeader title="Audit" description={DESCRIPTION} />
        <Denied heading="The audit trail is for admins">
          It records who did what, which is not everybody’s business. {me?.operatorDisplayName ?? 'The owner'} can make you an admin if you need it.
        </Denied>
      </Page>
    );
  }
  if (state.status === 'failed') {
    return (
      <Page>
        <PageHeader title="Audit" description={DESCRIPTION} />
        <LoadFailed
          what="The audit trail"
          message={state.message}
          onRetry={() => {
            setState({ status: 'loading' });
            setAttempt((n) => n + 1);
          }}
        />
      </Page>
    );
  }

  const rows = state.status === 'ready' ? state.data.rows : undefined;
  const filtered = event !== EVERYTHING || from !== '';

  return (
    <Page {...(rows ? {} : { 'aria-busy': true })}>
      <PageHeader title="Audit" description={DESCRIPTION} />

      <FilterBar
        aria-label="Filter the audit trail"
        trailing={
          <Button
            icon={icon(Download)}
            onClick={() => {
              window.location.assign(`/api/admin/audit/export?${query()}`);
            }}
          >
            Export what is showing
          </Button>
        }
      >
        <FormField label="Event" help="One event, or a whole family.">
          <Select
            value={event}
            onValueChange={setEvent}
            options={[
              { value: EVERYTHING, label: 'Everything' },
              // Families first — "every grant event" is usually the question.
              ...[...new Set(events.map((name) => `${name.split('.')[0] ?? ''}.`))].map((family) => ({
                value: family,
                label: `${family} (all)`,
              })),
              ...events.map((name) => ({ value: name, label: name })),
            ]}
          />
        </FormField>
        <FormField label="Since" help="Leave empty for all of it.">
          <Input
            name="from"
            type="date"
            value={from}
            onChange={(e) => {
              setFrom(e.target.value);
            }}
          />
        </FormField>
      </FilterBar>

      {!rows ? (
        <RowsSkeleton rows={6} />
      ) : (
        <Card>
          <DataList
            aria-label="Audit trail"
            empty={
              filtered ? (
                <EmptyState
                  kind="no-results"
                  size="inline"
                  heading="Nothing matches these filters"
                  action={
                    <Button
                      size="sm"
                      onClick={() => {
                        setEvent(EVERYTHING);
                        setFrom('');
                      }}
                    >
                      Clear filters
                    </Button>
                  }
                >
                  Pick a whole family of events, or an earlier date.
                </EmptyState>
              ) : (
                <EmptyState kind="empty" size="inline" heading="Nothing has happened yet">
                  Every sign-in and every change will be recorded here.
                </EmptyState>
              )
            }
          >
            {rows.map((row) => (
              <DataListRow
                key={row.id}
                truncate={false}
                title={<code>{row.event}</code>}
                description={
                  <>
                    {[
                      row.actor ? row.actor.displayName : 'The system',
                      row.targetType ? `${row.targetType} ${row.targetId?.slice(0, 8) ?? ''}` : null,
                      row.ip ? row.ip.replace(/^::ffff:/, '') : null,
                    ]
                      .filter(Boolean)
                      .join(' · ')}
                    {JSON.stringify(row.detail) === '{}' || row.detail === null ? null : (
                      <>
                        {' · '}
                        <code>{JSON.stringify(row.detail)}</code>
                      </>
                    )}
                  </>
                }
                meta={<span>{when(row.at)}</span>}
              />
            ))}
          </DataList>
        </Card>
      )}

      {state.status === 'ready' && state.data.nextCursor ? (
        <Cluster>
          <Button
            loading={more}
            onClick={() => {
              setMore(true);
              load(state.data.nextCursor);
            }}
          >
            Show older events
          </Button>
        </Cluster>
      ) : null}
    </Page>
  );
}
