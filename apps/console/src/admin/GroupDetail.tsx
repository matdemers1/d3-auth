import { Alert, Avatar, Badge, Button, DataList, DataListRow, EmptyState, Link, Page, PageHeader, Section } from '@d3cloud/ui';
import { ArrowLeft } from 'lucide-react';
import { useState } from 'react';
import { api, type App, type Person } from '../api';
import { Confirm } from '../shared/Confirm';
import { icon } from '../shared/icons';
import { messageOf, useLoad } from '../shared/load';
import { useMe } from '../shared/me';
import { Denied, LoadFailed, RowsSkeleton } from '../shared/states';
import { AccessList } from './access';

// One group: who is in it, and what that gets them (Detail page pattern).

interface GroupDetailView {
  id: string;
  name: string;
  description: string;
  members: { userId: string; displayName: string; email: string }[];
  grants: { clientId: string; name: string; roles: string[] }[];
}

type Region = 'members' | 'access';

function Back() {
  return (
    <Link variant="muted" href="/admin/groups">
      {icon(ArrowLeft, 14)}
      Groups
    </Link>
  );
}

export function GroupDetail({ id }: { id: string }) {
  const me = useMe();
  const group = useLoad(() => api.get<GroupDetailView>(`/api/admin/groups/${encodeURIComponent(id)}`), id);
  const people = useLoad(() => api.get<{ people: Person[] }>('/api/admin/people').then((answer) => answer.people.filter((person) => person.status === 'active')), id);
  // Apps are owner-only; an admin still sees the access this group already has.
  const apps = useLoad(() => api.get<{ apps: App[] }>('/api/admin/apps').then((answer) => answer.apps.filter((app) => app.enabled)), id);
  const [feedback, setFeedback] = useState<{ where: Region; tone: 'success' | 'danger'; text: string } | undefined>();
  const [busy, setBusy] = useState(false);

  function act(where: Region, path: string, body: unknown, said: string) {
    setBusy(true);
    setFeedback(undefined);
    api
      .post(path, body)
      .then(() => {
        setFeedback({ where, tone: 'success', text: said });
        group.reload();
      })
      .catch((err: unknown) => {
        setFeedback({ where, tone: 'danger', text: messageOf(err) });
      })
      .finally(() => {
        setBusy(false);
      });
  }

  const alertFor = (where: Region) =>
    feedback?.where === where ? (
      <Alert tone={feedback.tone} dynamic title={feedback.tone === 'danger' ? 'That did not work' : 'Done'}>
        {feedback.text}
      </Alert>
    ) : null;

  const state = group.state;
  if (state.status !== 'ready') {
    return (
      <Page width="narrow" {...(state.status === 'loading' ? { 'aria-busy': true } : {})}>
        <PageHeader back={<Back />} title="Group" />
        {state.status === 'loading' ? (
          <>
            <RowsSkeleton rows={3} leading />
            <RowsSkeleton rows={2} />
          </>
        ) : state.status === 'denied' ? (
          <Denied heading="Groups are for admins">
            Your account can sign in to apps, but not organise who else can. {me?.operatorDisplayName ?? 'The owner'} can make you an admin.
          </Denied>
        ) : (
          <LoadFailed what="This group" message={state.message} onRetry={group.retry} />
        )}
      </Page>
    );
  }

  const view = state.data;
  const base = `/api/admin/groups/${encodeURIComponent(view.id)}`;
  const memberIds = view.members.map((member) => member.userId);
  // Members first, then everyone else who could be added.
  const everyone = people.state.status === 'ready' ? people.state.data : [];
  const ordered = [...everyone.filter((person) => memberIds.includes(person.id)), ...everyone.filter((person) => !memberIds.includes(person.id))];

  return (
    <Page width="narrow">
      <PageHeader back={<Back />} title={view.name} description={view.description || 'A group of people who need the same access.'} />

      <Section title="Who is in it" description={`${view.members.length} ${view.members.length === 1 ? 'person' : 'people'}. Only active accounts can be added.`}>
        {alertFor('members')}
        <DataList
          aria-label="Who is in it"
          empty={
            <EmptyState kind="empty" size="inline" headingLevel={3} heading="Nobody to add yet">
              Invite somebody first, from People.
            </EmptyState>
          }
        >
          {ordered.map((person) => {
            const inGroup = memberIds.includes(person.id);
            return (
              <DataListRow
                key={person.id}
                leading={<Avatar name={person.displayName} size="sm" decorative />}
                title={person.displayName}
                description={person.email}
                {...(inGroup ? { meta: <Badge size="sm">Member</Badge> } : {})}
                actions={
                  <Button
                    size="sm"
                    variant={inGroup ? 'ghost' : 'secondary'}
                    disabled={busy}
                    onClick={() => {
                      act(
                        'members',
                        `${base}/members`,
                        { userIds: inGroup ? memberIds.filter((member) => member !== person.id) : [...memberIds, person.id] },
                        inGroup ? `${person.displayName} is no longer in ${view.name}.` : `${person.displayName} is in ${view.name}.`,
                      );
                    }}
                  >
                    {inGroup ? 'Remove' : 'Add'}
                  </Button>
                }
              />
            );
          })}
        </DataList>
      </Section>

      <Section title="What that gets them" description="These roles add to whatever somebody has been given directly — never instead of it.">
        {alertFor('access')}
        <AccessList
          label="What that gets them"
          apps={apps.state.status === 'ready' ? apps.state.data : []}
          grants={view.grants}
          busy={busy}
          onGrant={(app, roles, said) => {
            act('access', `${base}/access`, { clientId: app.clientId, roles }, said);
          }}
          onRevoke={(app) => {
            act('access', `${base}/access/revoke`, { clientId: app.clientId }, `${view.name} no longer reaches ${app.name}.`);
          }}
          say={{
            role: (role, on) => (on ? `${role} removed from ${view.name}.` : `${role} given to ${view.name}.`),
            given: (app) => `${view.name} can reach ${app}.`,
          }}
          emptyHeading="No access yet"
          emptyText="A group with no access changes nothing."
        />
      </Section>

      <Section title="Delete">
        <DataList aria-label="Delete">
          <DataListRow
            truncate={false}
            title="Delete this group"
            description="Everyone in it loses the access it gave them, and keeps anything they were given directly."
            actions={
              <Confirm
                trigger={
                  <Button size="sm" variant="danger-ghost" disabled={busy}>
                    Delete {view.name}
                  </Button>
                }
                title={`Delete ${view.name}?`}
                description={`${
                  view.members.length === 0
                    ? 'Nobody is in it, so nobody loses access.'
                    : view.members.length === 1
                      ? 'The one person in it loses the access it gave them.'
                      : `The ${view.members.length} people in it lose the access it gave them.`
                } Access given to anyone directly stays. This cannot be undone.`}
                confirm={`Delete ${view.name}`}
                cancel={`Keep ${view.name}`}
                onConfirm={async () => {
                  await api.post(`${base}/remove`, {});
                  // Nothing is left to look at here, so back to the list, where the group is gone.
                  window.location.assign('/admin/groups');
                  await new Promise<void>(() => undefined);
                }}
              />
            }
          />
        </DataList>
      </Section>
    </Page>
  );
}
