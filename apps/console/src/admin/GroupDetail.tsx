import { Alert, Button, Card, EmptyState, PageHeader, Skeleton } from '@d3cloud/ui';
import { useEffect, useState } from 'react';
import { api, ApiError, type App, type Person } from '../api';

// One group: who is in it, and what that gets them.

interface GroupDetailView {
  id: string;
  name: string;
  description: string;
  members: { userId: string; displayName: string; email: string }[];
  grants: { clientId: string; name: string; roles: string[] }[];
}

export function GroupDetail({ id }: { id: string }) {
  const [group, setGroup] = useState<GroupDetailView | undefined>();
  const [people, setPeople] = useState<Person[]>([]);
  const [apps, setApps] = useState<App[]>([]);
  const [message, setMessage] = useState<{ tone: 'danger' | 'success'; text: string } | undefined>();
  const [busy, setBusy] = useState(false);

  const load = () => {
    api
      .get<GroupDetailView>(`/api/admin/groups/${encodeURIComponent(id)}`)
      .then(setGroup)
      .catch(() => {
        setMessage({ tone: 'danger', text: 'We could not load that group.' });
      });
    api
      .get<{ people: Person[] }>('/api/admin/people')
      .then((answer) => {
        setPeople(answer.people.filter((person) => person.status === 'active'));
      })
      .catch(() => {
        setPeople([]);
      });
    api
      .get<{ apps: App[] }>('/api/admin/apps')
      .then((answer) => {
        setApps(answer.apps.filter((app) => app.enabled));
      })
      .catch(() => {
        // Apps are owner-only; an admin still sees the access this group already has.
        setApps([]);
      });
  };

  useEffect(load, [id]);

  async function act(path: string, body: unknown, said: string) {
    setBusy(true);
    setMessage(undefined);
    try {
      await api.post(path, body);
      setMessage({ tone: 'success', text: said });
      load();
    } catch (err) {
      setMessage({ tone: 'danger', text: err instanceof ApiError ? err.message : 'That did not work.' });
    } finally {
      setBusy(false);
    }
  }

  if (!group) {
    return (
      <main className="shell">
        {message ? (
          <Alert tone="danger" title="That did not work">
            {message.text}
          </Alert>
        ) : (
          <Skeleton height="12rem" />
        )}
      </main>
    );
  }

  const base = `/api/admin/groups/${encodeURIComponent(group.id)}`;
  const memberIds = group.members.map((member) => member.userId);
  const granted = new Map(group.grants.map((grant) => [grant.clientId, grant.roles]));

  return (
    <main className="shell">
      <PageHeader title={group.name} description={group.description || 'A group of people who need the same access.'} />

      {message ? (
        <Alert tone={message.tone} dynamic title={message.tone === 'danger' ? 'That did not work' : 'Done'}>
          {message.text}
        </Alert>
      ) : null}

      <Card padding="lg">
        <h2 className="section-title">Who is in it</h2>
        {people.length === 0 ? (
          <EmptyState kind="empty" size="inline" headingLevel={3} heading="Nobody to add yet">
            Invite somebody first.
          </EmptyState>
        ) : (
          <ul className="rows">
            {people.map((person) => {
              const inGroup = memberIds.includes(person.id);
              return (
                <li key={person.id} className="row">
                  <div>
                    <strong>{person.displayName}</strong> <span className="muted">{person.email}</span>
                  </div>
                  <Button
                    size="sm"
                    variant={inGroup ? 'danger-ghost' : 'secondary'}
                    disabled={busy}
                    onClick={() =>
                      void act(
                        `${base}/members`,
                        { userIds: inGroup ? memberIds.filter((member) => member !== person.id) : [...memberIds, person.id] },
                        inGroup ? `${person.displayName} is no longer in ${group.name}.` : `${person.displayName} is in ${group.name}.`,
                      )
                    }
                  >
                    {inGroup ? 'Remove' : 'Add'}
                  </Button>
                </li>
              );
            })}
          </ul>
        )}
      </Card>

      <Card padding="lg">
        <h2 className="section-title">What that gets them</h2>
        <p className="muted">These roles add to whatever somebody has been given directly — never instead of it.</p>
        {apps.length === 0 && group.grants.length === 0 ? (
          <EmptyState kind="empty" size="inline" headingLevel={3} heading="No access yet">
            A group with no access changes nothing.
          </EmptyState>
        ) : (
          <ul className="rows">
            {(apps.length > 0 ? apps : group.grants.map((grant) => ({ clientId: grant.clientId, name: grant.name, roles: [] }))).map((app) => {
              const roles = granted.get(app.clientId);
              const hasAccess = roles !== undefined;
              return (
                <li key={app.clientId} className="row">
                  <div>
                    <strong>{app.name}</strong>
                    <div className="muted">{hasAccess ? (roles.length > 0 ? roles.join(', ') : 'access, no roles') : 'no access'}</div>
                  </div>
                  <div className="row-meta">
                    {'roles' in app && Array.isArray(app.roles)
                      ? app.roles.map((role) => {
                          const on = roles?.includes(role.key) ?? false;
                          return (
                            <Button
                              key={role.key}
                              size="sm"
                              variant={on ? 'primary' : 'secondary'}
                              disabled={busy}
                              onClick={() =>
                                void act(
                                  `${base}/access`,
                                  {
                                    clientId: app.clientId,
                                    roles: on ? (roles ?? []).filter((key) => key !== role.key) : [...(roles ?? []), role.key],
                                  },
                                  on ? `${role.displayName} removed from ${group.name}.` : `${role.displayName} given to ${group.name}.`,
                                )
                              }
                            >
                              {role.displayName}
                            </Button>
                          );
                        })
                      : null}
                    {hasAccess ? (
                      <Button
                        size="sm"
                        variant="danger-ghost"
                        disabled={busy}
                        onClick={() => void act(`${base}/access/revoke`, { clientId: app.clientId }, `${group.name} no longer reaches ${app.name}.`)}
                      >
                        Revoke
                      </Button>
                    ) : (
                      <Button
                        size="sm"
                        variant="secondary"
                        disabled={busy}
                        onClick={() => void act(`${base}/access`, { clientId: app.clientId, roles: [] }, `${group.name} can reach ${app.name}.`)}
                      >
                        Give access
                      </Button>
                    )}
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </Card>

      <Card padding="lg">
        <h2 className="section-title">Danger</h2>
        <Button
          variant="danger-ghost"
          disabled={busy}
          onClick={() => void act(`${base}/remove`, {}, `${group.name} is gone, and the access it carried with it.`)}
        >
          Delete this group
        </Button>
      </Card>
    </main>
  );
}
