import { Alert, Badge, Button, Card, EmptyState, PageHeader, Skeleton } from '@d3cloud/ui';
import { useEffect, useState } from 'react';
import { api, ApiError, type App, type PersonDetail as Person } from '../api';

// C-2: one person — who they are, what they can reach, and how they prove it is them.
//
// The grants editor is the part that matters: access is deny-by-default, so this screen is
// where somebody stops being locked out of everything.

const when = (iso: string | null): string => (iso ? new Date(iso).toLocaleDateString() : 'never');

export function PersonDetail({ id }: { id: string }) {
  const [person, setPerson] = useState<Person | undefined>();
  const [apps, setApps] = useState<App[]>([]);
  const [message, setMessage] = useState<{ tone: 'danger' | 'success'; text: string } | undefined>();
  const [busy, setBusy] = useState(false);

  const load = () => {
    api
      .get<Person>(`/api/admin/people/${encodeURIComponent(id)}`)
      .then(setPerson)
      .catch(() => {
        setMessage({ tone: 'danger', text: 'We could not load that person.' });
      });
    api
      .get<{ apps: App[] }>('/api/admin/apps')
      .then((answer) => {
        setApps(answer.apps.filter((app) => app.enabled));
      })
      .catch(() => {
        // Only the owner can list apps; an admin still sees the access this person has.
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

  if (!person) {
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

  const granted = new Map(person.access.map((row) => [row.clientId, row.roles]));
  const base = `/api/admin/people/${encodeURIComponent(person.id)}`;
  const factorCount = person.factors.passkeys + person.factors.authenticatorApps;

  return (
    <main className="shell">
      <PageHeader title={person.displayName} description={person.email} />

      {message ? (
        <Alert tone={message.tone} dynamic title={message.tone === 'danger' ? 'That did not work' : 'Done'}>
          {message.text}
        </Alert>
      ) : null}

      <Card padding="lg">
        <ul className="rows">
          <li className="row">
            <span>Username</span>
            <span className="muted">@{person.username}</span>
          </li>
          <li className="row">
            <span>Kind</span>
            <div className="row-meta">
              <Badge tone={person.kind === 'guest' ? 'neutral' : 'attention'}>{person.kind}</Badge>
              {person.status === 'active' ? null : <Badge tone="danger">{person.status}</Badge>}
            </div>
          </li>
          <li className="row">
            <span>Last signed in</span>
            <span className="muted">{when(person.lastLoginAt)}</span>
          </li>
          <li className="row">
            <span>How they prove it is them</span>
            <span className="muted">
              {factorCount === 0
                ? 'Password only'
                : `${String(person.factors.passkeys)} passkey(s), ${String(person.factors.authenticatorApps)} authenticator app(s)`}
              {person.factors.trustedDevices > 0 ? ` · ${String(person.factors.trustedDevices)} trusted browser(s)` : ''}
            </span>
          </li>
          <li className="row">
            <span>Signed in now</span>
            <span className="muted">
              {person.sessions.length} {person.sessions.length === 1 ? 'session' : 'sessions'}
            </span>
          </li>
        </ul>
      </Card>

      <Card padding="lg">
        <h2 className="section-title">Apps they can sign in to</h2>
        {apps.length === 0 && person.access.length === 0 ? (
          <EmptyState kind="empty" size="inline" headingLevel={3} heading="No access yet">
            Nobody can sign in to an app until they are given access to it.
          </EmptyState>
        ) : (
          <ul className="rows">
            {(apps.length > 0 ? apps : person.access.map((row) => ({ clientId: row.clientId, name: row.name, roles: [] }))).map((app) => {
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
                                  on ? `${role.displayName} removed.` : `${role.displayName} given.`,
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
                        onClick={() => void act(`${base}/access/revoke`, { clientId: app.clientId }, `Access to ${app.name} revoked.`)}
                      >
                        Revoke
                      </Button>
                    ) : (
                      <Button
                        size="sm"
                        variant="secondary"
                        disabled={busy}
                        onClick={() => void act(`${base}/access`, { clientId: app.clientId, roles: [] }, `Access to ${app.name} given.`)}
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
    </main>
  );
}
