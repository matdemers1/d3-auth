import { Alert, Badge, Button, Card, EmptyState, Link, PageHeader, Skeleton } from '@d3cloud/ui';
import { useEffect, useState } from 'react';
import { api, ApiError, type App } from '../api';

// C-4: the apps people can sign in to. Owner-only, because registering an app decides who can
// ask for tokens at all — a different kind of power from managing the people who already have
// accounts.

export function Apps() {
  const [apps, setApps] = useState<App[] | undefined>();
  const [failed, setFailed] = useState<'not-allowed' | 'failed' | undefined>();

  useEffect(() => {
    api
      .get<{ apps: App[] }>('/api/admin/apps')
      .then((answer) => {
        setApps(answer.apps);
      })
      .catch((err: unknown) => {
        setFailed(err instanceof ApiError && err.status === 403 ? 'not-allowed' : 'failed');
      });
  }, []);

  if (failed === 'not-allowed') {
    return (
      <main className="shell">
        <EmptyState kind="no-access" size="page" headingLevel={2} heading="Apps are the owner's to manage">
          You can invite people and give them access to apps, but only the owner registers them.
        </EmptyState>
      </main>
    );
  }

  return (
    <main className="shell">
      <PageHeader title="Apps" description="Everything that can ask this system who somebody is." />

      {failed ? (
        <Alert tone="danger" title="We could not load the apps">
          Try again in a moment.
        </Alert>
      ) : null}

      <Card padding="lg">
        <p className="muted">An app is registered from its manifest: what it is called, where it may be sent back to, and the roles it understands.</p>
        <Button
          variant="primary"
          onClick={() => {
            window.location.assign('/admin/apps/new');
          }}
        >
          Register an app
        </Button>
      </Card>

      {!apps ? (
        <Skeleton height="8rem" />
      ) : apps.length === 0 ? (
        <Card padding="lg">
          <EmptyState kind="empty" size="inline" headingLevel={2} heading="No apps yet">
            Register one, then give people access to it.
          </EmptyState>
        </Card>
      ) : (
        <Card padding="lg">
          <h2 className="section-title">
            {apps.length} {apps.length === 1 ? 'app' : 'apps'}
          </h2>
          <ul className="rows">
            {apps.map((app) => (
              <li key={app.id} className="row">
                <div>
                  <strong>
                    <Link href={`/admin/apps/${encodeURIComponent(app.clientId)}`}>{app.name}</Link>
                  </strong>{' '}
                  <span className="muted">{app.clientId}</span>
                  <div className="muted">
                    {app.people} {app.people === 1 ? 'person' : 'people'} · {app.roles.length}{' '}
                    {app.roles.length === 1 ? 'role' : 'roles'}
                  </div>
                </div>
                <div className="row-meta">
                  {app.enabled ? null : <Badge tone="danger">disabled</Badge>}
                  {app.backchannelLogoutUri ? null : <Badge tone="attention">slow revoke</Badge>}
                  <span className="muted">{app.clientType === 'public_native' ? 'native' : 'web'}</span>
                </div>
              </li>
            ))}
          </ul>
        </Card>
      )}
    </main>
  );
}
