import { Alert, Badge, Button, Card, EmptyState, FormField, PageHeader, Skeleton, Textarea } from '@d3cloud/ui';
import { useEffect, useState } from 'react';
import { api, ApiError, type AccessRow, type App, type ManifestDiff } from '../api';

// C-5: one app — what it is, who can reach it, and the two buttons that stop it.

const when = (iso: string | null): string => (iso ? new Date(iso).toLocaleDateString() : 'never');

/** The manifest this app would produce, so re-pasting starts from what is actually registered. */
const manifestOf = (app: App): string =>
  JSON.stringify(
    {
      client_id: app.clientId,
      name: app.name,
      ...(app.description ? { description: app.description } : {}),
      client_type: app.clientType,
      redirect_uris: app.redirectUris,
      post_logout_redirect_uris: app.postLogoutRedirectUris,
      ...(app.backchannelLogoutUri ? { backchannel_logout_uri: app.backchannelLogoutUri } : {}),
      roles: app.roles.map((role) => ({
        key: role.key,
        display: role.displayName,
        ...(role.description ? { description: role.description } : {}),
        ...(role.isDefault ? { default: true } : {}),
      })),
    },
    null,
    2,
  );

export function AppDetail({ clientId }: { clientId: string }) {
  const [app, setApp] = useState<App | undefined>();
  const [access, setAccess] = useState<AccessRow[]>([]);
  const [message, setMessage] = useState<{ tone: 'danger' | 'success' | 'warning'; title: string; text: string } | undefined>();
  const [secret, setSecret] = useState<string | undefined>();
  const [manifest, setManifest] = useState('');
  const [blocking, setBlocking] = useState<ManifestDiff['blocking']>([]);
  const [busy, setBusy] = useState(false);

  const load = () => {
    api
      .get<App>(`/api/admin/apps/${encodeURIComponent(clientId)}`)
      .then((loaded) => {
        setApp(loaded);
        setManifest(manifestOf(loaded));
      })
      .catch(() => {
        setMessage({ tone: 'danger', title: 'We could not load that app', text: 'It may have been removed.' });
      });
    api
      .get<{ access: AccessRow[] }>(`/api/admin/apps/${encodeURIComponent(clientId)}/access`)
      .then((answer) => {
        setAccess(answer.access);
      })
      .catch(() => {
        setAccess([]);
      });
  };

  useEffect(load, [clientId]);

  async function act(path: string, body: unknown, said: { title: string; text: string }) {
    setBusy(true);
    setMessage(undefined);
    setBlocking([]);
    try {
      await api.post(path, body);
      setMessage({ tone: 'success', ...said });
      load();
    } catch (err) {
      if (err instanceof ApiError && err.body.error === 'roles_in_use') {
        setBlocking((err.body.detail as ManifestDiff['blocking'] | undefined) ?? []);
        setMessage({ tone: 'warning', title: 'That would take away access somebody has', text: err.message });
        return;
      }
      setMessage({ tone: 'danger', title: 'That did not work', text: err instanceof ApiError ? err.message : 'Try again.' });
    } finally {
      setBusy(false);
    }
  }

  if (!app) return <Skeleton height="12rem" />;

  const base = `/api/admin/apps/${encodeURIComponent(clientId)}`;

  return (
    <main className="shell">
      <PageHeader title={app.name} description={app.clientId} />

      {message ? (
        <Alert tone={message.tone} dynamic title={message.title}>
          {message.text}
          {blocking.length > 0 ? (
            <ul className="rows">
              {blocking.map((role) => (
                <li key={role.key}>
                  {role.key} — {role.granted ?? 0} {role.granted === 1 ? 'person has it' : 'people have it'}
                </li>
              ))}
            </ul>
          ) : null}
        </Alert>
      ) : null}

      {secret ? (
        <Alert tone="warning" dynamic title="This is the only time the new secret is shown">
          <p>Copy it into the app now. The old one stopped working the moment this appeared.</p>
          <code className="copy-link">{secret}</code>
        </Alert>
      ) : null}

      <Card padding="lg">
        <h2 className="section-title">How it signs people in</h2>
        <ul className="rows">
          <li className="row">
            <span>Type</span>
            <span className="muted">{app.clientType === 'public_native' ? 'Native app, no secret (PKCE)' : 'Web app with a client secret'}</span>
          </li>
          <li className="row">
            <span>Returns to</span>
            <span className="muted">{app.redirectUris.join(', ')}</span>
          </li>
          <li className="row">
            <span>Sign-out</span>
            <span className="muted">
              {app.backchannelLogoutUri ?? 'No endpoint — revoking access here takes effect when its tokens expire'}
            </span>
          </li>
        </ul>
      </Card>

      <Card padding="lg">
        <h2 className="section-title">Roles</h2>
        {app.roles.length === 0 ? (
          <p className="muted">This app declares no roles. People either have access or they do not.</p>
        ) : (
          <ul className="rows">
            {app.roles.map((role) => (
              <li key={role.key} className="row">
                <div>
                  <strong>{role.displayName}</strong> <span className="muted">{role.key}</span>
                  {role.description ? <div className="muted">{role.description}</div> : null}
                </div>
                <div className="row-meta">
                  {role.isDefault ? <Badge tone="neutral">suggested</Badge> : null}
                  <span className="muted">
                    {role.granted} {role.granted === 1 ? 'person' : 'people'}
                  </span>
                </div>
              </li>
            ))}
          </ul>
        )}
      </Card>

      <Card padding="lg">
        <h2 className="section-title">Who can sign in</h2>
        {access.length === 0 ? (
          <EmptyState kind="empty" size="inline" headingLevel={3} heading="Nobody yet">
            Give somebody access from their page in People.
          </EmptyState>
        ) : (
          <ul className="rows">
            {access.map((row) => (
              <li key={row.userId} className="row">
                <div>
                  <strong>{row.displayName}</strong> <span className="muted">{row.email}</span>
                  <div className="muted">
                    {row.roles.length > 0 ? row.roles.join(', ') : 'no roles'} · last signed in {when(row.lastSignIn)}
                  </div>
                </div>
                <Button
                  variant="danger-ghost"
                  size="sm"
                  disabled={busy}
                  onClick={() =>
                    void act(`/api/admin/people/${row.userId}/access/revoke`, { clientId }, {
                      title: 'Access revoked',
                      text: `${row.displayName} has been signed out of ${app.name}.`,
                    })
                  }
                >
                  Revoke
                </Button>
              </li>
            ))}
          </ul>
        )}
      </Card>

      <Card padding="lg">
        <h2 className="section-title">Manifest</h2>
        <p className="muted">Paste a new one to change the app. Removing a role somebody holds needs confirming.</p>
        <form
          className="stack"
          onSubmit={(event) => {
            event.preventDefault();
            void act(`${base}/manifest`, { manifest }, { title: 'Manifest applied', text: 'The change is live now.' });
          }}
        >
          <FormField label="This app's manifest">
            <Textarea
              name="manifest"
              rows={14}
              value={manifest}
              onChange={(event) => {
                setManifest(event.target.value);
              }}
            />
          </FormField>
          <Button type="submit" variant="primary" loading={busy}>
            Apply
          </Button>
          {blocking.length > 0 ? (
            <Button
              type="button"
              variant="danger"
              disabled={busy}
              onClick={() =>
                void act(
                  `${base}/manifest`,
                  { manifest, confirmRoleRemoval: true },
                  { title: 'Manifest applied', text: 'The roles were removed, and the access they carried with them.' },
                )
              }
            >
              Yes, remove those roles and their access
            </Button>
          ) : null}
        </form>
      </Card>

      <Card padding="lg">
        <h2 className="section-title">Danger</h2>
        <div className="stack">
          {app.clientType === 'confidential_web' ? (
            <Button
              variant="secondary"
              disabled={busy}
              onClick={() => {
                setBusy(true);
                api
                  .post<{ secret: string }>(`${base}/secret`)
                  .then((answer) => {
                    setSecret(answer.secret);
                  })
                  .catch(() => {
                    setMessage({ tone: 'danger', title: 'That did not work', text: 'Try again.' });
                  })
                  .finally(() => {
                    setBusy(false);
                  });
              }}
            >
              Rotate the client secret
            </Button>
          ) : null}
          <Button
            variant={app.enabled ? 'danger-ghost' : 'secondary'}
            disabled={busy}
            onClick={() =>
              void act(`${base}/enabled`, { enabled: !app.enabled }, {
                title: app.enabled ? 'App disabled' : 'App enabled',
                text: app.enabled ? 'Its tokens were revoked and nobody can sign in to it.' : 'People with access can sign in again.',
              })
            }
          >
            {app.enabled ? 'Disable this app' : 'Enable this app'}
          </Button>
        </div>
      </Card>
    </main>
  );
}
