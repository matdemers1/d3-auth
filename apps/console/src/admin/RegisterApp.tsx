import { Alert, Button, Card, FormField, PageHeader, Textarea } from '@d3cloud/ui';
import { useState } from 'react';
import { api, ApiError, type App, type ManifestDiff } from '../api';

// C-6: register an app by pasting its manifest (REQ-046, REQ-067).
//
// Paste, preview, create. The preview is not decoration: it is the only chance to see what a
// manifest will do before it does it, and the same screen is how an app is changed later.

const EXAMPLE = `{
  "client_id": "bindery",
  "name": "Bindery",
  "client_type": "confidential_web",
  "redirect_uris": ["https://bindery.d3cloud.io/api/auth/oidc/callback"],
  "post_logout_redirect_uris": ["https://bindery.d3cloud.io/"],
  "backchannel_logout_uri": "https://bindery.d3cloud.io/api/auth/oidc/backchannel-logout",
  "roles": [
    { "key": "admin", "display": "Administrator" },
    { "key": "member", "display": "Member", "default": true }
  ]
}`;

interface Created {
  app: App;
  secret?: string;
}

export function RegisterApp() {
  const [manifest, setManifest] = useState('');
  const [problems, setProblems] = useState<string[]>([]);
  const [diff, setDiff] = useState<ManifestDiff | undefined>();
  const [created, setCreated] = useState<Created | undefined>();
  const [busy, setBusy] = useState(false);

  const readProblems = (err: unknown): string[] => {
    if (!(err instanceof ApiError)) return ['We could not reach the server.'];
    const listed = err.body.problems;
    if (Array.isArray(listed)) return (listed as { field: string; message: string }[]).map((p) => `${p.field}: ${p.message}`);
    return [err.message];
  };

  async function act(path: string, onDone: (answer: Created & { diff?: ManifestDiff }) => void) {
    setBusy(true);
    setProblems([]);
    try {
      onDone(await api.post<Created & { diff?: ManifestDiff }>(path, { manifest }));
    } catch (err) {
      setProblems(readProblems(err));
    } finally {
      setBusy(false);
    }
  }

  if (created) {
    return (
      <main className="shell">
        <PageHeader title={`${created.app.name} is registered`} description="Give somebody access to it and they can sign in." />
        {created.secret ? (
          <Alert tone="warning" dynamic title="This is the only time the client secret is shown">
            <p>Copy it into the app now. Nothing here can print it again — if it is lost, rotate it.</p>
            <code className="copy-link">{created.secret}</code>
          </Alert>
        ) : (
          <Alert tone="info" title="No client secret">
            A native app holds no secret. It proves itself with PKCE instead.
          </Alert>
        )}
        <Card padding="lg">
          <Button
            variant="primary"
            onClick={() => {
              window.location.assign(`/admin/apps/${encodeURIComponent(created.app.clientId)}`);
            }}
          >
            Open {created.app.name}
          </Button>
        </Card>
      </main>
    );
  }

  return (
    <main className="shell">
      <PageHeader title="Register an app" description="Paste the app's manifest. Roles are declared there and nowhere else." />

      {problems.length > 0 ? (
        <Alert tone="danger" dynamic title="That manifest cannot be used">
          <ul className="rows">
            {problems.map((problem) => (
              <li key={problem}>{problem}</li>
            ))}
          </ul>
        </Alert>
      ) : null}

      {diff ? (
        <Alert tone="info" dynamic title={diff.isNew ? 'This would register a new app' : 'This would change the registered app'}>
          <ul className="rows">
            {diff.roles.added.map((role) => (
              <li key={`add-${role.key}`}>Adds the role {role.key}.</li>
            ))}
            {diff.redirectUris.added.map((uri) => (
              <li key={`uri-${uri}`}>Allows a return to {uri}.</li>
            ))}
            {diff.changed.map((change) => (
              <li key={change.field}>
                Changes {change.field} to {change.to || '(empty)'}.
              </li>
            ))}
          </ul>
        </Alert>
      ) : null}

      <Card padding="lg">
        <form
          className="stack"
          onSubmit={(event) => {
            event.preventDefault();
            void act('/api/admin/apps', setCreated);
          }}
        >
          <FormField label="Manifest" help="JSON. The client id cannot be changed later.">
            <Textarea
              name="manifest"
              rows={16}
              required
              placeholder={EXAMPLE}
              value={manifest}
              onChange={(event) => {
                setManifest(event.target.value);
                setDiff(undefined);
              }}
            />
          </FormField>
          <Button
            type="button"
            variant="secondary"
            disabled={busy || manifest.trim() === ''}
            onClick={() =>
              void act('/api/admin/apps/preview', (answer) => {
                setDiff(answer.diff);
              })
            }
          >
            Check it first
          </Button>
          <Button type="submit" variant="primary" loading={busy} disabled={manifest.trim() === ''}>
            Register
          </Button>
        </form>
      </Card>
    </main>
  );
}
