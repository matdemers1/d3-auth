import { Checkbox, Alert, Button, FormActions, FormField, Link, Page, PageHeader, Section, Stack, Textarea } from '@d3cloud/ui';
import { ArrowLeft } from 'lucide-react';
import { useState } from 'react';
import { api, ApiError, type ManifestDiff, type Registration } from '../api';
import { icon } from '../shared/icons';
import { useStepUp } from '../shared/StepUp';
import { Registered } from './Registered';

// C-6: register your own app by pasting its manifest (REQ-046, REQ-067), as a form page of its own.
// Apps D3 Auth already knows are added from the picker instead (AddApp, PresetForm).
//
// Paste, check, register. The check is not decoration: it is the only chance to see what a manifest
// will do before it does it, and the same code path is how an app is changed later.

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

function Back() {
  return (
    <Link variant="muted" href="/admin/apps/new">
      {icon(ArrowLeft, 14)}
      Add an app
    </Link>
  );
}

export function RegisterApp() {
  const [manifest, setManifest] = useState('');
  const [problems, setProblems] = useState<string[]>([]);
  const [diff, setDiff] = useState<ManifestDiff | undefined>();
  const [created, setCreated] = useState<Registration | undefined>();
  const [busy, setBusy] = useState(false);
  // The owner is given the app's highest role by default (ADR-007); untick to register without it.
  const [grantMe, setGrantMe] = useState(true);
  const { ask, prompt } = useStepUp();

  const readProblems = (err: unknown): string[] => {
    if (!(err instanceof ApiError)) return ['The console could not reach the server. Nothing was registered.'];
    const listed = err.body.problems;
    if (Array.isArray(listed)) return (listed as { field: string; message: string }[]).map((p) => `${p.field}: ${p.message}`);
    return [err.message];
  };

  async function act(path: string, onDone: (answer: Registration) => void) {
    setBusy(true);
    setProblems([]);
    try {
      onDone(await api.post<Registration>(path, { manifest, ...(grantMe ? {} : { grantMe: false }) }));
    } catch (err) {
      // Registering needs fresh proof; hold the click until they have given it.
      if (ask(err, 'registering an app', () => void act(path, onDone))) return;
      setProblems(readProblems(err));
    } finally {
      setBusy(false);
    }
  }

  if (created) return <Registered registration={created} />;

  return (
    <Page width="narrow">
      <PageHeader back={<Back />} title="Register an app" description="Paste the app’s manifest. Roles are declared there and nowhere else." />

      <Stack
        as="form"
        gap="24"
        aria-label="Register an app"
        onSubmit={(event) => {
          event.preventDefault();
          void act('/api/admin/apps', setCreated);
        }}
      >
        {problems.length > 0 ? (
          <Alert tone="danger" dynamic title="That manifest cannot be used. Nothing was registered.">
            <ul>
              {problems.map((problem) => (
                <li key={problem}>{problem}</li>
              ))}
            </ul>
          </Alert>
        ) : null}

        {diff ? (
          <Alert tone="info" dynamic title={diff.isNew ? 'This would register a new app' : 'This would change an app that is already registered'}>
            <ul>
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

        <Section title="Manifest">
          <FormField label="Manifest" help="JSON, like the example in the box. The client ID cannot be changed later.">
            <Textarea
              name="manifest"
              rows={16}
              required
              spellCheck={false}
              placeholder={EXAMPLE}
              value={manifest}
              onChange={(event) => {
                setManifest(event.target.value);
                setDiff(undefined);
              }}
            />
          </FormField>
        </Section>

        <Section title="Your own access" description="Nobody can sign in to a new app until they are given it — you included.">
          <Checkbox
            label="Give me access, with the first role the manifest lists"
            checked={grantMe}
            onCheckedChange={(checked) => {
              setGrantMe(checked === true);
            }}
          />
        </Section>

        <FormActions
          leading={
            <Button
              variant="ghost"
              disabled={busy}
              onClick={() => {
                window.location.assign('/admin/apps');
              }}
            >
              Cancel
            </Button>
          }
        >
          <Button
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
            Register app
          </Button>
        </FormActions>
      </Stack>
      {prompt}
    </Page>
  );
}
