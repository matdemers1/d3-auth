import { Alert, Button, Card, FormActions, FormField, Input, PasswordInput, Stack } from '@d3cloud/ui';
import { useEffect, useState } from 'react';
import { LoginLayout } from './LoginLayout';

// I-11: first-run setup. Shown only while the instance has no accounts; the server decides that,
// not this screen. The same form is server-rendered into the page, so it works without JS.

interface Claim {
  ok: boolean;
  message?: string;
  problems?: string[];
  next?: string;
}

const FIELDS = [
  { id: 'email', label: 'Your email', type: 'email', autoComplete: 'email', width: 'lg' },
  { id: 'username', label: 'Username', type: 'text', autoComplete: 'username', width: 'md', help: 'How you appear to apps. Letters, numbers, dot, dash or underscore.' },
  { id: 'displayName', label: 'Display name', type: 'text', autoComplete: 'name', width: 'lg' },
] as const;

export function Setup() {
  const [available, setAvailable] = useState<boolean | undefined>();
  const [busy, setBusy] = useState(false);
  const [problems, setProblems] = useState<string[]>([]);
  const [values, setValues] = useState<Record<string, string>>({ code: '', email: '', username: '', displayName: '', password: '' });

  useEffect(() => {
    fetch('/api/setup', { headers: { accept: 'application/json' } })
      .then((res) => res.json() as Promise<{ available: boolean }>)
      .then((body) => {
        setAvailable(body.available);
      })
      .catch(() => {
        setAvailable(true);
      });
  }, []);

  const set = (id: string) => (event: React.ChangeEvent<HTMLInputElement>) => {
    const { value } = event.target;
    setValues((current) => ({ ...current, [id]: value }));
  };

  async function onSubmit(event: React.SyntheticEvent) {
    event.preventDefault();
    setBusy(true);
    setProblems([]);
    try {
      const res = await fetch('/api/setup', {
        method: 'POST',
        headers: { 'content-type': 'application/json', accept: 'application/json' },
        body: JSON.stringify(values),
      });
      const body = (await res.json()) as Claim;
      if (body.ok) {
        window.location.assign(body.next ?? '/login/setup');
        return;
      }
      setProblems(body.problems?.length ? body.problems : [body.message ?? 'That did not work. Check the details and try again.']);
    } catch {
      setProblems(['We could not reach the server. Try again.']);
    } finally {
      setBusy(false);
    }
  }

  if (available === false) {
    return <LoginLayout title="Setup is finished" description="This instance already has an account. Sign in from the app you want to use." />;
  }

  return (
    <LoginLayout
      title="Set up D3 Auth"
      description="This instance has no accounts yet. Create the owner account to finish setting it up."
      focusOnMount={false}
    >
      <Card>
        <Stack as="form" gap="16" method="post" action="/api/setup" aria-label="Set up D3 Auth" onSubmit={(event) => void onSubmit(event)}>
          {problems.length > 0 ? (
            <Alert tone="danger" dynamic title="The owner account was not created">
              <ul>
                {problems.map((problem) => (
                  <li key={problem}>{problem}</li>
                ))}
              </ul>
            </Alert>
          ) : null}
          <FormField label="Setup code" width="md" help="Printed in the server log when the service started: docker compose logs server.">
            <Input name="code" autoFocus required autoComplete="off" spellCheck={false} value={values.code} onChange={set('code')} />
          </FormField>
          {FIELDS.map((field) => (
            <FormField key={field.id} label={field.label} width={field.width} {...('help' in field ? { help: field.help } : {})}>
              <Input name={field.id} type={field.type} required autoComplete={field.autoComplete} value={values[field.id] ?? ''} onChange={set(field.id)} />
            </FormField>
          ))}
          <FormField label="Password" help="At least 12 characters. A few words you can remember beats a short scramble.">
            <PasswordInput name="password" required autoComplete="new-password" value={values.password} onChange={set('password')} />
          </FormField>
          <FormActions layout="stack">
            <Button type="submit" variant="primary" loading={busy}>
              Create the owner account
            </Button>
          </FormActions>
        </Stack>
      </Card>
    </LoginLayout>
  );
}
