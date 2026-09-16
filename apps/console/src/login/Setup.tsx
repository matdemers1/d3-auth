import { Alert, Button, Card, FormField, Input, PasswordInput } from '@d3cloud/ui';
import { useEffect, useState } from 'react';

// I-11: first-run setup. Shown only while the instance has no accounts; the server decides that,
// not this screen. The same form is server-rendered into the page, so it works without JS.

interface Claim {
  ok: boolean;
  message?: string;
  problems?: string[];
  next?: string;
}

const FIELDS = [
  { id: 'email', label: 'Your email', type: 'email', autoComplete: 'email' },
  { id: 'username', label: 'Username', type: 'text', autoComplete: 'username', help: 'How you appear to apps.' },
  { id: 'displayName', label: 'Display name', type: 'text', autoComplete: 'name' },
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

  async function onSubmit(event: React.SyntheticEvent<HTMLFormElement, SubmitEvent>) {
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
    return (
      <main className="shell shell--narrow">
        <h1 className="signin-title">Setup is finished</h1>
        <p className="signin-identity">This instance already has an account. Sign in from the app you want to use.</p>
      </main>
    );
  }

  return (
    <main className="shell shell--narrow">
      <h1 className="signin-title">Set up D3 Auth</h1>
      <p className="signin-identity">This instance has no accounts yet. Create the owner account to finish setting it up.</p>
      {problems.length > 0 ? (
        <Alert tone="danger" dynamic title="That did not work">
          <ul>
            {problems.map((problem) => (
              <li key={problem}>{problem}</li>
            ))}
          </ul>
        </Alert>
      ) : null}
      <Card padding="lg">
        <form method="post" action="/api/setup" onSubmit={(event) => void onSubmit(event)} className="signin-form">
          <FormField label="Setup code" help="Printed in the server log at startup: docker compose logs server.">
            <Input name="code" autoFocus required autoComplete="off" spellCheck={false} value={values.code} onChange={set('code')} />
          </FormField>
          {FIELDS.map((field) => (
            <FormField key={field.id} label={field.label} {...('help' in field ? { help: field.help } : {})}>
              <Input
                name={field.id}
                type={field.type}
                required
                autoComplete={field.autoComplete}
                value={values[field.id] ?? ''}
                onChange={set(field.id)}
              />
            </FormField>
          ))}
          <FormField label="Password" help="At least 12 characters. A few words you can remember beats a short scramble.">
            <PasswordInput name="password" required autoComplete="new-password" value={values.password} onChange={set('password')} />
          </FormField>
          <Button type="submit" variant="primary" loading={busy}>
            Create the owner account
          </Button>
        </form>
      </Card>
    </main>
  );
}
