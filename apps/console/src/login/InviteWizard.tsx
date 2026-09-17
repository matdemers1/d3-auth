import { Alert, Button, Card, FormActions, FormField, Input, PasswordInput, Skeleton, Stack } from '@d3cloud/ui';
import { useEffect, useState } from 'react';
import { api, ApiError } from '../api';
import { LoginLayout } from './LoginLayout';

// I-6: the invite wizard. Step one is the account; protecting it with a passkey or a code comes
// next, on the security screen. The same form is server-rendered into the page, so a guest on a
// slow phone sees something that works immediately.

interface Props {
  token: string;
}

interface Described {
  valid: boolean;
  email?: string;
}

export function InviteWizard({ token }: Props) {
  const [invite, setInvite] = useState<Described | undefined>();
  const [values, setValues] = useState({ displayName: '', username: '', password: '' });
  const [problems, setProblems] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api
      .get<Described>(`/api/invite/${encodeURIComponent(token)}`)
      .then(setInvite)
      .catch(() => {
        setInvite({ valid: false });
      });
  }, [token]);

  const set = (key: keyof typeof values) => (event: React.ChangeEvent<HTMLInputElement>) => {
    const { value } = event.target;
    setValues((current) => ({ ...current, [key]: value }));
  };

  async function submit(event: React.SyntheticEvent) {
    event.preventDefault();
    setBusy(true);
    setProblems([]);
    try {
      const result = await api.post<{ ok: boolean; next?: string }>(`/api/invite/${encodeURIComponent(token)}/accept`, values);
      window.location.assign(result.next ?? '/login/welcome');
    } catch (err) {
      if (err instanceof ApiError) {
        const listed = Array.isArray(err.body.problems) ? (err.body.problems as string[]) : [];
        setProblems(listed.length > 0 ? listed : [err.message]);
      } else {
        setProblems(['We could not reach the server. Try again.']);
      }
      setBusy(false);
    }
  }

  if (!invite) {
    return (
      <LoginLayout title="Create your account" focusOnMount={false} busy>
        <Card>
          <Stack gap="16" aria-hidden="true">
            <Skeleton variant="block" height="2.5rem" />
            <Skeleton variant="block" height="2.5rem" />
            <Skeleton variant="block" height="2.5rem" />
          </Stack>
        </Card>
      </LoginLayout>
    );
  }

  if (!invite.valid) {
    return <LoginLayout title="This invite has expired" description="Invites last a few days and can be used once. Ask for a new one." />;
  }

  return (
    <LoginLayout
      title="Create your account"
      description={
        <>
          Signing up as <strong>{invite.email}</strong>
        </>
      }
      focusOnMount={false}
    >
      <Card>
        <Stack
          as="form"
          gap="16"
          method="post"
          action={`/api/invite/${encodeURIComponent(token)}/accept`}
          aria-label="Create your account"
          onSubmit={(event) => void submit(event)}
        >
          {problems.length > 0 ? (
            <Alert tone="danger" dynamic title="Your account was not created yet">
              <ul>
                {problems.map((problem) => (
                  <li key={problem}>{problem}</li>
                ))}
              </ul>
            </Alert>
          ) : null}
          <FormField label="Your name" width="lg">
            <Input name="displayName" autoComplete="name" required autoFocus value={values.displayName} onChange={set('displayName')} />
          </FormField>
          <FormField label="Username" width="md" help="How you appear to apps. Letters, numbers, dot, dash or underscore.">
            <Input name="username" autoComplete="username" spellCheck={false} required value={values.username} onChange={set('username')} />
          </FormField>
          <FormField label="Password" help="At least 12 characters. A few words you can remember beats a short scramble.">
            <PasswordInput name="password" autoComplete="new-password" required value={values.password} onChange={set('password')} />
          </FormField>
          <FormActions layout="stack">
            <Button type="submit" variant="primary" loading={busy}>
              Create my account
            </Button>
          </FormActions>
        </Stack>
      </Card>
    </LoginLayout>
  );
}
