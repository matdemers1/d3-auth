import { Alert, Button, Card, FormField, Input, PageHeader, PasswordInput } from '@d3cloud/ui';
import { useEffect, useState } from 'react';
import { api, ApiError } from '../api';

// A-3: change your password (REQ-081).
//
// Anyone holding a factor has to use it here as well as their current password. The screen only
// asks for it once the server says so, so people without a factor never see a step they cannot do.

interface Factors {
  passkeys: { id: string }[];
  totp: { id: string }[];
}

export function Password() {
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [code, setCode] = useState('');
  const [factors, setFactors] = useState<Factors | undefined>();
  const [problems, setProblems] = useState<string[]>([]);
  const [done, setDone] = useState<string | undefined>();
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api
      .get<Factors>('/api/account/factors')
      .then(setFactors)
      .catch(() => {
        setFactors({ passkeys: [], totp: [] });
      });
  }, []);

  const hasPasskey = (factors?.passkeys.length ?? 0) > 0;
  const hasTotp = (factors?.totp.length ?? 0) > 0;

  /** The passkey ceremony, run only when the person chooses that way of proving it is them. */
  async function passkeyAssertion(): Promise<unknown> {
    const { startAuthentication } = await import('@simplewebauthn/browser');
    const options = await api.post<Parameters<typeof startAuthentication>[0]['optionsJSON']>('/api/account/step-up/passkey/begin');
    return startAuthentication({ optionsJSON: options });
  }

  async function change(usePasskey: boolean) {
    setBusy(true);
    setProblems([]);
    setDone(undefined);
    try {
      const passkey = usePasskey ? await passkeyAssertion() : undefined;
      const answer = await api.post<{ otherSessionsRevoked: number }>('/api/account/password', {
        currentPassword: current,
        newPassword: next,
        ...(code ? { code } : {}),
        ...(passkey ? { passkey } : {}),
      });
      setCurrent('');
      setNext('');
      setCode('');
      setDone(
        answer.otherSessionsRevoked > 0
          ? `Password changed. ${String(answer.otherSessionsRevoked)} other sign-in${answer.otherSessionsRevoked === 1 ? ' was' : 's were'} ended.`
          : 'Password changed.',
      );
    } catch (err) {
      if (err instanceof ApiError) {
        const listed = err.body.problems;
        setProblems(Array.isArray(listed) ? (listed as string[]) : [err.message]);
      } else {
        // A cancelled passkey prompt is a choice, not a failure.
        setProblems([]);
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="shell">
      <PageHeader title="Your password" description="At least 12 characters. Length beats punctuation." />

      {problems.length > 0 ? (
        <Alert tone="danger" dynamic title="That did not work">
          <ul className="rows">
            {problems.map((problem) => (
              <li key={problem}>{problem}</li>
            ))}
          </ul>
        </Alert>
      ) : null}
      {done ? (
        <Alert tone="success" dynamic title="Done">
          {done}
        </Alert>
      ) : null}

      <Card padding="lg">
        <form
          className="stack"
          onSubmit={(event) => {
            event.preventDefault();
            void change(false);
          }}
        >
          <FormField label="Current password">
            <PasswordInput
              name="currentPassword"
              autoComplete="current-password"
              required
              value={current}
              onChange={(event) => {
                setCurrent(event.target.value);
              }}
            />
          </FormField>
          <FormField label="New password" help="A few unrelated words work well.">
            <PasswordInput
              name="newPassword"
              autoComplete="new-password"
              required
              value={next}
              onChange={(event) => {
                setNext(event.target.value);
              }}
            />
          </FormField>

          {hasTotp ? (
            <FormField label="Code from your authenticator app" help="Confirms it is you, not just someone at your keyboard.">
              <Input
                name="code"
                inputMode="numeric"
                autoComplete="one-time-code"
                value={code}
                onChange={(event) => {
                  setCode(event.target.value);
                }}
              />
            </FormField>
          ) : null}

          <Button type="submit" variant="primary" loading={busy}>
            Change password
          </Button>
          {hasPasskey ? (
            <Button
              type="button"
              variant="secondary"
              disabled={busy}
              onClick={() => {
                void change(true);
              }}
            >
              Change it with my passkey
            </Button>
          ) : null}
        </form>
      </Card>
    </main>
  );
}
