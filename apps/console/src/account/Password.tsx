import { Alert, Button, CodeInput, FormActions, FormField, Page, PageHeader, PasswordInput, Section, Stack } from '@d3cloud/ui';
import { useEffect, useState } from 'react';
import { api, ApiError } from '../api';

// A-3: change your password (REQ-081).
//
// Anyone holding a factor has to use it here as well as their current password. The screen only
// asks for it once it knows there is one, so people without a factor never see a step they cannot
// do.

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
        // Without the list, the form asks for the password alone; the server still asks for more if it needs it.
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
          : 'Password changed. You stay signed in here.',
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
    <Page width="narrow">
      <PageHeader title="Password" description="At least 12 characters. A few unrelated words beat a short scramble." />

      <Section title="Change your password" description="Changing it signs you out everywhere else.">
        {problems.length > 0 ? (
          <Alert tone="danger" dynamic title="Your password was not changed">
            <ul>
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

        <Stack
          as="form"
          gap="16"
          aria-label="Change your password"
          onSubmit={(event) => {
            event.preventDefault();
            void change(false);
          }}
        >
          <FormField label="Current password" width="lg">
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
          <FormField label="New password" width="lg" help="A few unrelated words work well.">
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
              <CodeInput name="code" autoComplete="one-time-code" value={code} onValueChange={setCode} />
            </FormField>
          ) : null}

          <FormActions
            {...(hasPasskey
              ? {
                  leading: (
                    <Button
                      variant="ghost"
                      disabled={busy}
                      onClick={() => {
                        void change(true);
                      }}
                    >
                      Change it with my passkey
                    </Button>
                  ),
                }
              : {})}
          >
            <Button type="submit" variant="primary" loading={busy}>
              Change password
            </Button>
          </FormActions>
        </Stack>
      </Section>
    </Page>
  );
}
