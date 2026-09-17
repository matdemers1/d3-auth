import { Alert, Button, Card, CodeInput, FormActions, FormField, Input, PasswordInput, Section, Skeleton, Stack } from '@d3cloud/ui';
import { useEffect, useRef, useState } from 'react';
import { ContinueAs } from './ContinueAs';
import { answerTrust, loadInteraction, signInWithPasskey, submitCode, submitEmail, submitPassword, type InteractionView, type StepResult } from './api';
import { LoginLayout, troubleFooter } from './LoginLayout';

// I-1, I-2, I-3: sign in, phone first. Email, then password, then — for anyone with a factor — the
// passkey or the code, then the trusted-browser offer (REQ-076).
//
// Each step is a real <form> with a real action, so it works with JavaScript off and for simple
// automated browsers; React intercepts the submit to avoid a full page load when it can. A field
// takes focus on every step, so the heading does not.

interface Props {
  uid: string;
}

const RETRY_TICK_MS = 1000;

/**
 * What someone already typed into the server-rendered form. React replaces that markup when it
 * mounts; read during the first render, before the commit, the answer survives the swap instead of
 * leaving an empty field under a person who has just filled it in.
 */
const typedIntoFallback = (id: string): string => {
  const field = document.getElementById(id);
  return field instanceof HTMLInputElement ? field.value : '';
};

export function SignIn({ uid }: Props) {
  const [view, setView] = useState<InteractionView | undefined>();
  const [failed, setFailed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | undefined>();
  const [retryAfter, setRetryAfter] = useState(0);
  const [email, setEmail] = useState(() => typedIntoFallback('email'));
  const passwordRef = useRef<HTMLInputElement>(null);
  const [password, setPassword] = useState(() => typedIntoFallback('password'));
  const [code, setCode] = useState('');

  useEffect(() => {
    loadInteraction(uid)
      .then((loaded) => {
        setView(loaded);
        setEmail((typed) => loaded.email ?? typed);
      })
      .catch(() => {
        setFailed(true);
      });
  }, [uid]);

  useEffect(() => {
    if (retryAfter <= 0) return;
    const timer = setInterval(() => {
      setRetryAfter((seconds) => Math.max(0, seconds - 1));
    }, RETRY_TICK_MS);
    return () => {
      clearInterval(timer);
    };
  }, [retryAfter]);

  useEffect(() => {
    if (view?.step === 'password') passwordRef.current?.focus();
  }, [view?.step]);

  function apply(result: StepResult) {
    if (result.redirectTo) {
      window.location.assign(result.redirectTo);
      return;
    }
    if (result.retryAfterSeconds) {
      setRetryAfter(result.retryAfterSeconds);
      setMessage(undefined);
      return;
    }
    if (result.error) {
      setMessage(result.message ?? 'Something went wrong. Try again.');
      return;
    }
    setMessage(undefined);
    setView((current) =>
      current
        ? {
            ...current,
            step: result.step ?? current.step,
            ...(result.csrf ? { csrf: result.csrf } : {}),
            ...(result.factors ? { factors: result.factors } : {}),
          }
        : current,
    );
  }

  async function onSubmit(event: React.SyntheticEvent) {
    if (!view) return;
    event.preventDefault();
    setBusy(true);
    try {
      const result =
        view.step === 'identify'
          ? await submitEmail(uid, view.csrf, email)
          : view.step === 'factor'
            ? await submitCode(uid, view.csrf, code)
            : await submitPassword(uid, view.csrf, password);
      if (view.step === 'factor' && result.error) setCode('');
      apply(result);
    } catch {
      setMessage('We could not reach the server. Check your connection and try again.');
    } finally {
      setBusy(false);
    }
  }

  if (failed) {
    return (
      <LoginLayout
        title="This sign-in link has expired"
        description="Sign-in links last a few minutes. Go back to the app you came from and start again."
      />
    );
  }

  // The frame is known before the step is: skeletons the shape of the form, inside the Card.
  if (!view) {
    return (
      <LoginLayout title="Sign in" focusOnMount={false} busy>
        <Card>
          <Stack gap="16" aria-hidden="true">
            <Skeleton variant="text" width="6rem" />
            <Skeleton variant="block" height="2.5rem" />
            <Skeleton variant="block" height="2.5rem" />
          </Stack>
        </Card>
      </LoginLayout>
    );
  }

  // Signed in already, first time at this app: a different screen entirely.
  if (view.step === 'continue') return <ContinueAs uid={uid} view={view} apply={apply} />;

  const throttled = retryAfter > 0;
  const step = view.step === 'identify' ? 'identify' : view.step === 'factor' ? 'totp' : view.step === 'trust' ? 'trust' : 'password';
  const action = `/api/interaction/${encodeURIComponent(uid)}/${step}`;
  // An account whose factors are not listed still gets the code: it is the step the server can check.
  const factors = view.factors ?? ['totp'];
  const hasPasskey = factors.includes('passkey');
  const hasTotp = factors.includes('totp');

  async function answerDevice(csrf: string, trust: boolean) {
    setBusy(true);
    try {
      apply(await answerTrust(uid, csrf, trust));
    } catch {
      setMessage('We could not reach the server. Check your connection and try again.');
    } finally {
      setBusy(false);
    }
  }

  async function usePasskey(csrf: string) {
    setBusy(true);
    setMessage(undefined);
    try {
      apply(await signInWithPasskey(uid, csrf));
    } catch {
      // A cancelled prompt is not an error worth shouting about; the other way in is still there.
      setMessage(undefined);
    } finally {
      setBusy(false);
    }
  }

  const problems = (
    <>
      {message ? (
        <Alert tone="danger" dynamic title="Check your details">
          {message}
        </Alert>
      ) : null}
      {throttled ? (
        <Alert tone="warning" dynamic title="Too many attempts">
          Wait {retryAfter} second{retryAfter === 1 ? '' : 's'} and try again. Nothing is locked — this is just a pause.
        </Alert>
      ) : null}
    </>
  );

  const title = `Sign in to ${view.clientName}`;
  const footer = troubleFooter(view.operatorDisplayName);

  if (view.step === 'trust') {
    return (
      <LoginLayout title={title} footer={footer} focusOnMount={false}>
        <Section title="Skip this step on this browser?" description="We will not ask for your passkey or code here for the next 30 days. Use this only on a browser that is yours — you can undo it from Security in your account.">
          {problems}
          <Stack as="form" gap="16" method="post" action={action} aria-label="Skip this step on this browser?">
            <input type="hidden" name="csrf" value={view.csrf} />
            <FormActions
              layout="stack"
              leading={
                <Button
                  type="submit"
                  name="trust"
                  value="false"
                  variant="ghost"
                  disabled={busy}
                  onClick={(event) => {
                    event.preventDefault();
                    void answerDevice(view.csrf, false);
                  }}
                >
                  Not this time
                </Button>
              }
            >
              <Button
                type="submit"
                name="trust"
                value="true"
                variant="primary"
                autoFocus
                loading={busy}
                onClick={(event) => {
                  event.preventDefault();
                  void answerDevice(view.csrf, true);
                }}
              >
                Yes, remember this browser
              </Button>
            </FormActions>
          </Stack>
        </Section>
      </LoginLayout>
    );
  }

  if (view.step === 'factor') {
    return (
      <LoginLayout title={title} description="One more step: confirm it is you." footer={footer} focusOnMount={false}>
        <Card>
          <Stack as="form" gap="16" method="post" action={action} aria-label="Confirm it is you" onSubmit={(event) => void onSubmit(event)}>
            <input type="hidden" name="csrf" value={view.csrf} />
            {problems}
            {hasTotp ? (
              <>
                <FormField label="Code from your authenticator app" help="Six digits, from the app you set up. It changes every 30 seconds.">
                  <CodeInput name="code" autoComplete="one-time-code" autoFocus required value={code} onValueChange={setCode} />
                </FormField>
                <FormActions
                  layout="stack"
                  {...(hasPasskey
                    ? {
                        leading: (
                          <Button variant="ghost" disabled={busy} onClick={() => void usePasskey(view.csrf)}>
                            Use a passkey
                          </Button>
                        ),
                      }
                    : {})}
                >
                  <Button type="submit" variant="primary" loading={busy} disabled={throttled}>
                    Verify code
                  </Button>
                </FormActions>
              </>
            ) : (
              <FormActions layout="stack">
                <Button variant="primary" autoFocus loading={busy} onClick={() => void usePasskey(view.csrf)}>
                  Use a passkey
                </Button>
              </FormActions>
            )}
          </Stack>
        </Card>
      </LoginLayout>
    );
  }

  return (
    <LoginLayout
      title={title}
      {...(view.step === 'identify'
        ? {}
        : {
            description: (
              <>
                Signing in as <strong>{email}</strong>
              </>
            ),
          })}
      footer={footer}
      focusOnMount={false}
    >
      <Card>
        <Stack as="form" gap="16" method="post" action={action} aria-label="Sign in" onSubmit={(event) => void onSubmit(event)}>
          <input type="hidden" name="csrf" value={view.csrf} />
          {problems}
          {view.step === 'identify' ? (
            <FormField label="Email" help="The address you were invited with.">
              <Input
                name="email"
                type="email"
                autoComplete="username"
                inputMode="email"
                autoFocus
                required
                value={email}
                onChange={(event) => {
                  setEmail(event.target.value);
                }}
              />
            </FormField>
          ) : (
            <FormField label="Password">
              <PasswordInput
                name="password"
                ref={passwordRef}
                autoComplete="current-password"
                required
                value={password}
                onChange={(event) => {
                  setPassword(event.target.value);
                }}
              />
            </FormField>
          )}
          <FormActions layout="stack">
            <Button type="submit" variant="primary" loading={busy} disabled={throttled}>
              {view.step === 'identify' ? 'Continue' : 'Sign in'}
            </Button>
          </FormActions>
        </Stack>
      </Card>
    </LoginLayout>
  );
}
