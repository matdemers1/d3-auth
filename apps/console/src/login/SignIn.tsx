import { Alert, Button, Card, FormField, Input, PasswordInput } from '@d3cloud/ui';
import { useEffect, useRef, useState } from 'react';
import { answerTrust, loadInteraction, signInWithPasskey, submitCode, submitEmail, submitPassword, type InteractionView, type StepResult } from './api';

// I-1: sign in, phone first. Email step, then password step (REQ-076).
//
// The form is a real <form> with a real action, so it works with JavaScript off and for simple
// automated browsers; React intercepts the submit to avoid a full page load when it can.

interface Props {
  uid: string;
}

const RETRY_TICK_MS = 1000;

export function SignIn({ uid }: Props) {
  const [view, setView] = useState<InteractionView | undefined>();
  const [failed, setFailed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | undefined>();
  const [retryAfter, setRetryAfter] = useState(0);
  const [email, setEmail] = useState('');
  const passwordRef = useRef<HTMLInputElement>(null);
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');

  useEffect(() => {
    loadInteraction(uid)
      .then((loaded) => {
        setView(loaded);
        setEmail(loaded.email ?? '');
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

  async function onSubmit(event: React.SyntheticEvent<HTMLFormElement, SubmitEvent>) {
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
      apply(result);
    } catch {
      setMessage('We could not reach the server. Check your connection and try again.');
    } finally {
      setBusy(false);
    }
  }

  if (failed) {
    return (
      <main className="shell shell--narrow">
        <Alert tone="danger" title="This sign-in link has expired">
          Go back to the app you came from and try again.
        </Alert>
      </main>
    );
  }

  if (!view) {
    return <main className="shell shell--narrow" aria-busy="true" />;
  }

  const throttled = retryAfter > 0;
  const step =
    view.step === 'identify' ? 'identify' : view.step === 'factor' ? 'totp' : view.step === 'trust' ? 'trust' : 'password';
  const action = `/api/interaction/${encodeURIComponent(uid)}/${step}`;
  const hasPasskey = (view.factors ?? []).includes('passkey');

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
      // A cancelled prompt is not an error worth shouting about; the password is still there.
      setMessage(undefined);
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="shell shell--narrow">
      <h1 className="signin-title">Sign in to {view.clientName}</h1>
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
      {view.step === 'trust' ? (
        <Card padding="lg">
          <form method="post" action={action} className="signin-form">
            <input type="hidden" name="csrf" value={view.csrf} />
            <p className="signin-identity">Skip this step on this browser?</p>
            <p className="signin-footnote">
              We will not ask for your passkey or code here for the next 30 days. Use this only on a browser that is yours
              — you can undo it from Security in your account.
            </p>
            <Button
              type="submit"
              name="trust"
              value="true"
              variant="primary"
              loading={busy}
              onClick={(event) => {
                event.preventDefault();
                void answerDevice(view.csrf, true);
              }}
            >
              Yes, remember this browser
            </Button>
            <Button
              type="submit"
              name="trust"
              value="false"
              variant="secondary"
              disabled={busy}
              onClick={(event) => {
                event.preventDefault();
                void answerDevice(view.csrf, false);
              }}
            >
              Not this time
            </Button>
          </form>
        </Card>
      ) : (
      <Card padding="lg">
        <form method="post" action={action} onSubmit={(event) => void onSubmit(event)} className="signin-form">
          <input type="hidden" name="csrf" value={view.csrf} />
          {view.step === 'factor' ? (
            <>
              <p className="signin-identity">One more step: confirm it is you.</p>
              {hasPasskey ? (
                <Button type="button" variant="primary" onClick={() => void usePasskey(view.csrf)} disabled={busy}>
                  Use a passkey
                </Button>
              ) : null}
              <FormField label="Code from your authenticator app" help="Six digits, from the app you set up.">
                <Input
                  name="code"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  autoFocus
                  required
                  value={code}
                  onChange={(event) => {
                    setCode(event.target.value);
                  }}
                />
              </FormField>
            </>
          ) : view.step === 'identify' ? (
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
            <>
              <p className="signin-identity">
                Signing in as <strong>{email}</strong>
              </p>
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
            </>
          )}
          <Button type="submit" variant={view.step === 'factor' && hasPasskey ? 'secondary' : 'primary'} loading={busy} disabled={throttled}>
            {view.step === 'identify' ? 'Continue' : view.step === 'factor' ? 'Confirm code' : 'Sign in'}
          </Button>
        </form>
      </Card>
      )}
      <p className="signin-footnote">Trouble signing in? Ask {view.operatorDisplayName}.</p>
    </main>
  );
}
