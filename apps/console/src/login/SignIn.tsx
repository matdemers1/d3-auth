import { Alert, Button, Card, FormField, Input, PasswordInput } from '@d3cloud/ui';
import { useEffect, useRef, useState } from 'react';
import { loadInteraction, submitEmail, submitPassword, type InteractionView, type StepResult } from './api';

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
    setView((current) => (current ? { ...current, step: result.step ?? current.step, ...(result.csrf ? { csrf: result.csrf } : {}) } : current));
  }

  async function onSubmit(event: React.SyntheticEvent<HTMLFormElement, SubmitEvent>) {
    if (!view) return;
    event.preventDefault();
    setBusy(true);
    try {
      const result =
        view.step === 'identify'
          ? await submitEmail(uid, view.csrf, email)
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
  const action = `/api/interaction/${encodeURIComponent(uid)}/${view.step === 'identify' ? 'identify' : 'password'}`;

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
      <Card padding="lg">
        <form method="post" action={action} onSubmit={(event) => void onSubmit(event)} className="signin-form">
          <input type="hidden" name="csrf" value={view.csrf} />
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
          <Button type="submit" variant="primary" loading={busy} disabled={throttled}>
            {view.step === 'identify' ? 'Continue' : 'Sign in'}
          </Button>
        </form>
      </Card>
      <p className="signin-footnote">Trouble signing in? Ask {view.operatorDisplayName}.</p>
    </main>
  );
}
