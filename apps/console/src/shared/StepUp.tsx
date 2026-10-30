import { Alert, Button, CodeInput, FormField, Modal, PasswordInput, Stack } from '@d3cloud/ui';
import { useCallback, useEffect, useId, useRef, useState } from 'react';
import { api, ApiError } from '../api';

// The prompt that appears when an action asks the person to prove it is them again (REQ-037).
//
// It is not a sign-in: they are already signed in, and this does not replace that. It is the
// answer to "is the person at this keyboard still the owner?", which a session left open on a desk
// cannot answer on its own. A Modal, because it interrupts one action and hands straight back to
// it: the click that asked is held, and runs again once they have proved it.
//
// Somebody holding a factor proves it with the password and that factor, so the prompt offers the
// factors they actually have: a passkey button for a passkey, a code field for an authenticator app.

interface Factors {
  passkeys: { id: string }[];
  totp: { id: string }[];
}

interface Pending {
  /** What they were trying to do, so the prompt can say why it appeared. */
  describe: string;
  retry: () => void;
}

function StepUpModal({ pending, onClose }: { pending: Pending | undefined; onClose: () => void }) {
  const formId = useId();
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [problem, setProblem] = useState<string | undefined>();
  const [needsFactor, setNeedsFactor] = useState(false);
  const [factors, setFactors] = useState<Factors | undefined>();
  const [busy, setBusy] = useState(false);
  const form = useRef<HTMLFormElement>(null);
  const open = pending !== undefined;

  useEffect(() => {
    if (!open) return;
    api
      .get<Factors>('/api/account/factors')
      .then(setFactors)
      .catch(() => {
        // Without the list, the prompt asks for the password alone; the server says if it needs more.
        setFactors({ passkeys: [], totp: [] });
      });
  }, [open]);

  const hasPasskey = (factors?.passkeys.length ?? 0) > 0;
  const hasTotp = (factors?.totp.length ?? 0) > 0;
  // The server asking for a factor the list did not show (it failed to load) still gets a field.
  const showCode = hasTotp || (needsFactor && !hasPasskey);

  const reset = () => {
    setPassword('');
    setCode('');
    setProblem(undefined);
    setNeedsFactor(false);
  };

  /** The passkey ceremony, run only when the person chooses that way of proving it is them. */
  async function passkeyAssertion(): Promise<unknown> {
    const { startAuthentication } = await import('@simplewebauthn/browser');
    const options = await api.post<Parameters<typeof startAuthentication>[0]['optionsJSON']>('/api/account/step-up/passkey/begin');
    return startAuthentication({ optionsJSON: options });
  }

  async function prove(usePasskey: boolean) {
    if (!pending) return;
    setBusy(true);
    setProblem(undefined);
    try {
      const passkey = usePasskey ? await passkeyAssertion() : undefined;
      await api.post('/api/account/step-up', { password, ...(code ? { code } : {}), ...(passkey ? { passkey } : {}) });
      reset();
      onClose();
      pending.retry();
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.body.error === 'factor_required') setNeedsFactor(true);
        setProblem(err.message);
      } else if (!usePasskey) {
        setProblem('The console could not reach the server. Try again.');
      }
      // A cancelled passkey prompt is a choice, not a failure.
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      open={open}
      onOpenChange={(open) => {
        if (!open) {
          reset();
          onClose();
        }
      }}
      title="Confirm it is you"
      description={pending ? `Before ${pending.describe}. You will not be asked again for five minutes.` : ''}
      footer={
        <>
          <Button
            disabled={busy}
            onClick={() => {
              reset();
              onClose();
            }}
          >
            Not now
          </Button>
          {hasPasskey ? (
            <Button
              type="button"
              variant="primary"
              loading={busy}
              onClick={() => {
                if (form.current?.reportValidity()) void prove(true);
              }}
            >
              Confirm with my passkey
            </Button>
          ) : (
            <Button type="submit" form={formId} variant="primary" loading={busy}>
              Confirm
            </Button>
          )}
        </>
      }
    >
      <Stack
        as="form"
        ref={form}
        id={formId}
        gap="16"
        aria-label="Confirm it is you"
        onSubmit={(event) => {
          event.preventDefault();
          void prove(hasPasskey && code === '');
        }}
      >
        {problem ? (
          <Alert tone="danger" dynamic title="That did not work">
            {problem}
          </Alert>
        ) : null}
        <FormField label="Your password">
          <PasswordInput
            name="password"
            autoComplete="current-password"
            required
            autoFocus
            value={password}
            onChange={(event) => {
              setPassword(event.target.value);
            }}
          />
        </FormField>
        {showCode ? (
          <FormField label="Code from your authenticator app" help="Six digits. It changes every 30 seconds.">
            <CodeInput name="code" autoComplete="one-time-code" value={code} onValueChange={setCode} />
          </FormField>
        ) : null}
      </Stack>
    </Modal>
  );
}

/**
 * `ask(err, describe, retry)` returns true when the error was a request for fresh proof, and holds
 * the retry until the person has given it. Render `prompt` once, anywhere in the page.
 */
export function useStepUp(): { ask: (err: unknown, describe: string, retry: () => void) => boolean; prompt: React.ReactNode } {
  const [pending, setPending] = useState<Pending | undefined>();
  const ask = useCallback((err: unknown, describe: string, retry: () => void): boolean => {
    if (err instanceof ApiError && err.body.error === 'step_up_required') {
      setPending({ describe, retry });
      return true;
    }
    return false;
  }, []);
  const prompt = (
    <StepUpModal
      pending={pending}
      onClose={() => {
        setPending(undefined);
      }}
    />
  );
  return { ask, prompt };
}
