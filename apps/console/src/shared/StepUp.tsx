import { Alert, Button, CodeInput, FormField, Modal, PasswordInput, Stack } from '@d3cloud/ui';
import { useCallback, useId, useState } from 'react';
import { api, ApiError } from '../api';

// The prompt that appears when an action asks the person to prove it is them again (REQ-037).
//
// It is not a sign-in: they are already signed in, and this does not replace that. It is the
// answer to "is the person at this keyboard still the owner?", which a session left open on a desk
// cannot answer on its own. A Modal, because it interrupts one action and hands straight back to
// it: the click that asked is held, and runs again once they have proved it.

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
  const [busy, setBusy] = useState(false);

  const reset = () => {
    setPassword('');
    setCode('');
    setProblem(undefined);
    setNeedsFactor(false);
  };

  async function prove(event: React.SyntheticEvent) {
    event.preventDefault();
    if (!pending) return;
    setBusy(true);
    setProblem(undefined);
    try {
      await api.post('/api/account/step-up', { password, ...(code ? { code } : {}) });
      reset();
      onClose();
      pending.retry();
    } catch (err) {
      if (err instanceof ApiError && err.body.error === 'factor_required') setNeedsFactor(true);
      setProblem(err instanceof ApiError ? err.message : 'The console could not reach the server. Try again.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      open={pending !== undefined}
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
          <Button type="submit" form={formId} variant="primary" loading={busy}>
            Confirm
          </Button>
        </>
      }
    >
      <Stack as="form" id={formId} gap="16" aria-label="Confirm it is you" onSubmit={(event) => void prove(event)}>
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
        {needsFactor ? (
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
