import { Alert, Button, Card, FormField, Input, PasswordInput } from '@d3cloud/ui';
import { useState } from 'react';
import { api, ApiError } from '../api';

// The prompt that appears when an owner-only action asks them to prove it is them again
// (REQ-037).
//
// It is not a sign-in: they are already signed in, and this does not replace that. It is the
// answer to "is the person at this keyboard still the owner?", which a session left open on a
// desk cannot answer on its own.

interface Props {
  /** What they were trying to do, so the prompt can say why it appeared. */
  action: string;
  onProved: () => void;
  onCancel: () => void;
}

export function StepUp({ action, onProved, onCancel }: Props) {
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [problem, setProblem] = useState<string | undefined>();
  const [needsFactor, setNeedsFactor] = useState(false);
  const [busy, setBusy] = useState(false);

  async function prove(event: React.SyntheticEvent<HTMLFormElement, SubmitEvent>) {
    event.preventDefault();
    setBusy(true);
    setProblem(undefined);
    try {
      await api.post('/api/account/step-up', { password, ...(code ? { code } : {}) });
      onProved();
    } catch (err) {
      if (err instanceof ApiError && err.body.error === 'factor_required') {
        setNeedsFactor(true);
        setProblem(err.message);
      } else {
        setProblem(err instanceof ApiError ? err.message : 'That did not work.');
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card padding="lg">
      <h2 className="section-title">Confirm it is you</h2>
      <p className="muted">Before {action}. You will not be asked again for five minutes.</p>

      {problem ? (
        <Alert tone="danger" dynamic title="That did not work">
          {problem}
        </Alert>
      ) : null}

      <form className="stack" onSubmit={(event) => void prove(event)}>
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
          <FormField label="Code from your authenticator app">
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
          Confirm
        </Button>
        <Button type="button" variant="secondary" disabled={busy} onClick={onCancel}>
          Not now
        </Button>
      </form>
    </Card>
  );
}
