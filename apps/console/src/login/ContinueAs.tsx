import { Button, Card, FormActions } from '@d3cloud/ui';
import { useState } from 'react';
import { answerContinue, switchAccount, type InteractionView, type StepResult } from './api';
import { LoginLayout, troubleFooter } from './LoginLayout';

// I-4: *Continue to {app} as {username}* (REQ-059).
//
// Not a consent screen — there is nothing to agree to (REQ-060). It is shown once per app, the
// first time somebody signs in to it, because arriving at a new app from a session you opened days
// ago is exactly when you might not be the person you think you are.

interface Props {
  uid: string;
  view: InteractionView;
  apply: (result: StepResult) => void;
}

export function ContinueAs({ uid, view, apply }: Props) {
  const [busy, setBusy] = useState(false);
  const who = view.username ?? '';

  async function answer(act: () => Promise<StepResult>) {
    setBusy(true);
    try {
      apply(await act());
    } finally {
      setBusy(false);
    }
  }

  return (
    <LoginLayout
      title={`Continue to ${view.clientName}`}
      description={
        <>
          You are signed in as <strong>{who}</strong>.
        </>
      }
      footer={troubleFooter(view.operatorDisplayName)}
    >
      <Card>
        <FormActions
          layout="stack"
          leading={
            <Button variant="ghost" disabled={busy} onClick={() => void answer(() => switchAccount(uid, view.csrf))}>
              Not you? Sign in as someone else
            </Button>
          }
        >
          <Button variant="primary" loading={busy} onClick={() => void answer(() => answerContinue(uid, view.csrf))}>
            Continue as {who}
          </Button>
        </FormActions>
      </Card>
    </LoginLayout>
  );
}
