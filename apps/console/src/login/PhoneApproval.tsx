import { Alert, Button, Stack } from '@d3cloud/ui';
import { useEffect, useRef, useState } from 'react';
import { pollApproval, startApproval, type StepResult } from './api';

// Sign-in approval (AUTH-T-10.5): ask the phone instead of typing a code. The browser shows a
// number, the phone offers three, and the person picks this one. A denial, a wrong number or two
// minutes passing all come back here with the code still on offer — the phone never locks anybody out.

const POLL_MS = 2000;

interface Props {
  uid: string;
  csrf: string;
  /** The server's next step once the phone approved: the trust offer, or the redirect. */
  onApproved: (result: StepResult) => void;
}

export function PhoneApproval({ uid, csrf, onApproved }: Props) {
  const [pending, setPending] = useState<{ id: string; number: number } | undefined>();
  const [said, setSaid] = useState<string | undefined>();
  const [busy, setBusy] = useState(false);
  const stopped = useRef(false);
  // The parent's handler changes every render; the poll must not restart because of it.
  const approved = useRef(onApproved);
  approved.current = onApproved;

  useEffect(() => {
    stopped.current = false;
    if (!pending) return;
    const timer = setInterval(() => {
      void pollApproval(uid, csrf, pending.id)
        .then((result) => {
          if (stopped.current || result.status === 'pending') return;
          if (result.status === 'approved' || result.redirectTo) {
            stopped.current = true;
            setPending(undefined);
            approved.current(result);
            return;
          }
          stopped.current = true;
          setPending(undefined);
          setSaid(
            result.status === 'expired'
              ? 'Nobody answered on the phone in time. Ask again, or use your code.'
              : 'That sign-in was not approved on your phone. Use your code, or ask again.',
          );
        })
        .catch(() => undefined);
    }, POLL_MS);
    return () => {
      stopped.current = true;
      clearInterval(timer);
    };
  }, [pending, uid, csrf]);

  async function ask() {
    setBusy(true);
    setSaid(undefined);
    try {
      const started = await startApproval(uid, csrf);
      if (started.approvalId && typeof started.number === 'number') {
        setPending({ id: started.approvalId, number: started.number });
      } else {
        setSaid(started.retryAfterSeconds ? 'Too many requests to your phone. Use your code for now.' : 'Your phone could not be asked. Use your code.');
      }
    } catch {
      setSaid('We could not reach the server. Check your connection and try again.');
    } finally {
      setBusy(false);
    }
  }

  if (pending) {
    return (
      <Stack gap="8">
        <p className="approval-ask">On your phone, open D3 Constellation and pick</p>
        <output className="approval-number" aria-live="polite" aria-label={`Pick ${String(pending.number)} on your phone`}>
          {pending.number}
        </output>
        <p className="approval-ask">Waiting for your phone…</p>
      </Stack>
    );
  }

  return (
    <Stack gap="8">
      {said ? (
        <Alert tone="warning" dynamic title="Not approved">
          {said}
        </Alert>
      ) : null}
      <Button variant="secondary" loading={busy} onClick={() => void ask()}>
        Approve on my phone
      </Button>
    </Stack>
  );
}
