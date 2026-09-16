import { Alert, Badge, Button, Card, PageHeader, Skeleton } from '@d3cloud/ui';
import { useEffect, useState } from 'react';
import { api, ApiError } from '../api';
import { StepUp } from './StepUp';

// C-9: the signing keys (REQ-070, REQ-118).
//
// Rotation is four states and two waits, and the waits are the whole point — so this screen's
// real job is to say why a button is disabled and when it will not be. Promote before consumers
// have seen a key and every token you issue is rejected by apps holding a stale key set.

interface Key {
  kid: string;
  alg: string;
  status: 'next' | 'current' | 'retiring' | 'retired';
  createdAt: string;
  retireAfter: string | null;
  ready: boolean;
  readyAt: string | null;
  signingNow: boolean;
}

const when = (iso: string | null): string => (iso ? new Date(iso).toLocaleString() : '—');

const TONE: Record<Key['status'], 'neutral' | 'attention' | 'danger'> = {
  current: 'attention',
  next: 'neutral',
  retiring: 'neutral',
  retired: 'danger',
};

export function Keys() {
  const [keys, setKeys] = useState<Key[] | undefined>();
  const [restartRequired, setRestartRequired] = useState(false);
  const [message, setMessage] = useState<{ tone: 'danger' | 'success'; text: string } | undefined>();
  const [failed, setFailed] = useState(false);
  const [busy, setBusy] = useState(false);
  /** What to do once they have proved it is them, so the click is not lost. */
  const [pending, setPending] = useState<{ describe: string; retry: () => void } | undefined>();

  const load = () => {
    api
      .get<{ keys: Key[]; restartRequired: boolean }>('/api/admin/keys')
      .then((answer) => {
        setKeys(answer.keys);
        setRestartRequired(answer.restartRequired);
      })
      .catch(() => {
        setFailed(true);
      });
  };

  useEffect(load, []);

  async function act(path: string, body: unknown, said: string, describe = 'changing the signing keys') {
    setBusy(true);
    setMessage(undefined);
    try {
      await api.post(path, body);
      setPending(undefined);
      setMessage({ tone: 'success', text: said });
      load();
    } catch (err) {
      if (err instanceof ApiError && err.body.error === 'step_up_required') {
        // Hold the click rather than losing it: they came here to do this.
        setPending({ describe, retry: () => void act(path, body, said, describe) });
        return;
      }
      setMessage({ tone: 'danger', text: err instanceof ApiError ? err.message : 'That did not work.' });
    } finally {
      setBusy(false);
    }
  }

  if (failed) {
    return (
      <main className="shell">
        <Alert tone="info" title="Keys are the owner's to manage">
          Rotating a signing key changes what every app has to trust.
        </Alert>
      </main>
    );
  }

  const next = keys?.find((key) => key.status === 'next');
  const retiring = keys?.find((key) => key.status === 'retiring');

  return (
    <main className="shell">
      <PageHeader title="Signing keys" description="What proves a token came from here." />

      {message ? (
        <Alert tone={message.tone} dynamic title={message.tone === 'danger' ? 'That did not work' : 'Done'}>
          {message.text}
        </Alert>
      ) : null}

      {pending ? (
        <StepUp
          action={pending.describe}
          onProved={() => {
            pending.retry();
          }}
          onCancel={() => {
            setPending(undefined);
          }}
        />
      ) : null}

      {restartRequired ? (
        <Alert tone="warning" title="Restart to finish the rotation">
          A key was promoted, but this process is still signing with the one it loaded when it started. Restart the service —
          <code className="copy-link">docker compose restart server</code> — and it will pick up the new one. Nothing is broken
          meanwhile: the old key is still published, so its tokens still verify.
        </Alert>
      ) : null}

      <Card padding="lg">
        <h2 className="section-title">How rotation works</h2>
        <ol className="rows">
          <li>
            <strong>Generate</strong> a next key. It is published immediately and signs nothing, which gives every app time to
            fetch it before it has to trust it.
          </li>
          <li>
            <strong>Promote</strong> it, two hours later at the earliest, then restart the service. The old key moves to
            retiring and keeps verifying what it already signed.
          </li>
          <li>
            <strong>Retire</strong> the old key once nothing it signed can still be in use. It leaves the key set.
          </li>
        </ol>
      </Card>

      {!keys ? (
        <Skeleton height="10rem" />
      ) : (
        <Card padding="lg">
          <ul className="rows">
            {keys.map((key) => (
              <li key={key.kid} className="row">
                <div>
                  <strong>{key.alg}</strong> <span className="muted">{key.kid.slice(0, 16)}…</span>
                  <div className="muted">
                    created {when(key.createdAt)}
                    {key.status === 'next' ? ` · can be promoted ${key.ready ? 'now' : when(key.readyAt)}` : ''}
                    {key.status === 'retiring' ? ` · can be retired ${key.ready ? 'now' : when(key.retireAfter)}` : ''}
                  </div>
                </div>
                <div className="row-meta">
                  <Badge tone={TONE[key.status]}>{key.status}</Badge>
                  {key.signingNow ? <Badge tone="neutral">signing now</Badge> : null}
                </div>
              </li>
            ))}
          </ul>
        </Card>
      )}

      <Card padding="lg">
        <h2 className="section-title">Rotate</h2>
        <div className="stack">
          <Button variant="secondary" disabled={busy || next !== undefined} onClick={() => void act('/api/admin/keys/generate', { alg: 'ES256' }, 'A next key is published. Promote it after the window.')}>
            {next ? 'A next key is already waiting' : 'Generate a next ES256 key'}
          </Button>
          <Button
            variant="primary"
            disabled={busy || next === undefined || !next.ready}
            onClick={() => void act('/api/admin/keys/promote', { alg: 'ES256' }, 'Promoted. Restart the service to start signing with it.')}
          >
            {next && !next.ready ? `Promote (waiting until ${when(next.readyAt)})` : 'Promote the next key'}
          </Button>
          <Button
            variant="secondary"
            disabled={busy || retiring === undefined || !retiring.ready}
            onClick={() => void act('/api/admin/keys/retire', {}, 'Retired. It is out of the key set.')}
          >
            {retiring && !retiring.ready ? `Retire the old key (waiting until ${when(retiring.retireAfter)})` : 'Retire the old key'}
          </Button>
        </div>
      </Card>
    </main>
  );
}
