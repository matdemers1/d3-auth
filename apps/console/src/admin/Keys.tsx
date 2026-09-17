import { Alert, Badge, Button, DataList, DataListRow, Page, PageHeader, Section } from '@d3cloud/ui';
import { KeyRound } from 'lucide-react';
import { useState } from 'react';
import { api } from '../api';
import { Confirm } from '../shared/Confirm';
import { icon } from '../shared/icons';
import { messageOf, useLoad } from '../shared/load';
import { useMe } from '../shared/me';
import { useStepUp } from '../shared/StepUp';
import { Denied, LoadFailed, RowsSkeleton } from '../shared/states';

// C-9: the signing keys (REQ-070, REQ-118).
//
// Rotation is four states and two waits, and the waits are the whole point — so this screen's real
// job is to say why a button is disabled and when it will not be. Promote before consumers have
// seen a key and every token you issue is rejected by apps holding a stale key set.

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

const when = (iso: string | null): string => (iso ? new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : '—');

const DESCRIPTION = 'What proves a token came from here. Rotate on a schedule, or at once if a key may be exposed.';

function Header() {
  return <PageHeader title="Keys" description={DESCRIPTION} />;
}

export function Keys() {
  const me = useMe();
  const { state, reload, retry } = useLoad(() => api.get<{ keys: Key[]; restartRequired: boolean }>('/api/admin/keys'));
  const { ask, prompt } = useStepUp();
  const [feedback, setFeedback] = useState<{ tone: 'danger' | 'success'; text: string } | undefined>();
  const [busy, setBusy] = useState(false);

  async function act(path: string, body: unknown, said: string, describe = 'changing the signing keys') {
    setBusy(true);
    setFeedback(undefined);
    try {
      await api.post(path, body);
      setFeedback({ tone: 'success', text: said });
      reload();
    } catch (err) {
      // Hold the click rather than losing it: they came here to do this.
      if (ask(err, describe, () => void act(path, body, said, describe))) return;
      setFeedback({ tone: 'danger', text: messageOf(err) });
    } finally {
      setBusy(false);
    }
  }

  if (state.status === 'loading') {
    return (
      <Page aria-busy="true">
        <Header />
        <RowsSkeleton rows={2} leading />
      </Page>
    );
  }
  if (state.status === 'denied') {
    return (
      <Page>
        <Header />
        <Denied heading="Keys are the owner’s">
          Rotating a signing key changes what every app has to trust, so only the owner can. Ask {me?.operatorDisplayName ?? 'the owner'} if a key
          needs rotating.
        </Denied>
      </Page>
    );
  }
  if (state.status === 'failed') {
    return (
      <Page>
        <Header />
        <LoadFailed what="The keys" message={state.message} onRetry={retry} />
      </Page>
    );
  }

  const { keys, restartRequired } = state.data;
  const next = keys.find((key) => key.status === 'next');
  const retiring = keys.find((key) => key.status === 'retiring');

  return (
    <Page>
      <Header />

      {restartRequired ? (
        <Alert tone="warning" title="Restart to finish the rotation">
          <p>
            A key was promoted, but this process is still signing with the one it loaded when it started. Restart the service and it picks up
            the new one: <code>docker compose restart server</code>
          </p>
          <p>Nothing is broken meanwhile. The old key is still published, so its tokens still verify.</p>
        </Alert>
      ) : null}

      <Section title="Signing keys" description="The current key signs; a next key is published ahead of time; a retiring key still verifies what it signed.">
        <DataList aria-label="Signing keys">
          {keys.map((key) => (
            <DataListRow
              key={key.kid}
              leading={icon(KeyRound, 20)}
              title={
                <code>
                  {key.alg} · {key.kid.slice(0, 16)}…
                </code>
              }
              description={`Created ${when(key.createdAt)}${
                key.status === 'next' ? ` · can be promoted ${key.ready ? 'now' : when(key.readyAt)}` : ''
              }${key.status === 'retiring' ? ` · can be retired ${key.ready ? 'now' : when(key.retireAfter)}` : ''}`}
              meta={
                <>
                  {/* Every state here is ordinary, including retired: hue is kept for something that needs someone. */}
                  <Badge size="sm">
                    {key.status}
                  </Badge>
                  {key.signingNow ? <Badge size="sm">signing now</Badge> : null}
                </>
              }
            />
          ))}
        </DataList>
      </Section>

      <Section title="Rotate" description="Three steps, with a wait between each so no app is caught holding a key set it has not refreshed.">
        {feedback ? (
          <Alert tone={feedback.tone} dynamic title={feedback.tone === 'danger' ? 'That did not work' : 'Done'}>
            {feedback.text}
          </Alert>
        ) : null}
        <DataList aria-label="Rotation steps">
            <DataListRow
              truncate={false}
              title="1. Generate a next key"
              description="It is published immediately and signs nothing, which gives every app time to fetch it before it has to trust it."
              actions={
                <Button
                  size="sm"
                  disabled={busy || next !== undefined}
                  onClick={() => void act('/api/admin/keys/generate', { alg: 'ES256' }, 'A next key is published. Promote it after the window.')}
                >
                  {next ? 'A next key is already waiting' : 'Generate a next ES256 key'}
                </Button>
              }
            />
            <DataListRow
              truncate={false}
              title="2. Promote it"
              description="Two hours later at the earliest, then restart the service. The old key moves to retiring and keeps verifying what it already signed."
              actions={
                <Button
                  size="sm"
                  disabled={busy || next === undefined || !next.ready}
                  onClick={() => void act('/api/admin/keys/promote', { alg: 'ES256' }, 'Promoted. Restart the service to start signing with it.')}
                >
                  {next && !next.ready ? `Promote (waiting until ${when(next.readyAt)})` : 'Promote the next key'}
                </Button>
              }
            />
            <DataListRow
              truncate={false}
              title="3. Retire the old key"
              description="Once nothing it signed can still be in use. It leaves the key set, and anything it signed stops verifying."
              actions={
                <Confirm
                  trigger={
                    <Button size="sm" variant="danger-ghost" disabled={busy || retiring === undefined || !retiring.ready}>
                      {retiring && !retiring.ready ? `Retire the old key (waiting until ${when(retiring.retireAfter)})` : 'Retire the old key'}
                    </Button>
                  }
                  title="Retire the old key?"
                  description="It leaves the published key set now. Any token it signed that is still in use stops verifying, and the key cannot be brought back."
                  confirm="Retire the old key"
                  cancel="Keep it for now"
                  onConfirm={async () => {
                    try {
                      await api.post('/api/admin/keys/retire', {});
                      setFeedback({ tone: 'success', text: 'Retired. It is out of the key set.' });
                      reload();
                    } catch (err) {
                      if (!ask(err, 'retiring a signing key', () => void act('/api/admin/keys/retire', {}, 'Retired. It is out of the key set.'))) throw err;
                    }
                  }}
                />
              }
            />
        </DataList>
      </Section>

      {prompt}
    </Page>
  );
}
