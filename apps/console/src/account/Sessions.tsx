import { Alert, Badge, Button, DataList, DataListRow, Page, PageHeader, Section } from '@d3cloud/ui';
import { Laptop } from 'lucide-react';
import { useState } from 'react';
import { api } from '../api';
import { icon } from '../shared/icons';
import { messageOf, useLoad } from '../shared/load';
import { useStepUp } from '../shared/StepUp';
import { LoadFailed, RowsSkeleton } from '../shared/states';
import { describeAddress, describeDevice } from './device-name';

// A-5: where you are signed in, and how to end any of it (REQ-083).

interface SessionRow {
  id: string;
  ip: string | null;
  userAgent: string | null;
  createdAt: string;
  lastSeenAt: string;
  current: boolean;
}

interface DeviceRow {
  id: string;
  userAgent: string | null;
  createdAt: string;
  expiresAt: string;
  current: boolean;
}

type Region = 'sessions' | 'devices';

const when = (iso: string): string => new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });

const DESCRIPTION = 'Everywhere you are signed in, and the browsers you have chosen to trust.';

export function Sessions() {
  const sessions = useLoad(() => api.get<{ sessions: SessionRow[] }>('/api/account/sessions').then((answer) => answer.sessions));
  const devices = useLoad(() => api.get<{ devices: DeviceRow[] }>('/api/account/devices').then((answer) => answer.devices));
  const { ask, prompt } = useStepUp();
  const [message, setMessage] = useState<{ where: Region; tone: 'success' | 'danger'; text: string } | undefined>();
  const [busy, setBusy] = useState(false);

  // Ending other sign-ins asks for fresh proof first (ASVS 7.5.2).
  async function act(where: Region, path: string, said: string) {
    setBusy(true);
    setMessage(undefined);
    try {
      await api.post(path);
      setMessage({ where, tone: 'success', text: said });
      sessions.reload();
      devices.reload();
    } catch (err) {
      if (ask(err, 'ending a sign-in', () => void act(where, path, said))) return;
      setMessage({ where, tone: 'danger', text: messageOf(err) });
    } finally {
      setBusy(false);
    }
  }

  const alertFor = (where: Region) =>
    message?.where === where ? (
      <Alert tone={message.tone} dynamic title={message.tone === 'danger' ? 'That did not work' : 'Done'}>
        {message.text}
      </Alert>
    ) : null;

  const state = sessions.state;
  if (state.status !== 'ready') {
    return (
      <Page width="narrow" {...(state.status === 'loading' ? { 'aria-busy': true } : {})}>
        <PageHeader title="Sessions" description={DESCRIPTION} />
        {state.status === 'loading' ? (
          <RowsSkeleton rows={2} leading />
        ) : (
          <LoadFailed what="Your sign-ins" message={state.status === 'failed' ? state.message : 'The server refused.'} onRetry={sessions.retry} />
        )}
      </Page>
    );
  }

  const others = state.data.filter((session) => !session.current).length;
  const trusted = devices.state.status === 'ready' ? devices.state.data : [];

  return (
    <Page width="narrow">
      <PageHeader title="Sessions" description={DESCRIPTION} />

      <Section
        title="Signed in"
        description={others > 0 ? `Here, and in ${others === 1 ? 'one other place' : `${others} other places`}.` : 'Only here.'}
        {...(others > 0
          ? {
              actions: (
                <Button size="sm" disabled={busy} onClick={() => void act('sessions', '/api/account/sessions/revoke-others', 'Every other sign-in was ended.')}>
                  Sign out everywhere else
                </Button>
              ),
            }
          : {})}
      >
        {alertFor('sessions')}
        <DataList aria-label="Signed in">
          {state.data.map((session) => (
            <DataListRow
              key={session.id}
              leading={icon(Laptop, 20)}
              title={<span title={session.userAgent ?? undefined}>{describeDevice(session.userAgent)}</span>}
              description={`${describeAddress(session.ip)} · last seen ${when(session.lastSeenAt)}`}
              {...(session.current ? { meta: <Badge size="sm">This one</Badge> } : {})}
              {...(session.current
                ? {}
                : {
                    actions: (
                      <Button
                        size="sm"
                        variant="ghost"
                        disabled={busy}
                        onClick={() => void act('sessions', `/api/account/sessions/${encodeURIComponent(session.id)}/revoke`, 'That sign-in was ended.')}
                      >
                        Sign out
                      </Button>
                    ),
                  })}
            />
          ))}
        </DataList>
      </Section>

      {trusted.length > 0 ? (
        <Section title="Browsers that skip the second step" description="They ask for your password only, until they expire or you forget them.">
          {alertFor('devices')}
          <DataList aria-label="Browsers that skip the second step">
            {trusted.map((device) => (
              <DataListRow
                key={device.id}
                leading={icon(Laptop, 20)}
                title={<span title={device.userAgent ?? undefined}>{device.current ? 'This browser' : describeDevice(device.userAgent)}</span>}
                description={`Stops ${new Date(device.expiresAt).toLocaleDateString(undefined, { dateStyle: 'medium' })}`}
                actions={
                  <Button
                    size="sm"
                    variant="ghost"
                    disabled={busy}
                    onClick={() => void act('devices', `/api/account/devices/${encodeURIComponent(device.id)}/revoke`, 'That browser will be asked again.')}
                  >
                    Forget
                  </Button>
                }
              />
            ))}
          </DataList>
        </Section>
      ) : (
        alertFor('devices')
      )}

      {prompt}
    </Page>
  );
}
