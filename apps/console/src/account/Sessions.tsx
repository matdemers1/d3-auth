import { Alert, Badge, Button, Card, PageHeader, Skeleton } from '@d3cloud/ui';
import { useEffect, useState } from 'react';
import { api } from '../api';
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

const when = (iso: string): string => new Date(iso).toLocaleString();

export function Sessions() {
  const [sessions, setSessions] = useState<SessionRow[] | undefined>();
  const [devices, setDevices] = useState<DeviceRow[]>([]);
  const [message, setMessage] = useState<string | undefined>();
  const [busy, setBusy] = useState(false);

  const load = () => {
    api
      .get<{ sessions: SessionRow[] }>('/api/account/sessions')
      .then((answer) => {
        setSessions(answer.sessions);
      })
      .catch(() => {
        setMessage('We could not load your sign-ins.');
      });
    api
      .get<{ devices: DeviceRow[] }>('/api/account/devices')
      .then((answer) => {
        setDevices(answer.devices);
      })
      .catch(() => {
        setDevices([]);
      });
  };

  useEffect(load, []);

  async function act(path: string, said: string) {
    setBusy(true);
    setMessage(undefined);
    try {
      await api.post(path);
      setMessage(said);
      load();
    } catch {
      setMessage('That did not work. Try again.');
    } finally {
      setBusy(false);
    }
  }

  const others = (sessions ?? []).filter((session) => !session.current).length;

  return (
    <main className="shell">
      <PageHeader title="Sessions and devices" description="Everywhere you are signed in, and what you have chosen to trust." />

      {message ? (
        <Alert tone="info" dynamic title="Sessions">
          {message}
        </Alert>
      ) : null}

      {!sessions ? (
        <Skeleton height="10rem" />
      ) : (
        <Card padding="lg">
          <h2 className="section-title">Signed in</h2>
          <ul className="rows">
            {sessions.map((session) => (
              <li key={session.id} className="row">
                <div>
                  <strong title={session.userAgent ?? undefined}>{describeDevice(session.userAgent)}</strong>
                  <div className="muted">
                    {describeAddress(session.ip)} · last seen {when(session.lastSeenAt)}
                  </div>
                </div>
                <div className="row-meta">
                  {session.current ? <Badge tone="neutral">this one</Badge> : null}
                  {session.current ? null : (
                    <Button
                      variant="danger-ghost"
                      size="sm"
                      disabled={busy}
                      onClick={() => void act(`/api/account/sessions/${encodeURIComponent(session.id)}/revoke`, 'That sign-in was ended.')}
                    >
                      Sign out
                    </Button>
                  )}
                </div>
              </li>
            ))}
          </ul>
          {others > 0 ? (
            <Button
              variant="secondary"
              disabled={busy}
              onClick={() => void act('/api/account/sessions/revoke-others', 'Every other sign-in was ended.')}
            >
              Sign out everywhere else
            </Button>
          ) : null}
        </Card>
      )}

      {devices.length > 0 ? (
        <Card padding="lg">
          <h2 className="section-title">Browsers that skip the second step</h2>
          <ul className="rows">
            {devices.map((device) => (
              <li key={device.id} className="row">
                <div>
                  <strong title={device.userAgent ?? undefined}>
                    {device.current ? 'This browser' : describeDevice(device.userAgent)}
                  </strong>
                  <div className="muted">stops {new Date(device.expiresAt).toLocaleDateString()}</div>
                </div>
                <Button
                  variant="danger-ghost"
                  size="sm"
                  disabled={busy}
                  onClick={() => void act(`/api/account/devices/${encodeURIComponent(device.id)}/revoke`, 'That browser will be asked again.')}
                >
                  Forget
                </Button>
              </li>
            ))}
          </ul>
        </Card>
      ) : null}
    </main>
  );
}
