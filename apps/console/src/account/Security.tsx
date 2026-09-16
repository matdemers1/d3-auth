import { Alert, Badge, Button, Card, EmptyState, FormField, Input, PageHeader, Skeleton } from '@d3cloud/ui';
import { useEffect, useState } from 'react';
import { api, ApiError } from '../api';
import { StepUp } from '../admin/StepUp';
import { describeDevice } from './device-name';

// A-4: how you sign in. A passkey is the good path and leads; an authenticator app is the
// fallback for anyone whose device cannot do one.

interface Passkey {
  id: string;
  label: string;
  createdAt: string;
  lastUsedAt: string | null;
  backedUp: boolean;
}

interface TotpCredential {
  id: string;
  label: string;
}

interface Factors {
  passkeys: Passkey[];
  totp: TotpCredential[];
  factorRequired: boolean;
}

interface TrustedDevice {
  id: string;
  userAgent: string | null;
  createdAt: string;
  expiresAt: string;
  current: boolean;
}

interface Enrolment {
  credentialId: string;
  uri: string;
  manualKey: string;
}

const when = (iso: string | null): string => (iso ? new Date(iso).toLocaleDateString() : 'not yet');

export function Security() {
  const [factors, setFactors] = useState<Factors | undefined>();
  const [devices, setDevices] = useState<TrustedDevice[]>([]);
  const [message, setMessage] = useState<{ tone: 'danger' | 'success'; text: string } | undefined>();
  const [busy, setBusy] = useState(false);
  const [enrolment, setEnrolment] = useState<Enrolment | undefined>();
  const [qr, setQr] = useState<string | undefined>();
  const [code, setCode] = useState('');
  // Adding or removing a factor asks for fresh proof (ASVS 7.5.1): a borrowed session must not be
  // able to plant a passkey that outlasts a password change.
  const [pending, setPending] = useState<{ describe: string; retry: () => void } | undefined>();
  const askFirst = (err: unknown, describe: string, retry: () => void): boolean => {
    if (err instanceof ApiError && err.body.error === 'step_up_required') {
      setPending({ describe, retry });
      return true;
    }
    return false;
  };

  const load = () => {
    api
      .get<Factors>('/api/account/factors')
      .then(setFactors)
      .catch(() => {
        setMessage({ tone: 'danger', text: 'We could not load your security settings.' });
      });
    api
      .get<{ devices: TrustedDevice[] }>('/api/account/devices')
      .then((answer) => {
        setDevices(answer.devices);
      })
      .catch(() => {
        // The factor list is the point of this screen; a missing device list is not worth an alarm.
        setDevices([]);
      });
  };

  useEffect(load, []);

  async function addPasskey() {
    setBusy(true);
    setMessage(undefined);
    try {
      const { startRegistration } = await import('@simplewebauthn/browser');
      const options = await api.post<Parameters<typeof startRegistration>[0]['optionsJSON']>('/api/account/passkeys/begin');
      const response = await startRegistration({ optionsJSON: options });
      await api.post('/api/account/passkeys/finish', { response, label: 'Passkey' });
      setMessage({ tone: 'success', text: 'Passkey added. You can use it to sign in from now on.' });
      load();
    } catch (err) {
      if (askFirst(err, 'adding a passkey', () => void addPasskey())) return;
      if (err instanceof ApiError) setMessage({ tone: 'danger', text: err.message });
      // A cancelled prompt is a choice, not a failure.
    } finally {
      setBusy(false);
    }
  }

  async function startTotp() {
    setBusy(true);
    setMessage(undefined);
    try {
      const started = await api.post<Enrolment>('/api/account/totp/begin');
      setEnrolment(started);
      const { toDataURL } = await import('qrcode');
      setQr(await toDataURL(started.uri, { margin: 1, width: 220 }));
    } catch (err) {
      if (askFirst(err, 'adding an authenticator app', () => void startTotp())) return;
      setMessage({ tone: 'danger', text: 'We could not start that. Try again.' });
    } finally {
      setBusy(false);
    }
  }

  async function confirmTotp(event: React.SyntheticEvent<HTMLFormElement, SubmitEvent>) {
    event.preventDefault();
    if (!enrolment) return;
    setBusy(true);
    try {
      await api.post('/api/account/totp/confirm', { credentialId: enrolment.credentialId, code });
      setEnrolment(undefined);
      setQr(undefined);
      setCode('');
      setMessage({ tone: 'success', text: 'Authenticator app added.' });
      load();
    } catch (err) {
      if (askFirst(err, 'adding an authenticator app', () => undefined)) return;
      setMessage({ tone: 'danger', text: err instanceof ApiError ? err.message : 'That code did not match.' });
    } finally {
      setBusy(false);
    }
  }

  async function forgetDevice(id: string) {
    setMessage(undefined);
    try {
      await api.post(`/api/account/devices/${encodeURIComponent(id)}/revoke`);
      setMessage({ tone: 'success', text: 'That browser will be asked for a passkey or code again.' });
      load();
    } catch {
      setMessage({ tone: 'danger', text: 'That did not work.' });
    }
  }

  async function remove(kind: 'passkeys' | 'totp', id: string) {
    setMessage(undefined);
    try {
      await api.post(`/api/account/${kind}/${encodeURIComponent(id)}/remove`);
      load();
    } catch (err) {
      if (askFirst(err, kind === 'passkeys' ? 'removing a passkey' : 'removing an authenticator app', () => void remove(kind, id))) return;
      setMessage({ tone: 'danger', text: err instanceof ApiError ? err.message : 'That did not work.' });
    }
  }

  return (
    <main className="shell">
      <PageHeader title="How you sign in" description="Passkeys and authenticator apps on your account." />

      {message ? (
        <Alert tone={message.tone} dynamic title={message.tone === 'danger' ? 'That did not work' : 'Done'}>
          {message.text}
        </Alert>
      ) : null}

      {pending ? (
        <StepUp
          action={pending.describe}
          onProved={() => {
            const { retry } = pending;
            setPending(undefined);
            retry();
          }}
          onCancel={() => {
            setPending(undefined);
          }}
        />
      ) : null}

      {!factors ? (
        <Skeleton height="10rem" />
      ) : (
        <>
          <Card padding="lg">
            <h2 className="section-title">Passkeys</h2>
            {factors.passkeys.length === 0 ? (
              <EmptyState kind="empty" size="inline" headingLevel={3} heading="Your account is protected by a password only">
                A passkey uses your phone or laptop to prove it is you — nothing to remember, and nothing to phish.
              </EmptyState>
            ) : (
              <ul className="rows">
                {factors.passkeys.map((passkey) => (
                  <li key={passkey.id} className="row">
                    <div>
                      <strong>{passkey.label}</strong>
                      <div className="muted">
                        added {when(passkey.createdAt)} · last used {when(passkey.lastUsedAt)}
                      </div>
                    </div>
                    <div className="row-meta">
                      {passkey.backedUp ? <Badge tone="neutral">synced</Badge> : null}
                      <Button variant="danger-ghost" size="sm" onClick={() => void remove('passkeys', passkey.id)}>
                        Remove
                      </Button>
                    </div>
                  </li>
                ))}
              </ul>
            )}
            <Button variant="primary" onClick={() => void addPasskey()} loading={busy}>
              Add a passkey
            </Button>
          </Card>

          <Card padding="lg">
            <h2 className="section-title">Authenticator app</h2>
            {factors.totp.length === 0 ? (
              <p className="muted">A six-digit code from an app, for devices that cannot do passkeys.</p>
            ) : (
              <ul className="rows">
                {factors.totp.map((credential) => (
                  <li key={credential.id} className="row">
                    <strong>{credential.label}</strong>
                    <Button variant="danger-ghost" size="sm" onClick={() => void remove('totp', credential.id)}>
                      Remove
                    </Button>
                  </li>
                ))}
              </ul>
            )}

            {enrolment ? (
              <form className="stack" onSubmit={(event) => void confirmTotp(event)}>
                <p className="muted">Scan this with your authenticator app, then type the code it shows.</p>
                {qr ? <img className="qr" src={qr} alt="QR code for your authenticator app" width={220} height={220} /> : null}
                <p className="muted">
                  Cannot scan? Enter this key by hand: <code className="copy-link">{enrolment.manualKey}</code>
                </p>
                <FormField label="Code from the app">
                  <Input
                    name="code"
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    required
                    value={code}
                    onChange={(event) => {
                      setCode(event.target.value);
                    }}
                  />
                </FormField>
                <Button type="submit" variant="primary" loading={busy}>
                  Confirm
                </Button>
              </form>
            ) : (
              <Button variant="secondary" onClick={() => void startTotp()} loading={busy}>
                Add an authenticator app
              </Button>
            )}
          </Card>

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
                      <div className="muted">
                        trusted {when(device.createdAt)} · stops {when(device.expiresAt)}
                      </div>
                    </div>
                    <Button variant="danger-ghost" size="sm" onClick={() => void forgetDevice(device.id)}>
                      Forget
                    </Button>
                  </li>
                ))}
              </ul>
            </Card>
          ) : null}

          {factors.factorRequired ? (
            <Alert tone="info" title="Admins keep at least one factor">
              Your account can manage other people, so it needs a passkey or an authenticator app at all times.
            </Alert>
          ) : null}
        </>
      )}
    </main>
  );
}
