import {
  Alert,
  Badge,
  Button,
  CodeInput,
  DataList,
  DataListRow,
  EmptyState,
  FormActions,
  FormField,
  Page,
  PageHeader,
  Section,
  Stack,
} from '@d3cloud/ui';
import { KeyRound, Laptop, Smartphone } from 'lucide-react';
import { useState } from 'react';
import { api, ApiError } from '../api';
import { Confirm } from '../shared/Confirm';
import { icon } from '../shared/icons';
import { messageOf, useLoad } from '../shared/load';
import { useStepUp } from '../shared/StepUp';
import { FactsSkeleton, LoadFailed, RowsSkeleton } from '../shared/states';
import { describeDevice } from './device-name';

// A-4: how you sign in. A passkey is the good path and leads; an authenticator app is the fallback
// for anyone whose device cannot do one.

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

type Region = 'page' | 'passkeys' | 'totp' | 'devices';

const day = (iso: string | null): string => (iso ? new Date(iso).toLocaleDateString(undefined, { dateStyle: 'medium' }) : 'not yet');

const DESCRIPTION = 'Passkeys and authenticator apps on your account, and the browsers you have told to stop asking.';

export function Security() {
  const factors = useLoad(() => api.get<Factors>('/api/account/factors'));
  // The factor list is the point of this screen; a missing device list is not worth an alarm.
  const devices = useLoad(() => api.get<{ devices: TrustedDevice[] }>('/api/account/devices').then((answer) => answer.devices));
  const { ask, prompt } = useStepUp();
  const [message, setMessage] = useState<{ where: Region; tone: 'danger' | 'success'; text: string } | undefined>();
  const [busy, setBusy] = useState(false);
  const [enrolment, setEnrolment] = useState<Enrolment | undefined>();
  const [qr, setQr] = useState<string | undefined>();
  const [code, setCode] = useState('');
  // After a factor changes, offer to end every other sign-in (ASVS 7.4.3): if the change was made
  // because something was lost or suspected, the other sessions are exactly what to worry about.
  const [offerSignOutOthers, setOfferSignOutOthers] = useState(false);

  const load = () => {
    factors.reload();
    devices.reload();
  };

  // Adding or removing a factor asks for fresh proof (ASVS 7.5.1): a borrowed session must not be
  // able to plant a passkey that outlasts a password change.
  async function addPasskey() {
    setBusy(true);
    setMessage(undefined);
    try {
      const { startRegistration } = await import('@simplewebauthn/browser');
      const options = await api.post<Parameters<typeof startRegistration>[0]['optionsJSON']>('/api/account/passkeys/begin');
      const response = await startRegistration({ optionsJSON: options });
      await api.post('/api/account/passkeys/finish', { response, label: 'Passkey' });
      setMessage({ where: 'passkeys', tone: 'success', text: 'Passkey added. You can use it to sign in from now on.' });
      setOfferSignOutOthers(true);
      load();
    } catch (err) {
      if (ask(err, 'adding a passkey', () => void addPasskey())) return;
      if (err instanceof ApiError) setMessage({ where: 'passkeys', tone: 'danger', text: err.message });
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
      if (ask(err, 'adding an authenticator app', () => void startTotp())) return;
      setMessage({ where: 'totp', tone: 'danger', text: 'That could not start. Try again.' });
    } finally {
      setBusy(false);
    }
  }

  async function confirmTotp(event: React.SyntheticEvent) {
    event.preventDefault();
    if (!enrolment) return;
    setBusy(true);
    try {
      await api.post('/api/account/totp/confirm', { credentialId: enrolment.credentialId, code });
      setEnrolment(undefined);
      setQr(undefined);
      setCode('');
      setMessage({ where: 'totp', tone: 'success', text: 'Authenticator app added.' });
      setOfferSignOutOthers(true);
      load();
    } catch (err) {
      if (ask(err, 'adding an authenticator app', () => undefined)) return;
      setMessage({ where: 'totp', tone: 'danger', text: err instanceof ApiError ? err.message : 'That code did not match.' });
    } finally {
      setBusy(false);
    }
  }

  async function forgetDevice(id: string) {
    setMessage(undefined);
    try {
      await api.post(`/api/account/devices/${encodeURIComponent(id)}/revoke`);
      setMessage({ where: 'devices', tone: 'success', text: 'That browser will be asked for a passkey or code again.' });
      load();
    } catch {
      setMessage({ where: 'devices', tone: 'danger', text: 'That did not work. Try again.' });
    }
  }

  async function signOutOthers() {
    setBusy(true);
    try {
      const answer = await api.post<{ revoked?: number }>('/api/account/sessions/revoke-others');
      setOfferSignOutOthers(false);
      setMessage({
        where: 'page',
        tone: 'success',
        text: answer.revoked ? `Signed out of ${String(answer.revoked)} other sign-in${answer.revoked === 1 ? '' : 's'}.` : 'You were not signed in anywhere else.',
      });
    } catch (err) {
      if (ask(err, 'ending your other sign-ins', () => void signOutOthers())) return;
      setMessage({ where: 'page', tone: 'danger', text: 'That did not work. Try again.' });
    } finally {
      setBusy(false);
    }
  }

  /** Runs from inside the confirmation, so a step-up closes it and takes over. */
  async function remove(kind: 'passkeys' | 'totp', id: string) {
    setMessage(undefined);
    try {
      await api.post(`/api/account/${kind}/${encodeURIComponent(id)}/remove`);
      setOfferSignOutOthers(true);
      load();
    } catch (err) {
      const retry = () => {
        remove(kind, id).catch((again: unknown) => {
          setMessage({ where: kind === 'passkeys' ? 'passkeys' : 'totp', tone: 'danger', text: messageOf(again) });
        });
      };
      if (ask(err, kind === 'passkeys' ? 'removing a passkey' : 'removing an authenticator app', retry)) return;
      throw err;
    }
  }

  const alertFor = (where: Region) =>
    message?.where === where ? (
      <Alert tone={message.tone} dynamic title={message.tone === 'danger' ? 'That did not work' : 'Done'}>
        {message.text}
      </Alert>
    ) : null;

  const state = factors.state;
  if (state.status !== 'ready') {
    return (
      <Page width="narrow" {...(state.status === 'loading' ? { 'aria-busy': true } : {})}>
        <PageHeader title="Security" description={DESCRIPTION} />
        {state.status === 'loading' ? (
          <>
            <FactsSkeleton title="Passkeys" rows={1} />
            <RowsSkeleton rows={1} />
          </>
        ) : (
          <LoadFailed what="Your security settings" message={state.status === 'failed' ? state.message : 'The server refused.'} onRetry={factors.retry} />
        )}
      </Page>
    );
  }

  const { passkeys, totp, factorRequired } = state.data;
  const trusted = devices.state.status === 'ready' ? devices.state.data : [];

  return (
    <Page width="narrow">
      <PageHeader title="Security" description={DESCRIPTION} />

      {alertFor('page')}
      {offerSignOutOthers ? (
        <Alert
          tone="info"
          dynamic
          title="Sign out everywhere else?"
          actions={
            <>
              <Button
                size="sm"
                disabled={busy}
                onClick={() => {
                  setOfferSignOutOthers(false);
                }}
              >
                Not now
              </Button>
              <Button size="sm" loading={busy} onClick={() => void signOutOthers()}>
                Sign out everywhere else
              </Button>
            </>
          }
        >
          If you made this change because a device was lost or you suspect someone else, end every other sign-in too.
        </Alert>
      ) : null}

      <Section
        title="Passkeys"
        description={
          factorRequired
            ? 'Your phone or laptop proves it is you — nothing to remember, nothing to phish. Your account manages other people, so once it has a passkey or an authenticator app it cannot remove the last one.'
            : 'Your phone or laptop proves it is you — nothing to remember, nothing to phish.'
        }
        actions={
          <Button size="sm" variant="primary" loading={busy} onClick={() => void addPasskey()}>
            Add a passkey
          </Button>
        }
      >
        {alertFor('passkeys')}
        <DataList
          aria-label="Passkeys"
          empty={
            <EmptyState kind="empty" size="inline" headingLevel={3} heading="Your account is protected by a password only">
              Add a passkey, and signing in asks for your phone or laptop as well as your password.
            </EmptyState>
          }
        >
          {passkeys.map((passkey) => (
            <DataListRow
              key={passkey.id}
              leading={icon(KeyRound, 20)}
              title={passkey.label}
              description={`Added ${day(passkey.createdAt)} · last used ${day(passkey.lastUsedAt)}`}
              {...(passkey.backedUp ? { meta: <Badge size="sm">Synced</Badge> } : {})}
              actions={
                <Confirm
                  trigger={
                    <Button size="sm" variant="danger-ghost">
                      Remove
                    </Button>
                  }
                  title={`Remove ${passkey.label}?`}
                  description="It stops working for this account at once. To use it again you would add it again from this page."
                  confirm="Remove passkey"
                  cancel="Keep it"
                  onConfirm={() => remove('passkeys', passkey.id)}
                />
              }
            />
          ))}
        </DataList>
      </Section>

      <Section title="Authenticator app" description="A six-digit code from an app on your phone, for devices that cannot do passkeys.">
        {alertFor('totp')}
        {totp.length > 0 ? (
          <DataList aria-label="Authenticator apps">
            {totp.map((credential) => (
              <DataListRow
                key={credential.id}
                leading={icon(Smartphone, 20)}
                title={credential.label}
                actions={
                  <Confirm
                    trigger={
                      <Button size="sm" variant="danger-ghost">
                        Remove
                      </Button>
                    }
                    title={`Remove ${credential.label}?`}
                    description="Its codes stop working for this account at once. To use the app again you would scan a new code."
                    confirm="Remove authenticator app"
                    cancel="Keep it"
                    onConfirm={() => remove('totp', credential.id)}
                  />
                }
              />
            ))}
          </DataList>
        ) : null}

        {enrolment ? (
          <Stack as="form" gap="16" aria-label="Add an authenticator app" onSubmit={(event) => void confirmTotp(event)}>
            <p>Scan this with your authenticator app, then type the code it shows.</p>
            {/* The one local class: a QR code has to be dark on white to scan (styles.css). */}
            {qr ? <img className="qr" src={qr} alt="QR code for your authenticator app" width={220} height={220} /> : null}
            <p>
              Cannot scan it? Enter this key by hand: <code>{enrolment.manualKey}</code>
            </p>
            <FormField label="Code from the app" help="Six digits. It changes every 30 seconds.">
              <CodeInput name="code" autoComplete="one-time-code" required value={code} onValueChange={setCode} />
            </FormField>
            <FormActions>
              <Button
                disabled={busy}
                onClick={() => {
                  setEnrolment(undefined);
                  setQr(undefined);
                  setCode('');
                }}
              >
                Cancel
              </Button>
              <Button type="submit" loading={busy}>
                Confirm the code
              </Button>
            </FormActions>
          </Stack>
        ) : (
          <FormActions align="start">
            <Button loading={busy} onClick={() => void startTotp()}>
              Add an authenticator app
            </Button>
          </FormActions>
        )}
      </Section>

      {trusted.length > 0 ? (
        <Section title="Browsers that skip the second step" description="They ask for your password only, until they expire or you forget them here.">
          {alertFor('devices')}
          <DataList aria-label="Browsers that skip the second step">
            {trusted.map((device) => (
              <DataListRow
                key={device.id}
                leading={icon(Laptop, 20)}
                title={<span title={device.userAgent ?? undefined}>{device.current ? 'This browser' : describeDevice(device.userAgent)}</span>}
                description={`Trusted ${day(device.createdAt)} · stops ${day(device.expiresAt)}`}
                actions={
                  <Button size="sm" variant="ghost" onClick={() => void forgetDevice(device.id)}>
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
