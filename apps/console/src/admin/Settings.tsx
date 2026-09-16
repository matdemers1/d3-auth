import { Alert, Button, Card, FormField, Input, PageHeader, Select, Skeleton } from '@d3cloud/ui';
import { useEffect, useState } from 'react';
import { api, ApiError } from '../api';
import { StepUp } from './StepUp';

// C-10: settings (REQ-071, REQ-109).
//
// The test send is the important control here. Mail either works or it does not, and the only
// way to know is to send one — so this screen reports the driver's own error word for word.
// "Could not send" tells an operator nothing; "relay answered 401" tells them what to fix.

interface SettingsView {
  mail: { driver: 'worker' | 'smtp' | 'log'; from?: string; relayUrl?: string; smtpHost?: string; secretSet: boolean } | null;
  alerts: { recipients: string[] };
  lifetimes: { trustedDeviceDays: number; sessionDays: number };
  fromEnvironment: { mailDriver: string | null; mailConfigured: boolean };
}

export function Settings() {
  const [view, setView] = useState<SettingsView | undefined>();
  const [failed, setFailed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ tone: 'danger' | 'success'; title: string; text: string } | undefined>();
  const [pending, setPending] = useState<{ describe: string; retry: () => void } | undefined>();

  const [driver, setDriver] = useState<'worker' | 'smtp' | 'log'>('log');
  const [from, setFrom] = useState('');
  const [relayUrl, setRelayUrl] = useState('');
  const [secret, setSecret] = useState('');
  const [recipients, setRecipients] = useState('');
  const [trustedDeviceDays, setTrustedDeviceDays] = useState(30);
  const [sessionDays, setSessionDays] = useState(30);

  const load = () => {
    api
      .get<SettingsView>('/api/admin/settings')
      .then((loaded) => {
        setView(loaded);
        setDriver(loaded.mail?.driver ?? 'log');
        setFrom(loaded.mail?.from ?? '');
        setRelayUrl(loaded.mail?.relayUrl ?? '');
        setRecipients(loaded.alerts.recipients.join(', '));
        setTrustedDeviceDays(loaded.lifetimes.trustedDeviceDays);
        setSessionDays(loaded.lifetimes.sessionDays);
      })
      .catch(() => {
        setFailed(true);
      });
  };

  useEffect(load, []);

  async function save(path: string, body: unknown, said: string, describe: string) {
    setBusy(true);
    setMessage(undefined);
    try {
      await api.post(path, body);
      setPending(undefined);
      setMessage({ tone: 'success', title: 'Saved', text: said });
      load();
    } catch (err) {
      if (err instanceof ApiError && err.body.error === 'step_up_required') {
        setPending({ describe, retry: () => void save(path, body, said, describe) });
        return;
      }
      setMessage({ tone: 'danger', title: 'That did not work', text: err instanceof ApiError ? err.message : 'Try again.' });
    } finally {
      setBusy(false);
    }
  }

  async function testSend() {
    setBusy(true);
    setMessage(undefined);
    try {
      const result = await api.post<{ driver: string }>('/api/admin/settings/mail/test');
      setMessage({ tone: 'success', title: 'Sent', text: `Delivered with the ${result.driver} driver. Check the inbox.` });
    } catch (err) {
      // Verbatim, on purpose (REQ-109).
      setMessage({
        tone: 'danger',
        title: 'It did not send',
        text: err instanceof ApiError ? (typeof err.body.error === 'string' ? err.body.error : err.message) : 'No answer from the server.',
      });
    } finally {
      setBusy(false);
    }
  }

  if (failed) {
    return (
      <main className="shell">
        <Alert tone="info" title="Settings are the owner's">
          They decide how this system reaches people and how long it trusts them.
        </Alert>
      </main>
    );
  }
  if (!view) return <Skeleton height="14rem" />;

  return (
    <main className="shell">
      <PageHeader title="Settings" description="How this system sends mail, who it warns, and how long it trusts a browser." />

      {message ? (
        <Alert tone={message.tone} dynamic title={message.title}>
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

      <Card padding="lg">
        <h2 className="section-title">Mail</h2>
        {view.mail === null && view.fromEnvironment.mailDriver ? (
          <p className="muted">
            Configured in the container as <strong>{view.fromEnvironment.mailDriver}</strong>. Saving here overrides that.
          </p>
        ) : null}
        <div className="stack">
          <FormField label="Driver" help="The Worker relay in production; SMTP if you have one; log for development.">
            <Select
              value={driver}
              onValueChange={(value) => {
                setDriver(value as 'worker' | 'smtp' | 'log');
              }}
              options={[
                { value: 'worker', label: 'Cloudflare Worker relay' },
                { value: 'smtp', label: 'SMTP' },
                { value: 'log', label: 'Log only (no mail is sent)' },
              ]}
            />
          </FormField>
          <FormField label="From address">
            <Input
              name="from"
              type="email"
              value={from}
              onChange={(event) => {
                setFrom(event.target.value);
              }}
            />
          </FormField>
          {driver === 'worker' ? (
            <FormField label="Relay URL">
              <Input
                name="relayUrl"
                value={relayUrl}
                onChange={(event) => {
                  setRelayUrl(event.target.value);
                }}
              />
            </FormField>
          ) : null}
          {driver !== 'log' ? (
            <FormField
              label={driver === 'worker' ? 'Relay secret' : 'SMTP URL'}
              help={view.mail?.secretSet ? 'One is stored. Leave blank to keep it.' : 'Stored sealed; it is never shown again.'}
            >
              <Input
                name="secret"
                type="password"
                value={secret}
                onChange={(event) => {
                  setSecret(event.target.value);
                }}
              />
            </FormField>
          ) : null}
          <Button
            variant="primary"
            loading={busy}
            onClick={() =>
              void save(
                '/api/admin/settings/mail',
                {
                  settings: { driver, ...(from ? { from } : {}), ...(relayUrl ? { relayUrl } : {}) },
                  ...(secret ? { secret } : {}),
                },
                'Mail settings saved. Send a test to be sure.',
                'changing how mail is sent',
              )
            }
          >
            Save mail settings
          </Button>
          <Button variant="secondary" disabled={busy} onClick={() => void testSend()}>
            Send a test message to me
          </Button>
        </div>
      </Card>

      <Card padding="lg">
        <h2 className="section-title">Alerts</h2>
        <div className="stack">
          <FormField label="Who to warn" help="Comma-separated. They hear when this system cannot reach something it needs.">
            <Input
              name="recipients"
              value={recipients}
              onChange={(event) => {
                setRecipients(event.target.value);
              }}
            />
          </FormField>
          <Button
            variant="secondary"
            loading={busy}
            onClick={() =>
              void save(
                '/api/admin/settings/alerts',
                { settings: { recipients: recipients.split(',').map((value) => value.trim()).filter(Boolean) } },
                'Alert recipients saved.',
                'changing who gets warned',
              )
            }
          >
            Save recipients
          </Button>
        </div>
      </Card>

      <Card padding="lg">
        <h2 className="section-title">Lifetimes</h2>
        <div className="stack">
          <FormField label="Trust a browser for (days)" help="How long “don’t ask again on this browser” lasts.">
            <Input
              name="trustedDeviceDays"
              type="number"
              min={1}
              max={365}
              value={String(trustedDeviceDays)}
              onChange={(event) => {
                setTrustedDeviceDays(Number(event.target.value));
              }}
            />
          </FormField>
          <FormField
            label="Sign somebody out after this many idle days"
            help="However busy a sign-in is, it ends ninety days after the person last proved who they are."
          >
            <Input
              name="sessionDays"
              type="number"
              min={1}
              max={90}
              value={String(sessionDays)}
              onChange={(event) => {
                setSessionDays(Number(event.target.value));
              }}
            />
          </FormField>
          <Button
            variant="secondary"
            loading={busy}
            onClick={() =>
              void save(
                '/api/admin/settings/lifetimes',
                { settings: { trustedDeviceDays, sessionDays } },
                'Lifetimes saved. They apply to new sessions and newly trusted browsers.',
                'changing how long this system trusts a browser',
              )
            }
          >
            Save lifetimes
          </Button>
        </div>
      </Card>
    </main>
  );
}
