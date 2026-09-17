import { Alert, Button, FormActions, FormField, Input, Page, PageHeader, PasswordInput, Section, Select, Stack } from '@d3cloud/ui';
import { useState } from 'react';
import { api, ApiError } from '../api';
import { messageOf, useLoad } from '../shared/load';
import { useMe } from '../shared/me';
import { useStepUp } from '../shared/StepUp';
import { Denied, FactsSkeleton, LoadFailed } from '../shared/states';

// C-10: settings (REQ-071, REQ-109), as a settings page: one Section per concern, each its own form
// with its own save, and the result where the button was pressed.
//
// The test send is the important control here. Mail either works or it does not, and the only way
// to know is to send one — so this screen reports the driver's own error word for word. "Could not
// send" tells an operator nothing; "relay answered 401" tells them what to fix.

interface SettingsView {
  mail: { driver: 'worker' | 'smtp' | 'log'; from?: string; relayUrl?: string; smtpHost?: string; secretSet: boolean } | null;
  alerts: { recipients: string[] };
  lifetimes: { trustedDeviceDays: number; sessionDays: number };
  fromEnvironment: { mailDriver: string | null; mailConfigured: boolean };
}

type Concern = 'mail' | 'alerts' | 'lifetimes';
type Result = { where: Concern; tone: 'success' | 'danger'; title: string; text: string };

const DESCRIPTION = 'How this system sends mail, who it warns, and how long it trusts a browser.';

function ResultAlert({ result, where }: { result: Result | undefined; where: Concern }) {
  if (result?.where !== where) return null;
  return (
    <Alert tone={result.tone} dynamic title={result.title}>
      {result.text}
    </Alert>
  );
}

function Loaded({ view, reload }: { view: SettingsView; reload: () => void }) {
  const { ask, prompt } = useStepUp();
  const [busy, setBusy] = useState<Concern | undefined>();
  const [result, setResult] = useState<Result | undefined>();

  const [driver, setDriver] = useState<'worker' | 'smtp' | 'log'>(view.mail?.driver ?? 'log');
  const [from, setFrom] = useState(view.mail?.from ?? '');
  const [relayUrl, setRelayUrl] = useState(view.mail?.relayUrl ?? '');
  const [secret, setSecret] = useState('');
  const [recipients, setRecipients] = useState(view.alerts.recipients.join(', '));
  const [trustedDeviceDays, setTrustedDeviceDays] = useState(view.lifetimes.trustedDeviceDays);
  const [sessionDays, setSessionDays] = useState(view.lifetimes.sessionDays);

  async function save(where: Concern, path: string, body: unknown, said: string, describe: string) {
    setBusy(where);
    setResult(undefined);
    try {
      await api.post(path, body);
      setResult({ where, tone: 'success', title: 'Saved', text: said });
      if (where === 'mail') setSecret('');
      reload();
    } catch (err) {
      if (ask(err, describe, () => void save(where, path, body, said, describe))) return;
      setResult({ where, tone: 'danger', title: 'Not saved', text: `${messageOf(err)} Nothing else on this page was affected.` });
    } finally {
      setBusy(undefined);
    }
  }

  async function testSend() {
    setBusy('mail');
    setResult(undefined);
    try {
      const sent = await api.post<{ driver: string }>('/api/admin/settings/mail/test');
      setResult({ where: 'mail', tone: 'success', title: 'Sent', text: `Delivered with the ${sent.driver} driver. Check the inbox.` });
    } catch (err) {
      // Verbatim, on purpose (REQ-109).
      setResult({
        where: 'mail',
        tone: 'danger',
        title: 'It did not send',
        text: err instanceof ApiError ? (typeof err.body.error === 'string' ? err.body.error : err.message) : 'No answer from the server.',
      });
    } finally {
      setBusy(undefined);
    }
  }

  return (
    <>
      <Section
        title="Mail"
        description={
          view.mail === null && view.fromEnvironment.mailDriver
            ? `Invites, resets and alerts go out this way. Set in the container as ${view.fromEnvironment.mailDriver}; saving here overrides that.`
            : 'Invites, resets and alerts go out this way.'
        }
      >
        <ResultAlert result={result} where="mail" />
        <Stack
          as="form"
          gap="16"
          aria-label="Mail"
          onSubmit={(event) => {
            event.preventDefault();
            void save(
              'mail',
              '/api/admin/settings/mail',
              { settings: { driver, ...(from ? { from } : {}), ...(relayUrl ? { relayUrl } : {}) }, ...(secret ? { secret } : {}) },
              'Mail settings saved. Send a test to be sure they work.',
              'changing how mail is sent',
            );
          }}
        >
          <FormField label="Driver" help="The Worker relay in production; SMTP if you have a mail server; log while developing.">
            <Select
              value={driver}
              onValueChange={(value) => {
                setDriver(value as 'worker' | 'smtp' | 'log');
              }}
              options={[
                { value: 'worker', label: 'Cloudflare Worker relay' },
                { value: 'smtp', label: 'SMTP server' },
                { value: 'log', label: 'Log only — nothing is sent' },
              ]}
            />
          </FormField>
          <FormField label="From address" width="lg" optional>
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
            <FormField label="Relay URL" optional>
              <Input
                name="relayUrl"
                type="url"
                spellCheck={false}
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
              optional
              help={view.mail?.secretSet ? 'One is stored. Leave this blank to keep it — it is never shown again.' : 'Stored sealed; it is never shown again.'}
            >
              <PasswordInput
                name="secret"
                autoComplete="new-password"
                value={secret}
                onChange={(event) => {
                  setSecret(event.target.value);
                }}
              />
            </FormField>
          ) : null}
          <FormActions>
            <Button disabled={busy !== undefined} onClick={() => void testSend()}>
              Send a test message to me
            </Button>
            <Button type="submit" loading={busy === 'mail'} disabled={busy !== undefined && busy !== 'mail'}>
              Save mail settings
            </Button>
          </FormActions>
        </Stack>
      </Section>

      <Section title="Alerts" description="Who hears about it when this system cannot reach something it needs.">
        <ResultAlert result={result} where="alerts" />
        <Stack
          as="form"
          gap="16"
          aria-label="Alerts"
          onSubmit={(event) => {
            event.preventDefault();
            void save(
              'alerts',
              '/api/admin/settings/alerts',
              { settings: { recipients: recipients.split(',').map((value) => value.trim()).filter(Boolean) } },
              'Alert recipients saved.',
              'changing who gets warned',
            );
          }}
        >
          <FormField label="Who to warn" help="Email addresses, separated by commas.">
            <Input
              name="recipients"
              value={recipients}
              onChange={(event) => {
                setRecipients(event.target.value);
              }}
            />
          </FormField>
          <FormActions>
            <Button type="submit" loading={busy === 'alerts'} disabled={busy !== undefined && busy !== 'alerts'}>
              Save recipients
            </Button>
          </FormActions>
        </Stack>
      </Section>

      <Section title="Lifetimes" description="How long this system trusts a browser before it asks again.">
        <ResultAlert result={result} where="lifetimes" />
        <Stack
          as="form"
          gap="16"
          aria-label="Lifetimes"
          onSubmit={(event) => {
            event.preventDefault();
            void save(
              'lifetimes',
              '/api/admin/settings/lifetimes',
              { settings: { trustedDeviceDays, sessionDays } },
              'Lifetimes saved. They apply to new sign-ins and newly trusted browsers.',
              'changing how long this system trusts a browser',
            );
          }}
        >
          <FormField label="Trust a browser for" width="xs" help="How long “don’t ask again on this browser” lasts. 1 to 365 days.">
            <Input
              name="trustedDeviceDays"
              type="number"
              inputMode="numeric"
              min={1}
              max={365}
              trailing="days"
              value={String(trustedDeviceDays)}
              onChange={(event) => {
                setTrustedDeviceDays(Number(event.target.value));
              }}
            />
          </FormField>
          <FormField
            label="Sign someone out after"
            width="xs"
            help="Days with no activity, 1 to 90. However busy a sign-in is, it ends ninety days after they last proved who they are."
          >
            <Input
              name="sessionDays"
              type="number"
              inputMode="numeric"
              min={1}
              max={90}
              trailing="days"
              value={String(sessionDays)}
              onChange={(event) => {
                setSessionDays(Number(event.target.value));
              }}
            />
          </FormField>
          <FormActions>
            <Button type="submit" loading={busy === 'lifetimes'} disabled={busy !== undefined && busy !== 'lifetimes'}>
              Save lifetimes
            </Button>
          </FormActions>
        </Stack>
      </Section>

      {prompt}
    </>
  );
}

export function Settings() {
  const me = useMe();
  const { state, reload, retry } = useLoad(() => api.get<SettingsView>('/api/admin/settings'));

  return (
    <Page width="narrow" {...(state.status === 'loading' ? { 'aria-busy': true } : {})}>
      <PageHeader title="Settings" description={DESCRIPTION} />
      {state.status === 'loading' ? (
        <>
          <FactsSkeleton title="Mail" rows={3} />
          <FactsSkeleton title="Alerts" rows={1} />
          <FactsSkeleton title="Lifetimes" rows={2} />
        </>
      ) : state.status === 'denied' ? (
        <Denied heading="Settings are the owner’s">
          They decide how this system reaches people and how long it trusts them. Ask {me?.operatorDisplayName ?? 'the owner'} if one needs changing.
        </Denied>
      ) : state.status === 'failed' ? (
        <LoadFailed what="Settings" message={state.message} onRetry={retry} />
      ) : (
        <Loaded view={state.data} reload={reload} />
      )}
    </Page>
  );
}
