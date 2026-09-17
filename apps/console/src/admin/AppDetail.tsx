import {
  Alert,
  Badge,
  Button,
  DataList,
  DataListRow,
  DescriptionItem,
  DescriptionList,
  EmptyState,
  FormActions,
  FormField,
  Link,
  Page,
  PageHeader,
  Section,
  Stack,
  Textarea,
} from '@d3cloud/ui';
import { ArrowLeft } from 'lucide-react';
import { useEffect, useState } from 'react';
import { api, ApiError, type AccessRow, type App, type ManifestDiff } from '../api';
import { Confirm } from '../shared/Confirm';
import { icon } from '../shared/icons';
import { messageOf, useLoad } from '../shared/load';
import { useMe } from '../shared/me';
import { Denied, FactsSkeleton, LoadFailed, RowsSkeleton } from '../shared/states';
import { clientTypeLabel } from './Apps';

// C-5: one app — what it is, who can reach it, its manifest, and the buttons that stop it
// (Detail page pattern).

const day = (iso: string | null): string => (iso ? new Date(iso).toLocaleDateString(undefined, { dateStyle: 'medium' }) : 'never');

/** The manifest this app would produce, so re-pasting starts from what is actually registered. */
const manifestOf = (app: App): string =>
  JSON.stringify(
    {
      client_id: app.clientId,
      name: app.name,
      ...(app.description ? { description: app.description } : {}),
      client_type: app.clientType,
      redirect_uris: app.redirectUris,
      post_logout_redirect_uris: app.postLogoutRedirectUris,
      ...(app.backchannelLogoutUri ? { backchannel_logout_uri: app.backchannelLogoutUri } : {}),
      roles: app.roles.map((role) => ({
        key: role.key,
        display: role.displayName,
        ...(role.description ? { description: role.description } : {}),
        ...(role.isDefault ? { default: true } : {}),
      })),
    },
    null,
    2,
  );

type Region = 'page' | 'access' | 'manifest';
type Feedback = { where: Region; tone: 'danger' | 'success'; title: string; text: string };

function Back() {
  return (
    <Link variant="muted" href="/admin/apps">
      {icon(ArrowLeft, 14)}
      Apps
    </Link>
  );
}

function UriList({ uris, none }: { uris: string[]; none: string }) {
  if (uris.length === 0) return <>{none}</>;
  return (
    <Stack gap="4">
      {uris.map((uri) => (
        <code key={uri}>{uri}</code>
      ))}
    </Stack>
  );
}

export function AppDetail({ clientId }: { clientId: string }) {
  const me = useMe();
  const base = `/api/admin/apps/${encodeURIComponent(clientId)}`;
  const app = useLoad(() => api.get<App>(base), clientId);
  const access = useLoad(() => api.get<{ access: AccessRow[] }>(`${base}/access`).then((answer) => answer.access), clientId);
  const [feedback, setFeedback] = useState<Feedback | undefined>();
  const [secret, setSecret] = useState<string | undefined>();
  const [manifest, setManifest] = useState('');
  const [blocking, setBlocking] = useState<ManifestDiff['blocking']>([]);
  const [busy, setBusy] = useState(false);

  const loaded = app.state.status === 'ready' ? app.state.data : undefined;
  useEffect(() => {
    if (loaded) setManifest(manifestOf(loaded));
  }, [loaded]);

  const reload = () => {
    app.reload();
    access.reload();
  };

  /** Runs one change and says what happened at the top of the Section it concerns. */
  async function act(where: Region, path: string, body: unknown, said: { title: string; text: string }) {
    setBusy(true);
    setFeedback(undefined);
    try {
      await api.post(path, body);
      setBlocking([]);
      setFeedback({ where, tone: 'success', ...said });
      reload();
    } catch (err) {
      if (err instanceof ApiError && err.body.error === 'roles_in_use') {
        // Removing a role somebody holds takes their access with it: that is a confirmation.
        setBlocking((err.body.detail as ManifestDiff['blocking'] | undefined) ?? []);
        return;
      }
      setFeedback({ where, tone: 'danger', title: 'That did not work', text: messageOf(err) });
    } finally {
      setBusy(false);
    }
  }

  const alertFor = (where: Region) =>
    feedback?.where === where ? (
      <Alert tone={feedback.tone} dynamic title={feedback.title}>
        {feedback.text}
      </Alert>
    ) : null;

  const state = app.state;
  if (state.status !== 'ready') {
    return (
      <Page width="narrow" {...(state.status === 'loading' ? { 'aria-busy': true } : {})}>
        <PageHeader back={<Back />} title="App" />
        {state.status === 'loading' ? (
          <>
            <FactsSkeleton title="How it signs people in" rows={4} />
            <RowsSkeleton rows={2} />
          </>
        ) : state.status === 'denied' ? (
          <Denied heading="Apps are the owner’s to manage">
            You can give people access to apps from their page in People, but only {me?.operatorDisplayName ?? 'the owner'} changes an app.
          </Denied>
        ) : (
          <LoadFailed what="This app" message={state.message} onRetry={app.retry} />
        )}
      </Page>
    );
  }

  const view = state.data;
  const rows = access.state.status === 'ready' ? access.state.data : [];

  return (
    <Page width="narrow">
      <PageHeader
        back={<Back />}
        title={view.name}
        description={
          <>
            {clientTypeLabel(view.clientType)}
            {view.enabled ? null : (
              <>
                {' '}
                <Badge size="sm" tone="danger">
                  Disabled
                </Badge>
              </>
            )}
          </>
        }
      />

      {alertFor('page')}
      {secret ? (
        <Alert tone="warning" dynamic title="This is the only time the new secret is shown">
          <p>Copy it into the app now. The old one stopped working the moment this appeared.</p>
          <code>{secret}</code>
        </Alert>
      ) : null}

      <Section title="How it signs people in">
        <DescriptionList>
          <DescriptionItem term="Client ID">
            <code>{view.clientId}</code>
          </DescriptionItem>
          <DescriptionItem term="Type">{clientTypeLabel(view.clientType)}</DescriptionItem>
          <DescriptionItem term="Returns to">
            <UriList uris={view.redirectUris} none="Nowhere yet" />
          </DescriptionItem>
          <DescriptionItem term="After sign-out">
            <UriList uris={view.postLogoutRedirectUris} none="The provider’s own signed-out page" />
          </DescriptionItem>
          <DescriptionItem term="Sign-out notice">
            {view.backchannelLogoutUri ? (
              <code>{view.backchannelLogoutUri}</code>
            ) : (
              <>
                <Badge size="sm" tone="attention">
                  Slow revoke
                </Badge>{' '}
                No endpoint — revoking access here takes effect when its tokens expire.
              </>
            )}
          </DescriptionItem>
          <DescriptionItem term="Registered" numeric>
            {day(view.createdAt)}
          </DescriptionItem>
        </DescriptionList>
      </Section>

      <Section title="Roles" description="Declared in the manifest. An app sees only its own roles in a token.">
        <DataList
          aria-label="Roles"
          empty={
            <EmptyState kind="empty" size="inline" headingLevel={3} heading="No roles">
              This app declares none. People either have access or they do not.
            </EmptyState>
          }
        >
          {view.roles.map((role) => (
            <DataListRow
              key={role.key}
              title={role.displayName}
              description={
                <>
                  <code>{role.key}</code>
                  {role.description ? ` · ${role.description}` : ''}
                </>
              }
              meta={
                <>
                  {role.isDefault ? <Badge size="sm">Suggested</Badge> : null}
                  <span>{role.granted === 1 ? '1 person' : `${role.granted} people`}</span>
                </>
              }
            />
          ))}
        </DataList>
      </Section>

      <Section title="Who can sign in" description="Revoking signs them out of this app now, if it has a sign-out notice endpoint.">
        {alertFor('access')}
        <DataList
          aria-label="Who can sign in"
          empty={
            <EmptyState kind="empty" size="inline" headingLevel={3} heading="Nobody yet">
              Give somebody access from their page in People.
            </EmptyState>
          }
        >
          {rows.map((row) => (
            <DataListRow
              key={row.userId}
              title={<Link href={`/admin/people/${encodeURIComponent(row.userId)}`}>{row.displayName}</Link>}
              description={`${row.email} · ${row.roles.length > 0 ? row.roles.join(', ') : 'no roles'}`}
              meta={<span>Signed in {day(row.lastSignIn)}</span>}
              actions={
                <Button
                  size="sm"
                  variant="ghost"
                  disabled={busy}
                  onClick={() =>
                    void act('access', `/api/admin/people/${row.userId}/access/revoke`, { clientId }, {
                      title: 'Access revoked',
                      text: `${row.displayName} has been signed out of ${view.name}.`,
                    })
                  }
                >
                  Revoke
                </Button>
              }
            />
          ))}
        </DataList>
      </Section>

      <Section title="Manifest" description="Paste a new one to change the app. The client ID cannot change.">
        {alertFor('manifest')}
        <Stack
          as="form"
          gap="16"
          aria-label="Manifest"
          onSubmit={(event) => {
            event.preventDefault();
            void act('manifest', `${base}/manifest`, { manifest }, { title: 'Manifest applied', text: 'The change is live now.' });
          }}
        >
          <FormField label="This app’s manifest" help="JSON. Removing a role somebody holds asks first.">
            <Textarea
              name="manifest"
              rows={14}
              spellCheck={false}
              value={manifest}
              onChange={(event) => {
                setManifest(event.target.value);
              }}
            />
          </FormField>
          <FormActions>
            <Button type="submit" loading={busy}>
              Apply manifest
            </Button>
          </FormActions>
        </Stack>
      </Section>

      <Confirm
        open={blocking.length > 0}
        onOpenChange={(open) => {
          if (!open) setBlocking([]);
        }}
        title="Remove roles people hold?"
        description={`${blocking
          .map((role) => `${role.key} (${String(role.granted ?? 0)} ${role.granted === 1 ? 'person' : 'people'})`)
          .join(', ')} would go, and the access they carry goes with them. Those people are signed out of ${view.name}. This cannot be undone.`}
        confirm="Remove roles and their access"
        cancel="Keep the roles"
        onConfirm={async () => {
          await api.post(`${base}/manifest`, { manifest, confirmRoleRemoval: true });
          setFeedback({ where: 'manifest', tone: 'success', title: 'Manifest applied', text: 'The roles were removed, and the access they carried with them.' });
          reload();
        }}
      />

      <Section title="Disable or rotate">
        <DataList aria-label="Disable or rotate">
          {view.clientType === 'confidential_web' ? (
            <DataListRow
              truncate={false}
              title="Rotate the client secret"
              description="Makes a new secret and stops the old one at once. The app cannot sign anyone in until it has the new one."
              actions={
                <Confirm
                  trigger={
                    <Button size="sm" variant="danger-ghost" disabled={busy}>
                      Rotate secret
                    </Button>
                  }
                  title={`Rotate ${view.name}’s secret?`}
                  description={`The current secret stops working now, and sign-in to ${view.name} fails until the new one is in its configuration. The new secret is shown once. This cannot be undone.`}
                  confirm="Rotate secret"
                  cancel="Keep the current secret"
                  onConfirm={async () => {
                    const answer = await api.post<{ secret: string }>(`${base}/secret`);
                    setSecret(answer.secret);
                  }}
                />
              }
            />
          ) : null}
          {view.enabled ? (
            <DataListRow
              truncate={false}
              title="Disable sign-in"
              description="Nobody can sign in to it until you turn it back on. Its tokens are revoked now."
              actions={
                <Confirm
                  trigger={
                    <Button size="sm" variant="danger-ghost" disabled={busy}>
                      Disable {view.name}
                    </Button>
                  }
                  title={`Disable ${view.name}?`}
                  description={`Everyone signed in to ${view.name} is signed out, its tokens are revoked, and nobody can sign in until you enable it again. Access and roles are kept.`}
                  confirm={`Disable ${view.name}`}
                  cancel={`Keep ${view.name} on`}
                  onConfirm={async () => {
                    await api.post(`${base}/enabled`, { enabled: false });
                    setFeedback({ where: 'page', tone: 'success', title: 'App disabled', text: 'Its tokens were revoked and nobody can sign in to it.' });
                    reload();
                  }}
                />
              }
            />
          ) : (
            <DataListRow
              truncate={false}
              title="Enable sign-in"
              description="People with access can sign in again."
              actions={
                <Button
                  size="sm"
                  disabled={busy}
                  onClick={() =>
                    void act('page', `${base}/enabled`, { enabled: true }, { title: 'App enabled', text: 'People with access can sign in again.' })
                  }
                >
                  Enable {view.name}
                </Button>
              }
            />
          )}
        </DataList>
      </Section>
    </Page>
  );
}
