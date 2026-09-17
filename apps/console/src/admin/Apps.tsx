import { Badge, Button, Card, DataList, DataListRow, EmptyState, Page, PageHeader } from '@d3cloud/ui';
import { AppWindow, Plus } from 'lucide-react';
import { api, type App } from '../api';
import { icon } from '../shared/icons';
import { useLoad } from '../shared/load';
import { useMe } from '../shared/me';
import { Denied, LoadFailed, RowsSkeleton } from '../shared/states';

// C-4: the apps people can sign in to (List page pattern). Owner-only, because registering an app
// decides who can ask for tokens at all — a different kind of power from managing the people who
// already have accounts.

const DESCRIPTION = 'Everything that can ask this system who somebody is.';

export const clientTypeLabel = (type: App['clientType']): string =>
  type === 'public_native' ? 'Native app, PKCE with no secret' : 'Web app with a client secret';

function register(label = 'Add an app') {
  return (
    <Button
      variant="primary"
      icon={icon(Plus)}
      onClick={() => {
        window.location.assign('/admin/apps/new');
      }}
    >
      {label}
    </Button>
  );
}

export function Apps() {
  const me = useMe();
  const { state, retry } = useLoad(() => api.get<{ apps: App[] }>('/api/admin/apps').then((answer) => answer.apps));

  if (state.status === 'loading') {
    return (
      <Page aria-busy="true">
        <PageHeader title="Apps" description={DESCRIPTION} actions={register()} />
        <RowsSkeleton rows={3} leading />
      </Page>
    );
  }
  if (state.status === 'denied') {
    return (
      <Page>
        <PageHeader title="Apps" description={DESCRIPTION} />
        <Denied heading="Apps are the owner’s to manage">
          You can invite people and give them access to apps, but only {me?.operatorDisplayName ?? 'the owner'} registers them.
        </Denied>
      </Page>
    );
  }
  if (state.status === 'failed') {
    return (
      <Page>
        <PageHeader title="Apps" description={DESCRIPTION} />
        <LoadFailed what="The apps" message={state.message} onRetry={retry} />
      </Page>
    );
  }

  const apps = state.data;
  if (apps.length === 0) {
    return (
      <Page>
        <PageHeader title="Apps" count={0} countNoun={{ one: 'app', other: 'apps' }} description={DESCRIPTION} />
        <Card>
          <EmptyState kind="empty" headingLevel={2} heading="No apps yet" icon={icon(AppWindow, 24)} action={register()}>
            Pick an app D3 Auth already knows, like Immich, or describe your own with a manifest. Then give people access to it.
          </EmptyState>
        </Card>
      </Page>
    );
  }

  return (
    <Page>
      <PageHeader title="Apps" count={apps.length} countNoun={{ one: 'app', other: 'apps' }} description={DESCRIPTION} actions={register()} />
      <Card>
        <DataList aria-label="Apps">
          {apps.map((app) => (
            <DataListRow
              key={app.id}
              href={`/admin/apps/${encodeURIComponent(app.clientId)}`}
              leading={icon(AppWindow, 20)}
              title={app.name}
              description={`${app.clientId} · ${clientTypeLabel(app.clientType)}`}
              meta={
                <>
                  {app.enabled ? null : (
                    <Badge size="sm" tone="danger">
                      Disabled
                    </Badge>
                  )}
                  {/* Without a back-channel endpoint, revoking access waits for tokens to expire. */}
                  {app.backchannelLogoutUri ? null : (
                    <Badge size="sm" tone="attention">
                      Slow revoke
                    </Badge>
                  )}
                  <span>
                    {app.people === 1 ? '1 person' : `${app.people} people`} · {app.roles.length === 1 ? '1 role' : `${app.roles.length} roles`}
                  </span>
                </>
              }
            />
          ))}
        </DataList>
      </Card>
    </Page>
  );
}
