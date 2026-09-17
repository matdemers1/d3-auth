import { Link, Page, PageHeader } from '@d3cloud/ui';
import { ArrowLeft } from 'lucide-react';
import { api, type App, type Connection } from '../api';
import { icon } from '../shared/icons';
import { useLoad } from '../shared/load';
import { useMe } from '../shared/me';
import { Denied, FactsSkeleton, LoadFailed } from '../shared/states';
import { ConnectionSection, PresetSheetSection } from './connection';

// C-6 again, later: the paste sheet for an app a preset built, for the day its settings need
// checking or re-entering. The same sheet the registered screen showed, without the secret — that
// was shown once, and rotating it on the app's page is how to see a new one.

export function AppConnect({ clientId }: { clientId: string }) {
  const me = useMe();
  const base = `/api/admin/apps/${encodeURIComponent(clientId)}`;
  const { state, retry } = useLoad(() => Promise.all([api.get<App>(base), api.get<Connection>(`${base}/connection`)]), clientId);

  const back = (name: string) => (
    <Link variant="muted" href={`/admin/apps/${encodeURIComponent(clientId)}`}>
      {icon(ArrowLeft, 14)}
      {name}
    </Link>
  );

  if (state.status !== 'ready') {
    return (
      <Page width="narrow" {...(state.status === 'loading' ? { 'aria-busy': true } : {})}>
        <PageHeader back={back('App')} title="Connect this app" />
        {state.status === 'loading' ? (
          <FactsSkeleton title="Connection details" rows={6} />
        ) : state.status === 'denied' ? (
          <Denied heading="Apps are the owner’s to manage">
            Only {me?.operatorDisplayName ?? 'the owner'} can see how an app is connected.
          </Denied>
        ) : (
          <LoadFailed what="How to connect this app" message={state.message} onRetry={retry} />
        )}
      </Page>
    );
  }

  const [app, connection] = state.data;
  return (
    <Page width="narrow">
      <PageHeader
        back={back(app.name)}
        title={`Connect ${app.name}`}
        description={
          connection.preset
            ? `What goes in ${app.name}’s own settings. The client secret is not shown again; rotate it on ${app.name}’s page to get a new one.`
            : 'What the app needs. The client secret is not shown again; rotate it on the app’s page to get a new one.'
        }
      />
      {connection.preset ? <PresetSheetSection sheet={connection.preset} /> : null}
      <ConnectionSection
        connection={connection}
        {...(connection.preset ? { description: `The same values in D3 Auth’s words, for when ${app.name} asks for one differently.` } : {})}
      />
    </Page>
  );
}
