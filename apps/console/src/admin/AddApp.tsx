import { Card, CardTitle, Grid, Link, Page, PageHeader, Section, Skeleton } from '@d3cloud/ui';
import { ArrowLeft } from 'lucide-react';
import { api, type PresetSummary } from '../api';
import { icon } from '../shared/icons';
import { useLoad } from '../shared/load';
import { useMe } from '../shared/me';
import { Denied, LoadFailed } from '../shared/states';

// C-6, the first step: which app is this? An app D3 Auth already knows gets a short form and a
// paste sheet in its own words; anything else is described by its manifest, as before.
//
// The list of known apps comes from the server's preset registry, so this page cannot offer an app
// the server does not know how to register.

const TITLE = 'Add an app';
const DESCRIPTION = 'Pick the app if it is listed. Otherwise describe your own with a manifest.';

function Back() {
  return (
    <Link variant="muted" href="/admin/apps">
      {icon(ArrowLeft, 14)}
      Apps
    </Link>
  );
}

function Choice({ href, name, summary }: { href: string; name: string; summary: string }) {
  return (
    <Card interactive href={href} padding="md">
      <CardTitle>{name}</CardTitle>
      <span className="sheet-why">{summary}</span>
    </Card>
  );
}

export function AddApp() {
  const me = useMe();
  const { state, retry } = useLoad(() => api.get<{ presets: PresetSummary[] }>('/api/admin/app-presets').then((answer) => answer.presets));

  const own = (
    <Section surface="plain" title="Your own app" description="Anything that speaks OpenID Connect. You paste its manifest: its redirect URIs and the roles it understands.">
      <Grid minItemWidth="sm">
        <Choice href="/admin/apps/new/manifest" name="Register from a manifest" summary="For an app you build or configure yourself" />
      </Grid>
    </Section>
  );

  if (state.status === 'denied') {
    return (
      <Page width="narrow">
        <PageHeader back={<Back />} title={TITLE} />
        <Denied heading="Apps are the owner’s to manage">
          You can give people access to apps from their page in People, but only {me?.operatorDisplayName ?? 'the owner'} adds an app.
        </Denied>
      </Page>
    );
  }

  return (
    <Page width="narrow" {...(state.status === 'loading' ? { 'aria-busy': true } : {})}>
      <PageHeader back={<Back />} title={TITLE} description={DESCRIPTION} />

      {state.status === 'failed' ? (
        <LoadFailed what="The list of known apps" message={state.message} onRetry={retry} />
      ) : (
        <Section surface="plain" title="Apps D3 Auth knows" description="Give the app’s address and D3 Auth registers it, then shows what to paste into the app’s own settings.">
          {state.status === 'loading' ? (
            <Grid minItemWidth="sm" aria-hidden="true">
              <Skeleton variant="block" height="4.5rem" />
            </Grid>
          ) : (
            <Grid minItemWidth="sm">
              {state.data.map((preset) => (
                <Choice key={preset.key} href={`/admin/apps/new/${encodeURIComponent(preset.key)}`} name={preset.name} summary={preset.summary} />
              ))}
            </Grid>
          )}
        </Section>
      )}

      {own}
    </Page>
  );
}
