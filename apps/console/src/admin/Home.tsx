import {
  Badge,
  DataList,
  DataListRow,
  DescriptionItem,
  DescriptionList,
  EmptyState,
  Grid,
  Link,
  Page,
  PageHeader,
  Section,
  Skeleton,
} from '@d3cloud/ui';
import { Circle, CircleCheck } from 'lucide-react';
import { api } from '../api';
import { icon } from '../shared/icons';
import { useLoad } from '../shared/load';
import { useMe } from '../shared/me';
import { Denied, LoadFailed, RowsSkeleton } from '../shared/states';

// C-0: the console's front page (REQ-073), as a dashboard: what needs someone, then counts and
// what happened lately.
//
// Each tile says what is true and what to do rather than just "OK": "never tested" is more useful
// than a green tick that means nothing, and "invites are not arriving" is what an operator actually
// needs to hear when a mail test failed last week. Healthy tiles are quiet; only a tile that needs
// someone gets a badge and a link to the fix.

interface Tile {
  key: 'database' | 'keys' | 'mail' | 'migrations' | 'backups';
  ok: boolean;
  detail: string;
}

interface Overview {
  tiles: Tile[];
  counts: { people: number; apps: number; groups: number; signInsToday: number };
  recent: { id: string; at: string; event: string; actor: { displayName: string } | null; targetType?: string | null; targetId: string | null }[];
  checklist: { key: string; done: boolean; label: string; href: string }[] | null;
}

const TILE: Record<Tile['key'], { title: string; badge: string; tone: 'danger' | 'attention'; fix?: { href: string; label: string; ownerOnly: boolean } }> = {
  database: { title: 'Database', badge: 'Not answering', tone: 'danger' },
  migrations: { title: 'Schema', badge: 'Behind this build', tone: 'danger' },
  mail: { title: 'Mail', badge: 'Needs you', tone: 'attention', fix: { href: '/admin/settings', label: 'Check the mail settings', ownerOnly: true } },
  keys: { title: 'Signing keys', badge: 'Needs you', tone: 'attention', fix: { href: '/admin/keys', label: 'Open the keys', ownerOnly: true } },
  backups: { title: 'Backups', badge: 'Needs you', tone: 'attention' },
};

const when = (iso: string): string => new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });

function Header() {
  return <PageHeader title="Home" description="How this instance is doing, and what needs you." />;
}

export function Home() {
  const me = useMe();
  const { state, retry } = useLoad(() => api.get<Overview>('/api/admin/overview'));

  if (state.status === 'loading') {
    return (
      <Page aria-busy="true">
        <Header />
        <Section surface="plain" title="Status" description="Anything that needs you comes first.">
          <Grid minItemWidth="md" aria-hidden="true">
            {[0, 1, 2, 3, 4].map((i) => (
              <Skeleton key={i} variant="block" height="6.5rem" />
            ))}
          </Grid>
        </Section>
        <Grid minItemWidth="lg">
          <RowsSkeleton rows={4} />
          <RowsSkeleton rows={4} />
        </Grid>
      </Page>
    );
  }
  if (state.status === 'denied') {
    return (
      <Page>
        <Header />
        <Denied heading="The console is for admins">
          Your account signs in to apps, but it does not manage this instance. {me?.operatorDisplayName ?? 'The owner'} can make you an
          admin if you need to be one. <Link variant="inline" href="/account">Go to your account</Link>.
        </Denied>
      </Page>
    );
  }
  if (state.status === 'failed') {
    return (
      <Page>
        <Header />
        <LoadFailed what="Home" message={state.message} onRetry={retry} />
      </Page>
    );
  }

  const view = state.data;
  const owner = me?.kind === 'owner';
  // What needs someone first; the order within each group is the server's.
  const tiles = [...view.tiles.filter((tile) => !tile.ok), ...view.tiles.filter((tile) => tile.ok)];

  return (
    <Page>
      <Header />

      {view.checklist ? (
        <Section title="Getting started" description="A fresh instance is empty, not broken. These make it useful.">
          <DataList aria-label="Getting started">
            {view.checklist.map((step) => (
              <DataListRow
                key={step.key}
                leading={icon(step.done ? CircleCheck : Circle, 20)}
                title={step.done ? step.label : <Link href={step.href}>{step.label}</Link>}
                meta={step.done ? <span>Done</span> : <Badge size="sm" tone="attention">To do</Badge>}
              />
            ))}
          </DataList>
        </Section>
      ) : null}

      <Section surface="plain" title="Status" description="Anything that needs you comes first.">
        <Grid minItemWidth="md">
          {tiles.map((tile) => {
            const about = TILE[tile.key];
            const fix = !tile.ok && about.fix && (!about.fix.ownerOnly || owner) ? about.fix : undefined;
            return (
              <Section
                key={tile.key}
                headingLevel={3}
                title={
                  tile.ok ? (
                    about.title
                  ) : (
                    <>
                      {about.title}{' '}
                      <Badge size="sm" tone={about.tone}>
                        {about.badge}
                      </Badge>
                    </>
                  )
                }
                description={tile.detail}
              >
                {fix ? <Link href={fix.href}>{fix.label}</Link> : null}
              </Section>
            );
          })}
        </Grid>
      </Section>

      <Grid minItemWidth="lg">
        <Section title="Counts">
          <DescriptionList>
            <DescriptionItem term={<Link href="/admin/people">People</Link>} numeric>
              {view.counts.people}
            </DescriptionItem>
            <DescriptionItem term={owner ? <Link href="/admin/apps">Apps</Link> : 'Apps'} numeric>
              {view.counts.apps}
            </DescriptionItem>
            <DescriptionItem term={<Link href="/admin/groups">Groups</Link>} numeric>
              {view.counts.groups}
            </DescriptionItem>
            <DescriptionItem term="Sign-ins today" numeric>
              {view.counts.signInsToday}
            </DescriptionItem>
          </DescriptionList>
        </Section>

        <Section title="Recent activity" actions={<Link href="/admin/audit">Audit trail</Link>}>
          <DataList
            aria-label="Recent activity"
            empty={
              <EmptyState kind="empty" size="inline" headingLevel={3} heading="Nothing has happened yet">
                Sign-ins and changes show here as they happen.
              </EmptyState>
            }
          >
            {/* A glance, not the record: the audit page has the rest. */}
            {view.recent.slice(0, 6).map((row) => (
              <DataListRow
                key={row.id}
                title={<code>{row.event}</code>}
                description={row.actor ? row.actor.displayName : 'The system'}
                meta={<span>{when(row.at)}</span>}
              />
            ))}
          </DataList>
        </Section>
      </Grid>
    </Page>
  );
}
