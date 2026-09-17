import {
  Alert,
  Badge,
  Button,
  DataList,
  DataListRow,
  DescriptionItem,
  DescriptionList,
  EmptyState,
  Link,
  Page,
  PageHeader,
  Section,
} from '@d3cloud/ui';
import { ArrowLeft, Laptop } from 'lucide-react';
import { useState } from 'react';
import { api, type App, type PersonDetail as Person } from '../api';
import { describeAddress, describeDevice } from '../account/device-name';
import { icon } from '../shared/icons';
import { messageOf, useLoad } from '../shared/load';
import { KIND_LABEL, useMe } from '../shared/me';
import { Denied, FactsSkeleton, LoadFailed, RowsSkeleton } from '../shared/states';
import { AccessList } from './access';
import { changeKind, ConfirmReset, firstName, reactivate, suspend, type ResetResult, ResetOutcome } from './person-actions';

// C-2: one person — who they are, what they can reach, where they are signed in, and the two
// things that stop them (Detail page pattern).

const day = (iso: string | null): string => (iso ? new Date(iso).toLocaleDateString(undefined, { dateStyle: 'long' }) : 'Never');
const plural = (n: number, one: string, many: string): string => `${n} ${n === 1 ? one : many}`;

type Region = 'profile' | 'access' | 'danger';
type Feedback = { where: Region; tone: 'success' | 'danger'; text: string } | { where: 'danger'; tone: 'reset'; result: ResetResult };

function Back() {
  return (
    <Link variant="muted" href="/admin/people">
      {icon(ArrowLeft, 14)}
      People
    </Link>
  );
}

function FeedbackAlert({ feedback, where }: { feedback: Feedback | undefined; where: Region }) {
  if (feedback?.where !== where) return null;
  if (feedback.tone === 'reset') return <ResetOutcome result={feedback.result} />;
  return (
    <Alert tone={feedback.tone} dynamic title={feedback.tone === 'danger' ? 'That did not work' : 'Done'}>
      {feedback.text}
    </Alert>
  );
}

export function PersonDetail({ id }: { id: string }) {
  const me = useMe();
  const person = useLoad(() => api.get<Person>(`/api/admin/people/${encodeURIComponent(id)}`), id);
  // Only the owner can list apps; an admin still sees the access this person has.
  const apps = useLoad(() => api.get<{ apps: App[] }>('/api/admin/apps').then((answer) => answer.apps.filter((app) => app.enabled)), id);
  const [feedback, setFeedback] = useState<Feedback | undefined>();
  const [busy, setBusy] = useState(false);

  function act(where: Region, run: () => Promise<unknown>, said: string) {
    setBusy(true);
    setFeedback(undefined);
    run()
      .then(() => {
        setFeedback({ where, tone: 'success', text: said });
        person.reload();
      })
      .catch((err: unknown) => {
        setFeedback({ where, tone: 'danger', text: messageOf(err) });
      })
      .finally(() => {
        setBusy(false);
      });
  }

  const state = person.state;
  if (state.status !== 'ready') {
    return (
      <Page width="narrow" {...(state.status === 'loading' ? { 'aria-busy': true } : {})}>
        <PageHeader back={<Back />} title="Person" />
        {state.status === 'loading' ? (
          <>
            <FactsSkeleton title="Profile" rows={6} />
            <RowsSkeleton rows={2} />
          </>
        ) : state.status === 'denied' ? (
          <Denied heading="Managing people is for admins">
            Your account can sign in to apps, but not see or change anyone else’s. {me?.operatorDisplayName ?? 'The owner'} can make you an admin.
          </Denied>
        ) : (
          <LoadFailed what="This person" message={state.message} onRetry={person.retry} />
        )}
      </Page>
    );
  }

  const who = state.data;
  const base = `/api/admin/people/${encodeURIComponent(who.id)}`;
  const locked = who.kind === 'owner' || who.id === me?.id;
  const factors = [
    who.factors.passkeys > 0 ? plural(who.factors.passkeys, 'passkey', 'passkeys') : null,
    who.factors.authenticatorApps > 0 ? plural(who.factors.authenticatorApps, 'authenticator app', 'authenticator apps') : null,
  ].filter(Boolean);

  return (
    <Page width="narrow">
      <PageHeader back={<Back />} title={who.displayName} description={`${KIND_LABEL[who.kind]} · ${who.email}`} />

      <Section
        title="Profile"
        {...(me?.kind === 'owner' && !locked
          ? {
              actions: (
                <Button
                  size="sm"
                  disabled={busy}
                  onClick={() => {
                    act('profile', () => changeKind(who), who.kind === 'admin' ? `${who.displayName} is a guest again.` : `${who.displayName} is an admin.`);
                  }}
                >
                  {who.kind === 'admin' ? 'Make a guest' : 'Make an admin'}
                </Button>
              ),
            }
          : {})}
      >
        <FeedbackAlert feedback={feedback} where="profile" />
        <DescriptionList>
          <DescriptionItem term="Username">
            <code>{who.username}</code>
          </DescriptionItem>
          <DescriptionItem term="Email">{who.email}</DescriptionItem>
          <DescriptionItem term="Role">
            <Badge size="sm">{KIND_LABEL[who.kind]}</Badge>
          </DescriptionItem>
          <DescriptionItem term="Status">
            {who.status === 'suspended' ? (
              <Badge size="sm" tone="danger">
                Suspended
              </Badge>
            ) : who.status === 'invited' ? (
              'Invited, not set up yet'
            ) : (
              'Active'
            )}
          </DescriptionItem>
          <DescriptionItem term="Signs in with">
            {factors.length === 0 ? 'A password only' : `A password, and ${factors.join(' and ')}`}
            {who.factors.trustedDevices > 0 ? ` · ${plural(who.factors.trustedDevices, 'trusted browser', 'trusted browsers')}` : ''}
          </DescriptionItem>
          <DescriptionItem term="Last signed in" numeric>
            {day(who.lastLoginAt)}
          </DescriptionItem>
          <DescriptionItem term="Joined" numeric>
            {day(who.createdAt)}
          </DescriptionItem>
        </DescriptionList>
      </Section>

      <Section title="App access" description="Removing access signs them out of that app. Groups can add more; they never take away.">
        <FeedbackAlert feedback={feedback} where="access" />
        <AccessList
          label="App access"
          apps={apps.state.status === 'ready' ? apps.state.data : []}
          grants={who.access}
          busy={busy}
          onGrant={(app, roles, said) => {
            act('access', () => api.post(`${base}/access`, { clientId: app.clientId, roles }), said);
          }}
          onRevoke={(app) => {
            act('access', () => api.post(`${base}/access/revoke`, { clientId: app.clientId }), `Access to ${app.name} revoked.`);
          }}
          say={{ role: (role, on) => (on ? `${role} removed.` : `${role} given.`), given: (app) => `Access to ${app} given.` }}
          emptyHeading="No access yet"
          emptyText={`${firstName(who)} cannot sign in to anything until they are given access to an app.`}
        />
      </Section>

      <Section title="Signed in now" description={plural(who.sessions.length, 'session', 'sessions')}>
        <DataList
          aria-label="Signed in now"
          empty={
            <EmptyState kind="empty" size="inline" headingLevel={3} heading="Not signed in anywhere">
              Their next sign-in will show here.
            </EmptyState>
          }
        >
          {who.sessions.map((session) => (
            <DataListRow
              key={session.id}
              leading={icon(Laptop, 20)}
              title={<span title={session.userAgent ?? undefined}>{describeDevice(session.userAgent)}</span>}
              description={describeAddress(session.ip)}
              meta={<span>Last seen {new Date(session.lastSeenAt).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })}</span>}
            />
          ))}
        </DataList>
      </Section>

      {locked ? null : (
        <Section title="Suspend or reset">
          <FeedbackAlert feedback={feedback} where="danger" />
          <DataList aria-label="Suspend or reset">
            {who.status === 'suspended' ? (
              <DataListRow
                truncate={false}
                title="Let them back in"
                description="They can sign in again, to the same apps as before."
                actions={
                  <Button
                    size="sm"
                    disabled={busy}
                    onClick={() => {
                      act('danger', () => reactivate(who), `${who.displayName} can sign in again.`);
                    }}
                  >
                    Let {firstName(who)} back in
                  </Button>
                }
              />
            ) : (
              <DataListRow
                truncate={false}
                title="Suspend"
                description="Signs them out everywhere and stops every sign-in until you let them back in. Nothing is deleted."
                actions={
                  <Button
                    size="sm"
                    disabled={busy}
                    onClick={() => {
                      act('danger', () => suspend(who), `${who.displayName} is suspended and signed out everywhere.`);
                    }}
                  >
                    Suspend {firstName(who)}
                  </Button>
                }
              />
            )}
            <DataListRow
              truncate={false}
              title="Reset their account"
              description="Removes their password and every factor. They set it up again from an emailed link — for a lost phone."
              actions={
                <ConfirmReset
                  person={who}
                  trigger={
                    <Button size="sm" variant="danger-ghost" disabled={busy}>
                      Reset account
                    </Button>
                  }
                  onDone={(result) => {
                    setFeedback({ where: 'danger', tone: 'reset', result });
                    person.reload();
                  }}
                />
              }
            />
          </DataList>
        </Section>
      )}
    </Page>
  );
}
