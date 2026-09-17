import {
  Alert,
  Avatar,
  Badge,
  Button,
  Card,
  DataList,
  DataListRow,
  EmptyState,
  FilterBar,
  FormField,
  IconButton,
  Input,
  Link,
  Menu,
  MenuContent,
  MenuItem,
  MenuTrigger,
  Modal,
  Page,
  PageHeader,
  Section,
  Stack,
} from '@d3cloud/ui';
import { Ellipsis, Mail, Search, UserPlus } from 'lucide-react';
import { useId, useState } from 'react';
import { api, type InviteCreated, type PendingInvite, type Person } from '../api';
import { icon } from '../shared/icons';
import { messageOf, useLoad } from '../shared/load';
import { useMe } from '../shared/me';
import { Denied, LoadFailed, RowsSkeleton } from '../shared/states';
import { changeKind, ConfirmReset, reactivate, suspend, type ResetResult, ResetOutcome } from './person-actions';

// C-1 and C-3: who can sign in, and how somebody new gets added (List page pattern).

interface Directory {
  people: Person[];
  pendingInvites: PendingInvite[];
}

const lastSeen = (iso: string | null): string =>
  iso ? `Signed in ${new Date(iso).toLocaleDateString(undefined, { dateStyle: 'medium' })}` : 'Never signed in';

type Outcome =
  | { kind: 'done'; text: string }
  | { kind: 'failed'; text: string }
  | { kind: 'invited'; invite: InviteCreated }
  | { kind: 'reset'; result: ResetResult };

function Header({ count, onInvite }: { count?: number; onInvite?: () => void }) {
  return (
    <PageHeader
      title="People"
      {...(count === undefined ? {} : { count })}
      description="Everyone who can sign in, and the invites you have sent."
      {...(onInvite
        ? {
            actions: (
              <Button variant="primary" icon={icon(UserPlus)} onClick={onInvite}>
                Invite someone
              </Button>
            ),
          }
        : {})}
    />
  );
}

/** C-3 as a Modal: one field, opened by the page's primary action (Forms pattern). */
function InviteModal({ open, onOpenChange, onInvited }: { open: boolean; onOpenChange: (open: boolean) => void; onInvited: (invite: InviteCreated) => void }) {
  const formId = useId();
  const [email, setEmail] = useState('');
  const [problem, setProblem] = useState<string | undefined>();
  const [busy, setBusy] = useState(false);

  async function invite(event: React.SyntheticEvent) {
    event.preventDefault();
    setBusy(true);
    setProblem(undefined);
    try {
      const created = await api.post<InviteCreated>('/api/admin/invites', { email });
      setEmail('');
      onOpenChange(false);
      onInvited(created);
    } catch (err) {
      setProblem(messageOf(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      open={open}
      onOpenChange={(next) => {
        if (!next) setProblem(undefined);
        onOpenChange(next);
      }}
      title="Invite someone"
      description="They get an email with a link that works once, and choose their own username and password. It expires in three days."
      footer={
        <>
          <Button
            disabled={busy}
            onClick={() => {
              onOpenChange(false);
            }}
          >
            Cancel
          </Button>
          <Button type="submit" form={formId} variant="primary" loading={busy}>
            Send invite
          </Button>
        </>
      }
    >
      <Stack as="form" id={formId} gap="16" aria-label="Invite someone" onSubmit={(event) => void invite(event)}>
        {problem ? (
          <Alert tone="danger" dynamic title="The invite was not sent">
            {problem}
          </Alert>
        ) : null}
        <FormField label="Their email address">
          <Input
            name="email"
            type="email"
            autoComplete="off"
            required
            autoFocus
            value={email}
            onChange={(event) => {
              setEmail(event.target.value);
            }}
          />
        </FormField>
      </Stack>
    </Modal>
  );
}

function OutcomeAlert({ outcome }: { outcome: Outcome }) {
  switch (outcome.kind) {
    case 'done':
      return (
        <Alert tone="success" dynamic title="Done">
          {outcome.text}
        </Alert>
      );
    case 'failed':
      return (
        <Alert tone="danger" dynamic title="That did not work">
          {outcome.text}
        </Alert>
      );
    case 'reset':
      return <ResetOutcome result={outcome.result} />;
    case 'invited':
      return outcome.invite.mail.delivered ? (
        <Alert tone="success" dynamic title={`Invite sent to ${outcome.invite.email}`}>
          It expires in three days. They will need a minute to pick a username and a password.
        </Alert>
      ) : (
        <Alert tone="warning" dynamic title={`The invite for ${outcome.invite.email} was saved, but the email did not send`}>
          <p>Send them this link yourself. It works once and expires in three days.</p>
          <code>{outcome.invite.url}</code>
        </Alert>
      );
  }
}

function PersonRow({
  person,
  me,
  busy,
  onAct,
  onReset,
}: {
  person: Person;
  me: ReturnType<typeof useMe>;
  busy: boolean;
  onAct: (run: () => Promise<unknown>, said: string) => void;
  onReset: (person: Person) => void;
}) {
  // The owner's row and your own hold no actions the server would refuse. The slot stays empty.
  const locked = person.kind === 'owner' || person.id === me?.id;
  return (
    <DataListRow
      leading={<Avatar name={person.displayName} size="sm" decorative />}
      title={<Link href={`/admin/people/${encodeURIComponent(person.id)}`}>{person.displayName}</Link>}
      description={`@${person.username} · ${person.email}`}
      meta={
        <>
          {person.status === 'suspended' ? (
            <Badge size="sm" tone="danger">
              Suspended
            </Badge>
          ) : person.status === 'invited' ? (
            <Badge size="sm">Invited</Badge>
          ) : null}
          {person.kind === 'guest' ? null : <Badge size="sm">{person.kind === 'owner' ? 'Owner' : 'Admin'}</Badge>}
          <span>{lastSeen(person.lastLoginAt)}</span>
        </>
      }
      {...(locked
        ? {}
        : {
            actions: (
              <>
                {person.status === 'suspended' ? (
                  <Button size="sm" disabled={busy} onClick={() => { onAct(() => reactivate(person), `${person.displayName} can sign in again.`); }}>
                    Let back in
                  </Button>
                ) : (
                  <Button
                    size="sm"
                    disabled={busy}
                    onClick={() => { onAct(() => suspend(person), `${person.displayName} is suspended and signed out everywhere.`); }}
                  >
                    Suspend
                  </Button>
                )}
                <Menu>
                  <MenuTrigger>
                    <IconButton size="sm" label={`More actions for ${person.displayName}`} icon={icon(Ellipsis)} />
                  </MenuTrigger>
                  <MenuContent align="end">
                    {me?.kind === 'owner' ? (
                      <MenuItem
                        onSelect={() => {
                          onAct(
                            () => changeKind(person),
                            person.kind === 'admin' ? `${person.displayName} is a guest again.` : `${person.displayName} is an admin.`,
                          );
                        }}
                      >
                        {person.kind === 'admin' ? 'Make a guest' : 'Make an admin'}
                      </MenuItem>
                    ) : null}
                    <MenuItem
                      tone="danger"
                      onSelect={() => {
                        onReset(person);
                      }}
                    >
                      Reset their account…
                    </MenuItem>
                  </MenuContent>
                </Menu>
              </>
            ),
          })}
    />
  );
}

export function People() {
  const me = useMe();
  const { state, reload, retry } = useLoad(() => api.get<Directory>('/api/admin/people'));
  const [inviting, setInviting] = useState(false);
  const [resetting, setResetting] = useState<Person | undefined>();
  const [outcome, setOutcome] = useState<Outcome | undefined>();
  const [busy, setBusy] = useState(false);
  const [query, setQuery] = useState('');

  /** One place for the row actions: act, say what happened, reload. */
  function act(run: () => Promise<unknown>, said: string) {
    setBusy(true);
    setOutcome(undefined);
    run()
      .then(() => {
        setOutcome({ kind: 'done', text: said });
        reload();
      })
      .catch((err: unknown) => {
        setOutcome({ kind: 'failed', text: messageOf(err) });
      })
      .finally(() => {
        setBusy(false);
      });
  }

  if (state.status === 'loading') {
    return (
      <Page aria-busy="true">
        <Header />
        <RowsSkeleton rows={5} leading />
      </Page>
    );
  }
  if (state.status === 'denied') {
    return (
      <Page>
        <Header />
        <Denied heading="Managing people is for admins">
          Your account can sign in to apps, but not change who else can. {me?.operatorDisplayName ?? 'The owner'} can make you an admin.
        </Denied>
      </Page>
    );
  }
  if (state.status === 'failed') {
    return (
      <Page>
        <Header />
        <LoadFailed what="People" message={state.message} onRetry={retry} />
      </Page>
    );
  }

  const { people, pendingInvites } = state.data;
  const q = query.trim().toLowerCase();
  const shown = people.filter((person) => !q || [person.displayName, person.username, person.email].some((value) => value.toLowerCase().includes(q)));

  return (
    <Page>
      <Header
        count={people.length}
        onInvite={() => {
          setInviting(true);
        }}
      />

      {outcome ? <OutcomeAlert outcome={outcome} /> : null}

      <FilterBar aria-label="Filter people" trailing={<span>{`${shown.length} of ${people.length} ${people.length === 1 ? 'person' : 'people'}`}</span>}>
        <FormField label="Search">
          <Input
            type="search"
            leading={icon(Search)}
            placeholder="Name, username or email"
            value={query}
            onChange={(event) => {
              setQuery(event.target.value);
            }}
          />
        </FormField>
      </FilterBar>

      <Card>
        <DataList
          aria-label="People"
          empty={
            <EmptyState
              kind="no-results"
              size="inline"
              heading={`No one matches “${query.trim()}”`}
              action={
                <Button
                  size="sm"
                  onClick={() => {
                    setQuery('');
                  }}
                >
                  Clear the search
                </Button>
              }
            >
              Search looks at names, usernames and email addresses.
            </EmptyState>
          }
        >
          {shown.map((person) => (
            <PersonRow key={person.id} person={person} me={me} busy={busy} onAct={act} onReset={setResetting} />
          ))}
        </DataList>
      </Card>

      {pendingInvites.length > 0 ? (
        <Section title="Waiting to accept" description="Invites that have not been used yet. Each works once.">
          <DataList aria-label="Waiting to accept">
            {pendingInvites.map((pending) => (
              <DataListRow
                key={pending.id}
                leading={icon(Mail, 20)}
                title={pending.email}
                description={`Sent ${new Date(pending.createdAt).toLocaleDateString(undefined, { dateStyle: 'medium' })}`}
                meta={<span>Expires {new Date(pending.expiresAt).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })}</span>}
              />
            ))}
          </DataList>
        </Section>
      ) : null}

      <InviteModal
        open={inviting}
        onOpenChange={setInviting}
        onInvited={(invite) => {
          setOutcome({ kind: 'invited', invite });
          reload();
        }}
      />

      {resetting ? (
        <ConfirmReset
          person={resetting}
          open
          onOpenChange={(open) => {
            if (!open) setResetting(undefined);
          }}
          onDone={(result) => {
            setOutcome({ kind: 'reset', result });
            reload();
          }}
        />
      ) : null}
    </Page>
  );
}
