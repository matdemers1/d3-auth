import { Alert, Badge, Button, Card, EmptyState, FormField, Input, PageHeader, Skeleton } from '@d3cloud/ui';
import { useEffect, useState } from 'react';
import { api, ApiError, type InviteCreated, type Me, type PendingInvite, type Person } from '../api';

// C-1 and C-3: who can sign in, and how somebody new gets added.

interface Directory {
  people: Person[];
  pendingInvites: PendingInvite[];
}

const when = (iso: string | null): string => (iso ? new Date(iso).toLocaleDateString() : 'never');

export function People() {
  const [directory, setDirectory] = useState<Directory | undefined>();
  const [failed, setFailed] = useState<string | undefined>();
  const [email, setEmail] = useState('');
  const [busy, setBusy] = useState(false);
  const [invited, setInvited] = useState<InviteCreated | undefined>();
  const [problem, setProblem] = useState<string | undefined>();
  const [me, setMe] = useState<Me | undefined>();
  const [note, setNote] = useState<string | undefined>();
  // Reset cannot be undone — the old password and factors are gone — so it asks twice.
  const [confirming, setConfirming] = useState<string | undefined>();
  const [reset, setReset] = useState<{ email: string; url: string; delivered: boolean } | undefined>();

  const load = () => {
    api
      .get<Directory>('/api/admin/people')
      .then(setDirectory)
      .catch((err: unknown) => {
        setFailed(err instanceof ApiError && err.status === 403 ? 'not-allowed' : 'failed');
      });
  };

  useEffect(() => {
    load();
    api
      .get<Me>('/api/me')
      .then(setMe)
      .catch(() => {
        // The directory call decides what this screen shows; knowing who I am is a nicety.
      });
  }, []);

  /** One place for the row actions: act, say what happened, reload. */
  async function act(person: Person, path: string, said: string, body?: unknown) {
    setProblem(undefined);
    setReset(undefined);
    setConfirming(undefined);
    setBusy(true);
    try {
      const answer = await api.post<{ url?: string; mail?: { delivered: boolean } }>(`/api/admin/people/${person.id}/${path}`, body);
      if (answer.url) setReset({ email: person.email, url: answer.url, delivered: answer.mail?.delivered ?? false });
      else setProblem(undefined);
      setNote(said);
      load();
    } catch (err) {
      setProblem(err instanceof ApiError ? err.message : 'That did not work.');
    } finally {
      setBusy(false);
    }
  }

  async function invite(event: React.SyntheticEvent<HTMLFormElement, SubmitEvent>) {
    event.preventDefault();
    setBusy(true);
    setProblem(undefined);
    setInvited(undefined);
    try {
      const created = await api.post<InviteCreated>('/api/admin/invites', { email });
      setInvited(created);
      setEmail('');
      load();
    } catch (err) {
      setProblem(err instanceof Error ? err.message : 'That did not work.');
    } finally {
      setBusy(false);
    }
  }

  if (failed === 'not-allowed') {
    return (
      <main className="shell">
        <EmptyState kind="no-access" size="page" headingLevel={2} heading="This part of the console is for admins">
          Your account can sign in to apps, but not manage people.
        </EmptyState>
      </main>
    );
  }

  return (
    <main className="shell">
      <PageHeader title="People" description="Everyone who can sign in, and the invites you have sent." />

      <Card padding="lg">
        <form className="stack" onSubmit={(event) => void invite(event)}>
          <FormField label="Invite someone" help="They get an email with a link that works once.">
            <Input
              name="email"
              type="email"
              required
              placeholder="them@example.com"
              value={email}
              onChange={(event) => {
                setEmail(event.target.value);
              }}
            />
          </FormField>
          <Button type="submit" variant="primary" loading={busy}>
            Send invite
          </Button>
        </form>

        {problem ? (
          <Alert tone="danger" dynamic title="That did not work">
            {problem}
          </Alert>
        ) : null}

        {invited ? (
          invited.mail.delivered ? (
            <Alert tone="success" dynamic title={`Invite sent to ${invited.email}`}>
              It expires in three days. They will need a minute to pick a username and a password.
            </Alert>
          ) : (
            <Alert tone="warning" dynamic title={`The invite for ${invited.email} was saved, but the email did not send`}>
              <p>Send them this link yourself — it works once and expires in three days.</p>
              <code className="copy-link">{invited.url}</code>
            </Alert>
          )
        ) : null}
      </Card>

      {note ? (
        <Alert tone="success" dynamic title="Done">
          {note}
        </Alert>
      ) : null}

      {reset ? (
        reset.delivered ? (
          <Alert tone="success" dynamic title={`A set-up-again link was emailed to ${reset.email}`}>
            It works once and expires in two hours. Their account, and everything it can reach, is unchanged.
          </Alert>
        ) : (
          <Alert tone="warning" dynamic title={`The account was reset, but the email to ${reset.email} did not send`}>
            <p>Send them this link yourself — it works once and expires in two hours.</p>
            <code className="copy-link">{reset.url}</code>
          </Alert>
        )
      ) : null}

      {!directory ? (
        <Skeleton height="8rem" />
      ) : (
        <>
          <Card padding="lg">
            <h2 className="section-title">{directory.people.length} {directory.people.length === 1 ? 'person' : 'people'}</h2>
            <ul className="rows">
              {directory.people.map((person) => (
                <li key={person.id} className="row">
                  <div>
                    <strong>{person.displayName}</strong> <span className="muted">@{person.username}</span>
                    <div className="muted">{person.email}</div>
                  </div>
                  <div className="row-meta">
                    <Badge tone={person.kind === 'guest' ? 'neutral' : 'attention'}>{person.kind}</Badge>
                    {person.status === 'active' ? null : <Badge tone="danger">{person.status}</Badge>}
                    <span className="muted">last signed in {when(person.lastLoginAt)}</span>
                    {person.kind === 'owner' || person.id === me?.id ? null : (
                      <>
                        {me?.kind === 'owner' ? (
                          <Button
                            variant="secondary"
                            size="sm"
                            disabled={busy}
                            onClick={() =>
                              void act(
                                person,
                                'kind',
                                person.kind === 'admin' ? `${person.displayName} is a guest again.` : `${person.displayName} is an admin.`,
                                { kind: person.kind === 'admin' ? 'guest' : 'admin' },
                              )
                            }
                          >
                            {person.kind === 'admin' ? 'Make a guest' : 'Make an admin'}
                          </Button>
                        ) : null}
                        {person.status === 'suspended' ? (
                          <Button
                            variant="secondary"
                            size="sm"
                            disabled={busy}
                            onClick={() => void act(person, 'reactivate', `${person.displayName} can sign in again.`)}
                          >
                            Let them back in
                          </Button>
                        ) : (
                          <Button
                            variant="danger-ghost"
                            size="sm"
                            disabled={busy}
                            onClick={() => void act(person, 'suspend', `${person.displayName} is suspended and signed out everywhere.`)}
                          >
                            Suspend
                          </Button>
                        )}
                        <Button
                          variant={confirming === person.id ? 'danger' : 'danger-ghost'}
                          size="sm"
                          disabled={busy}
                          onClick={() => {
                            if (confirming === person.id) {
                              void act(person, 'reset', `${person.displayName} has to set their account up again.`);
                            } else {
                              setConfirming(person.id);
                            }
                          }}
                        >
                          {confirming === person.id ? 'Yes, reset their account' : 'Reset'}
                        </Button>
                      </>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          </Card>

          {directory.pendingInvites.length > 0 ? (
            <Card padding="lg">
              <h2 className="section-title">Waiting to accept</h2>
              <ul className="rows">
                {directory.pendingInvites.map((pending) => (
                  <li key={pending.id} className="row">
                    <span>{pending.email}</span>
                    <span className="muted">expires {new Date(pending.expiresAt).toLocaleString()}</span>
                  </li>
                ))}
              </ul>
            </Card>
          ) : null}
        </>
      )}
    </main>
  );
}
