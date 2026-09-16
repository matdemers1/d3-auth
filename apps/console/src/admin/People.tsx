import { Alert, Badge, Button, Card, EmptyState, FormField, Input, PageHeader, Skeleton } from '@d3cloud/ui';
import { useEffect, useState } from 'react';
import { api, ApiError, type InviteCreated, type PendingInvite, type Person } from '../api';

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

  const load = () => {
    api
      .get<Directory>('/api/admin/people')
      .then(setDirectory)
      .catch((err: unknown) => {
        setFailed(err instanceof ApiError && err.status === 403 ? 'not-allowed' : 'failed');
      });
  };

  useEffect(load, []);

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
