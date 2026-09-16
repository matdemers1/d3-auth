import { Alert, Badge, Button, Card, EmptyState, FormField, Input, Link, PageHeader, Skeleton } from '@d3cloud/ui';
import { useEffect, useState } from 'react';
import { api, ApiError } from '../api';

// C-7: groups (REQ-068).
//
// A group is how the same access is given to several people at once — and taken away the same
// way. It never appears in a token, so nothing an app sees changes when these are edited; only
// what the people in them may do.

interface GroupSummary {
  id: string;
  name: string;
  description: string;
  memberCount: number;
  appCount: number;
}

export function Groups() {
  const [groups, setGroups] = useState<GroupSummary[] | undefined>();
  const [name, setName] = useState('');
  const [problem, setProblem] = useState<string | undefined>();
  const [failed, setFailed] = useState(false);
  const [busy, setBusy] = useState(false);

  const load = () => {
    api
      .get<{ groups: GroupSummary[] }>('/api/admin/groups')
      .then((answer) => {
        setGroups(answer.groups);
      })
      .catch(() => {
        setFailed(true);
      });
  };

  useEffect(load, []);

  async function create(event: React.SyntheticEvent<HTMLFormElement, SubmitEvent>) {
    event.preventDefault();
    setBusy(true);
    setProblem(undefined);
    try {
      await api.post('/api/admin/groups', { name });
      setName('');
      load();
    } catch (err) {
      setProblem(err instanceof ApiError ? err.message : 'That did not work.');
    } finally {
      setBusy(false);
    }
  }

  if (failed) {
    return (
      <main className="shell">
        <EmptyState kind="no-access" size="page" headingLevel={2} heading="Groups are for admins">
          Your account can sign in to apps, but not organise who else can.
        </EmptyState>
      </main>
    );
  }

  return (
    <main className="shell">
      <PageHeader title="Groups" description="Give the same access to several people at once." />

      {problem ? (
        <Alert tone="danger" dynamic title="That did not work">
          {problem}
        </Alert>
      ) : null}

      <Card padding="lg">
        <form className="stack" onSubmit={(event) => void create(event)}>
          <FormField label="New group" help="Letters, numbers and spaces. Name it after what it is for.">
            <Input
              name="name"
              required
              placeholder="Editors"
              value={name}
              onChange={(event) => {
                setName(event.target.value);
              }}
            />
          </FormField>
          <Button type="submit" variant="primary" loading={busy}>
            Create
          </Button>
        </form>
      </Card>

      {!groups ? (
        <Skeleton height="8rem" />
      ) : groups.length === 0 ? (
        <Card padding="lg">
          <EmptyState kind="empty" size="inline" headingLevel={2} heading="No groups yet">
            Access works without them. A group is worth making when the same set of people needs the same access to more than one app.
          </EmptyState>
        </Card>
      ) : (
        <Card padding="lg">
          <ul className="rows">
            {groups.map((group) => (
              <li key={group.id} className="row">
                <div>
                  <strong>
                    <Link href={`/admin/groups/${encodeURIComponent(group.id)}`}>{group.name}</Link>
                  </strong>
                  {group.description ? <div className="muted">{group.description}</div> : null}
                </div>
                <div className="row-meta">
                  <Badge tone="neutral">
                    {group.memberCount} {group.memberCount === 1 ? 'person' : 'people'}
                  </Badge>
                  <span className="muted">
                    {group.appCount} {group.appCount === 1 ? 'app' : 'apps'}
                  </span>
                </div>
              </li>
            ))}
          </ul>
        </Card>
      )}
    </main>
  );
}
