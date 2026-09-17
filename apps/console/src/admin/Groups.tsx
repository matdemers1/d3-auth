import { Alert, Button, Card, DataList, DataListRow, EmptyState, FormField, Input, Modal, Page, PageHeader, Stack } from '@d3cloud/ui';
import { Plus, UsersRound } from 'lucide-react';
import { useId, useState } from 'react';
import { api } from '../api';
import { icon } from '../shared/icons';
import { messageOf, useLoad } from '../shared/load';
import { useMe } from '../shared/me';
import { Denied, LoadFailed, RowsSkeleton } from '../shared/states';

// C-7: groups (REQ-068), as a list page.
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

const plural = (n: number, one: string, many: string): string => `${n} ${n === 1 ? one : many}`;

function CreateGroup({ open, onOpenChange, onCreated }: { open: boolean; onOpenChange: (open: boolean) => void; onCreated: (name: string) => void }) {
  const formId = useId();
  const [name, setName] = useState('');
  const [problem, setProblem] = useState<string | undefined>();
  const [busy, setBusy] = useState(false);

  async function create(event: React.SyntheticEvent) {
    event.preventDefault();
    setBusy(true);
    setProblem(undefined);
    try {
      await api.post('/api/admin/groups', { name });
      onOpenChange(false);
      onCreated(name);
      setName('');
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
      title="Create a group"
      description="Name it after what it is for. You add people and access on its page."
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
            Create group
          </Button>
        </>
      }
    >
      <Stack as="form" id={formId} gap="16" aria-label="Create a group" onSubmit={(event) => void create(event)}>
        {problem ? (
          <Alert tone="danger" dynamic title="The group was not created">
            {problem}
          </Alert>
        ) : null}
        <FormField label="Group name" help="Letters, numbers and spaces.">
          <Input
            name="name"
            required
            autoFocus
            autoComplete="off"
            value={name}
            onChange={(event) => {
              setName(event.target.value);
            }}
          />
        </FormField>
      </Stack>
    </Modal>
  );
}

export function Groups() {
  const me = useMe();
  const { state, reload, retry } = useLoad(() => api.get<{ groups: GroupSummary[] }>('/api/admin/groups').then((answer) => answer.groups));
  const [creating, setCreating] = useState(false);
  const [created, setCreated] = useState<string | undefined>();

  const create = (
    <Button
      variant="primary"
      icon={icon(Plus)}
      onClick={() => {
        setCreating(true);
      }}
    >
      Create a group
    </Button>
  );
  const description = 'Give the same access to several people at once.';
  const modal = (
    <CreateGroup
      open={creating}
      onOpenChange={setCreating}
      onCreated={(name) => {
        setCreated(name);
        reload();
      }}
    />
  );

  if (state.status === 'loading') {
    return (
      <Page aria-busy="true">
        <PageHeader title="Groups" description={description} actions={create} />
        <RowsSkeleton rows={3} />
      </Page>
    );
  }
  if (state.status === 'denied') {
    return (
      <Page>
        <PageHeader title="Groups" description={description} />
        <Denied heading="Groups are for admins">
          Your account can sign in to apps, but not organise who else can. {me?.operatorDisplayName ?? 'The owner'} can make you an admin.
        </Denied>
      </Page>
    );
  }
  if (state.status === 'failed') {
    return (
      <Page>
        <PageHeader title="Groups" description={description} />
        <LoadFailed what="Groups" message={state.message} onRetry={retry} />
      </Page>
    );
  }

  const groups = state.data;

  // Nothing exists yet: the empty state explains the list and carries the one primary.
  if (groups.length === 0) {
    return (
      <Page>
        <PageHeader title="Groups" count={0} description={description} />
        <Card>
          <EmptyState kind="empty" headingLevel={2} heading="No groups yet" icon={icon(UsersRound, 24)} action={create}>
            Access works without them. Make one when the same people need the same access to more than one app.
          </EmptyState>
        </Card>
        {modal}
      </Page>
    );
  }

  return (
    <Page>
      <PageHeader title="Groups" count={groups.length} description={description} actions={create} />
      {created ? (
        <Alert tone="success" dynamic title={`${created} is ready`}>
          Open it to add people and give it access.
        </Alert>
      ) : null}
      <Card>
        <DataList aria-label="Groups">
          {groups.map((group) => (
            <DataListRow
              key={group.id}
              leading={icon(UsersRound, 20)}
              href={`/admin/groups/${encodeURIComponent(group.id)}`}
              title={group.name}
              {...(group.description ? { description: group.description } : {})}
              meta={<span>{`${plural(group.memberCount, 'person', 'people')} · ${plural(group.appCount, 'app', 'apps')}`}</span>}
            />
          ))}
        </DataList>
      </Card>
      {modal}
    </Page>
  );
}
