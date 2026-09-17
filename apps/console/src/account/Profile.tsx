import { Alert, Button, FormActions, FormField, Input, Page, PageHeader, Section, Stack } from '@d3cloud/ui';
import { useState } from 'react';
import { api, ApiError } from '../api';
import { useLoad } from '../shared/load';
import { useOperator } from '../shared/me';
import { FactsSkeleton, LoadFailed } from '../shared/states';

// A-2: the parts of the profile a person owns. The email is shown but not editable — it is the
// address an admin invited, and it is how the account is found.

interface ProfileView {
  email: string;
  username: string;
  displayName: string;
}

const DESCRIPTION = 'The name people see, and the username you sign in with.';

function Form({ profile }: { profile: ProfileView }) {
  const operator = useOperator();
  const [displayName, setDisplayName] = useState(profile.displayName);
  const [username, setUsername] = useState(profile.username);
  const [problems, setProblems] = useState<string[]>([]);
  const [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(false);

  async function save(event: React.SyntheticEvent) {
    event.preventDefault();
    setBusy(true);
    setProblems([]);
    setSaved(false);
    try {
      await api.post('/api/account/profile', { displayName, username });
      setSaved(true);
    } catch (err) {
      if (err instanceof ApiError) {
        const listed = err.body.problems;
        setProblems(Array.isArray(listed) ? (listed as string[]) : [err.message]);
      } else {
        setProblems(['The console could not reach the server. Nothing was saved.']);
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <Section title="Your details">
      {problems.length > 0 ? (
        <Alert tone="danger" dynamic title="That did not save">
          <ul>
            {problems.map((problem) => (
              <li key={problem}>{problem}</li>
            ))}
          </ul>
        </Alert>
      ) : null}
      {saved ? (
        <Alert tone="success" dynamic title="Saved">
          Your profile is up to date.
        </Alert>
      ) : null}
      <Stack as="form" gap="16" aria-label="Your details" onSubmit={(event) => void save(event)}>
        <FormField label="Display name" width="lg" help="What other people see next to your activity.">
          <Input
            name="displayName"
            autoComplete="name"
            required
            value={displayName}
            onChange={(event) => {
              setDisplayName(event.target.value);
            }}
          />
        </FormField>
        <FormField label="Username" width="md" help="Letters, numbers, dot, dash or underscore.">
          <Input
            name="username"
            autoComplete="username"
            spellCheck={false}
            required
            value={username}
            onChange={(event) => {
              setUsername(event.target.value);
            }}
          />
        </FormField>
        <FormField label="Email" width="lg" help={`Ask ${operator} if this needs to change.`}>
          <Input name="email" value={profile.email} readOnly />
        </FormField>
        <FormActions>
          <Button type="submit" variant="primary" loading={busy}>
            Save profile
          </Button>
        </FormActions>
      </Stack>
    </Section>
  );
}

export function Profile() {
  const { state, retry } = useLoad(() => api.get<ProfileView>('/api/account/profile'));
  return (
    <Page width="narrow" {...(state.status === 'loading' ? { 'aria-busy': true } : {})}>
      <PageHeader title="Profile" description={DESCRIPTION} />
      {state.status === 'loading' ? (
        <FactsSkeleton title="Your details" rows={3} />
      ) : state.status === 'ready' ? (
        <Form profile={state.data} />
      ) : (
        <LoadFailed what="Your profile" message={state.status === 'failed' ? state.message : 'The server refused.'} onRetry={retry} />
      )}
    </Page>
  );
}
