import { Alert, Button, Card, FormField, Input, PageHeader, Skeleton } from '@d3cloud/ui';
import { useEffect, useState } from 'react';
import { api, ApiError } from '../api';

// A-2: the parts of the profile a person owns. The email is shown but not editable — it is the
// address an admin invited, and it is how the account is found.

interface ProfileView {
  email: string;
  username: string;
  displayName: string;
}

export function Profile() {
  const [profile, setProfile] = useState<ProfileView | undefined>();
  const [displayName, setDisplayName] = useState('');
  const [username, setUsername] = useState('');
  const [problems, setProblems] = useState<string[]>([]);
  const [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api
      .get<ProfileView>('/api/account/profile')
      .then((loaded) => {
        setProfile(loaded);
        setDisplayName(loaded.displayName);
        setUsername(loaded.username);
      })
      .catch(() => {
        setProblems(['We could not load your profile.']);
      });
  }, []);

  async function save(event: React.SyntheticEvent<HTMLFormElement, SubmitEvent>) {
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
        setProblems(['We could not save that. Try again.']);
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="shell">
      <PageHeader title="Your profile" description="The name people see, and the username you sign in with." />

      {problems.length > 0 ? (
        <Alert tone="danger" dynamic title="That did not save">
          <ul className="rows">
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

      {!profile ? (
        <Skeleton height="12rem" />
      ) : (
        <Card padding="lg">
          <form className="stack" onSubmit={(event) => void save(event)}>
            <FormField label="Display name" help="What other people see next to your activity.">
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
            <FormField label="Username" help="Letters, numbers, dot, dash or underscore.">
              <Input
                name="username"
                autoComplete="username"
                required
                value={username}
                onChange={(event) => {
                  setUsername(event.target.value);
                }}
              />
            </FormField>
            <FormField label="Email" help="Ask an admin if this needs to change.">
              <Input name="email" value={profile.email} readOnly />
            </FormField>
            <Button type="submit" variant="primary" loading={busy}>
              Save
            </Button>
          </form>
        </Card>
      )}
    </main>
  );
}
