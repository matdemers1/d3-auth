import { Alert, Button, Card, PageHeader } from '@d3cloud/ui';
import { useState } from 'react';
import { api, ApiError } from '../api';
import { StepUp } from './StepUp';

// C-11: export and import (REQ-072).
//
// The rule this screen exists to enforce: nothing is applied until somebody has read what it
// would do. The file is uploaded, previewed, and only then applied — and the preview is produced
// by the same code path that applies it, so it cannot drift into a comforting lie.

interface Plan {
  apps: { create: string[]; update: string[] };
  people: { create: string[]; update: string[] };
  groups: { create: string[]; update: string[] };
  secretPending: string[];
  needsReEnrolment: string[];
  problems: string[];
  applied: boolean;
}

function Changes({ label, part }: { label: string; part: { create: string[]; update: string[] } }) {
  if (part.create.length === 0 && part.update.length === 0) return <p className="muted">{label}: nothing changes.</p>;
  return (
    <div>
      <h3 className="section-title">
        {label}: {part.create.length} new, {part.update.length} updated
      </h3>
      <ul className="rows">
        {part.create.map((name) => (
          <li key={`new-${name}`}>
            <strong>New</strong> {name}
          </li>
        ))}
        {part.update.map((name) => (
          <li key={`upd-${name}`}>Updated {name}</li>
        ))}
      </ul>
    </div>
  );
}

export function Transfer() {
  const [state, setState] = useState<unknown>();
  const [fileName, setFileName] = useState('');
  const [plan, setPlan] = useState<Plan | undefined>();
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ tone: 'danger' | 'success'; title: string; text: string } | undefined>();
  const [pending, setPending] = useState<(() => void) | undefined>();

  async function chose(file: File) {
    setMessage(undefined);
    setPlan(undefined);
    setFileName(file.name);
    let parsed: unknown;
    try {
      parsed = JSON.parse(await file.text());
    } catch {
      setMessage({ tone: 'danger', title: 'That is not a state file', text: 'It could not be read as JSON.' });
      return;
    }
    setState(parsed);
    setBusy(true);
    try {
      setPlan(await api.post<Plan>('/api/admin/state/import/preview', { state: parsed }));
    } catch (err) {
      setMessage({
        tone: 'danger',
        title: 'That file was refused',
        text: err instanceof ApiError && Array.isArray(err.body.problems) ? (err.body.problems as string[]).join('; ') : 'It is not a state file this version understands.',
      });
    } finally {
      setBusy(false);
    }
  }

  async function apply() {
    setBusy(true);
    setMessage(undefined);
    try {
      const result = await api.post<Plan>('/api/admin/state/import', { state });
      setPlan(result);
      setPending(undefined);
      setMessage({
        tone: 'success',
        title: 'Imported',
        text:
          result.secretPending.length > 0
            ? `Done. ${result.secretPending.length} app(s) still need a secret before anyone can sign in to them.`
            : 'Done.',
      });
    } catch (err) {
      if (err instanceof ApiError && err.body.error === 'step_up_required') {
        setPending(() => () => void apply());
        return;
      }
      setMessage({ tone: 'danger', title: 'That did not work', text: err instanceof ApiError ? err.message : 'Try again.' });
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="shell">
      <PageHeader title="Export & import" description="Move this instance's shape somewhere else — apps, roles, groups and who may reach what." />

      {message ? (
        <Alert tone={message.tone} dynamic title={message.title}>
          {message.text}
        </Alert>
      ) : null}

      <Card padding="lg">
        <h2 className="section-title">Export</h2>
        <p className="muted">
          A JSON file describing every app, role, group and grant. It carries <strong>no secrets, no passwords and no keys</strong> — it is a shape,
          not a backup, and it is safe to keep in version control.
        </p>
        <Button
          variant="secondary"
          onClick={() => {
            window.location.href = '/api/admin/state/export';
          }}
        >
          Download the state file
        </Button>
      </Card>

      <Card padding="lg">
        <h2 className="section-title">Import</h2>
        <p className="muted">Nothing is written until you have read what it would do. Choose a file to see that first.</p>
        <input
          type="file"
          accept="application/json,.json"
          aria-label="State file"
          onChange={(event) => {
            const file = event.target.files?.[0];
            if (file) void chose(file);
          }}
        />

        {plan ? (
          <div className="stack" style={{ marginTop: 'var(--space-16)' }}>
            <h3 className="section-title">{plan.applied ? `Applied ${fileName}` : `What ${fileName} would do`}</h3>
            <Changes label="Apps" part={plan.apps} />
            <Changes label="People" part={plan.people} />
            <Changes label="Groups" part={plan.groups} />

            {plan.secretPending.length > 0 ? (
              <Alert tone="warning" title="Secret pending">
                {plan.secretPending.join(', ')} arrive without a client secret and cannot be signed in to until you rotate one on the app's page.
              </Alert>
            ) : null}
            {plan.needsReEnrolment.length > 0 ? (
              <Alert tone="warning" title="No way in yet">
                {plan.needsReEnrolment.length} person(s) will exist with no password and no passkey. They need an invite or a reset before they can
                sign in.
              </Alert>
            ) : null}
            {plan.problems.length > 0 ? (
              <Alert tone="danger" title="Problems in the file">
                <ul className="rows">
                  {plan.problems.map((problem) => (
                    <li key={problem}>{problem}</li>
                  ))}
                </ul>
              </Alert>
            ) : null}

            {plan.applied ? null : (
              <Button variant="primary" loading={busy} onClick={() => void apply()}>
                Apply this
              </Button>
            )}
          </div>
        ) : null}
      </Card>

      {pending ? (
        <StepUp
          action="importing a state file"
          onProved={() => {
            pending();
          }}
          onCancel={() => {
            setPending(undefined);
          }}
        />
      ) : null}
    </main>
  );
}
