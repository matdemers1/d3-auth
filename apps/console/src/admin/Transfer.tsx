import { Alert, Button, DescriptionItem, DescriptionList, FormActions, FormField, Input, Page, PageHeader, Section } from '@d3cloud/ui';
import { Download } from 'lucide-react';
import { useState } from 'react';
import { api, ApiError } from '../api';
import { icon } from '../shared/icons';
import { messageOf } from '../shared/load';
import { useMe } from '../shared/me';
import { useStepUp } from '../shared/StepUp';
import { Denied } from '../shared/states';

// C-11: export and import (REQ-072).
//
// The rule this screen exists to enforce: nothing is applied until somebody has read what it would
// do. The file is uploaded, previewed, and only then applied — and the preview is produced by the
// same code path that applies it, so it cannot drift into a comforting lie.

interface Plan {
  apps: { create: string[]; update: string[] };
  people: { create: string[]; update: string[] };
  groups: { create: string[]; update: string[] };
  secretPending: string[];
  needsReEnrolment: string[];
  problems: string[];
  applied: boolean;
}

function changes(part: { create: string[]; update: string[] }): React.ReactNode {
  if (part.create.length === 0 && part.update.length === 0) return 'Nothing changes';
  return [
    part.create.length > 0 ? `New: ${part.create.join(', ')}` : null,
    part.update.length > 0 ? `Updated: ${part.update.join(', ')}` : null,
  ]
    .filter(Boolean)
    .join('. ');
}

const DESCRIPTION = 'Move this instance’s shape somewhere else: apps, roles, groups and who may reach what.';

export function Transfer() {
  const me = useMe();
  const { ask, prompt } = useStepUp();
  const [state, setState] = useState<unknown>();
  const [fileName, setFileName] = useState('');
  const [plan, setPlan] = useState<Plan | undefined>();
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ tone: 'danger' | 'success'; title: string; text: string } | undefined>();

  async function chose(file: File) {
    setMessage(undefined);
    setPlan(undefined);
    setFileName(file.name);
    let parsed: unknown;
    try {
      parsed = JSON.parse(await file.text());
    } catch {
      setMessage({ tone: 'danger', title: 'That is not a state file', text: 'It could not be read as JSON. Nothing was changed.' });
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
        text:
          err instanceof ApiError && Array.isArray(err.body.problems)
            ? (err.body.problems as string[]).join('; ')
            : err instanceof ApiError && err.status === 403
              ? 'Importing is the owner’s to do.'
              : 'It is not a state file this version understands. Nothing was changed.',
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
      setMessage({
        tone: 'success',
        title: 'Imported',
        text:
          result.secretPending.length > 0
            ? `Done. ${result.secretPending.length === 1 ? 'One app still needs' : `${result.secretPending.length} apps still need`} a secret before anyone can sign in to it.`
            : 'Done. Everything in the file is in place.',
      });
    } catch (err) {
      if (ask(err, 'importing a state file', () => void apply())) return;
      setMessage({ tone: 'danger', title: 'Nothing was imported', text: messageOf(err) });
    } finally {
      setBusy(false);
    }
  }

  // Nothing loads before the first action here, so the role decides the page. The server still
  // refuses every call from anyone else.
  if (me && me.kind !== 'owner') {
    return (
      <Page width="narrow">
        <PageHeader title="Export and import" description={DESCRIPTION} />
        <Denied heading="Export and import are the owner’s">
          A state file describes every app and grant on this instance. Ask {me.operatorDisplayName} if you need one.
        </Denied>
      </Page>
    );
  }

  return (
    <Page width="narrow">
      <PageHeader title="Export and import" description={DESCRIPTION} />

      <Section
        title="Export"
        description="A JSON file of every app, role, group and grant. It carries no secrets, no passwords and no keys — a shape, not a backup — so it is safe to keep in version control."
      >
        <FormActions align="start">
          <Button
            icon={icon(Download)}
            onClick={() => {
              window.location.href = '/api/admin/state/export';
            }}
          >
            Download the state file
          </Button>
        </FormActions>
      </Section>

      <Section title="Import" description="Nothing is written until you have read what it would do. Choose a file to see that first.">
        {message ? (
          <Alert tone={message.tone} dynamic title={message.title}>
            {message.text}
          </Alert>
        ) : null}
        <FormField label="State file" width="lg" help="A file downloaded from Export, here or on another instance.">
          <Input
            type="file"
            accept="application/json,.json"
            onChange={(event) => {
              const file = event.target.files?.[0];
              if (file) void chose(file);
            }}
          />
        </FormField>

        {plan ? (
          <Section headingLevel={3} surface="plain" title={plan.applied ? `Applied ${fileName}` : `What ${fileName} would do`}>
            <DescriptionList>
              <DescriptionItem term="Apps">{changes(plan.apps)}</DescriptionItem>
              <DescriptionItem term="People">{changes(plan.people)}</DescriptionItem>
              <DescriptionItem term="Groups">{changes(plan.groups)}</DescriptionItem>
            </DescriptionList>

            {plan.secretPending.length > 0 ? (
              <Alert tone="warning" title="Secret pending">
                {plan.secretPending.join(', ')} arrive without a client secret, and cannot be signed in to until you rotate one on the app’s page.
              </Alert>
            ) : null}
            {plan.needsReEnrolment.length > 0 ? (
              <Alert tone="warning" title="No way in yet">
                {plan.needsReEnrolment.length === 1 ? 'One person' : `${plan.needsReEnrolment.length} people`} will exist with no password and no passkey.
                They need an invite or a reset before they can sign in.
              </Alert>
            ) : null}
            {plan.problems.length > 0 ? (
              <Alert tone="danger" title="Problems in the file">
                <ul>
                  {plan.problems.map((problem) => (
                    <li key={problem}>{problem}</li>
                  ))}
                </ul>
              </Alert>
            ) : null}

            {plan.applied ? null : (
              <FormActions>
                <Button variant="primary" loading={busy} onClick={() => void apply()}>
                  Apply {fileName}
                </Button>
              </FormActions>
            )}
          </Section>
        ) : null}
      </Section>

      {prompt}
    </Page>
  );
}
