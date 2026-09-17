import { Alert, Badge, Button, DescriptionItem, DescriptionList, EmptyState, FormActions, FormField, Input, Link, Page, PageHeader, Section, Stack } from '@d3cloud/ui';
import { ArrowLeft } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { api, ApiError, type Manifest, type ManifestDiff, type PresetSummary, type Problem, type Registration } from '../api';
import { icon } from '../shared/icons';
import { useLoad } from '../shared/load';
import { useMe } from '../shared/me';
import { useStepUp } from '../shared/StepUp';
import { Denied, FactsSkeleton, LoadFailed } from '../shared/states';
import { Registered } from './Registered';

// C-6 for an app D3 Auth knows (REQ-143): the one or two questions only the owner can answer, then
// what that registers, then Register.
//
// Checking first is not optional here. A preset decides redirect URIs from an address, and the
// owner should see exactly which URIs before any of them can receive a sign-in — so the primary
// button checks, and only once the check matches what is in the fields does it register.

function Back() {
  return (
    <Link variant="muted" href="/admin/apps/new">
      {icon(ArrowLeft, 14)}
      Add an app
    </Link>
  );
}

interface Preview {
  /** The fields as they were when the check ran, so an edit makes the preview stale. */
  sent: Record<string, string>;
  manifest: Manifest;
  diff: ManifestDiff;
}

function UriList({ uris }: { uris: string[] }) {
  return (
    <Stack gap="4" className="mono-list">
      {uris.map((uri) => (
        <code key={uri}>{uri}</code>
      ))}
    </Stack>
  );
}

function WhatItRegisters({ preview }: { preview: Preview }) {
  const { manifest, diff } = preview;
  return (
    <Section
      title="What D3 Auth will register"
      description="Only these addresses can receive a sign-in. Nobody can sign in until you give them access."
    >
      {diff.isNew ? null : (
        <Alert tone="danger" dynamic title={`An app called ${manifest.client_id} is already registered`}>
          Pick a different client ID, or change the existing app from its page.
        </Alert>
      )}
      <DescriptionList aria-label="What D3 Auth will register">
        <DescriptionItem term="Client ID">
          <code>{manifest.client_id}</code>
        </DescriptionItem>
        <DescriptionItem term="Type">Web app with a client secret</DescriptionItem>
        <DescriptionItem term="Returns to">
          <UriList uris={manifest.redirect_uris} />
        </DescriptionItem>
        <DescriptionItem term="After sign-out">
          <UriList uris={manifest.post_logout_redirect_uris} />
        </DescriptionItem>
        <DescriptionItem term="Sign-out notice">
          {manifest.backchannel_logout_uri ? (
            <code>{manifest.backchannel_logout_uri}</code>
          ) : (
            <Badge size="sm" tone="attention">
              Slow revoke
            </Badge>
          )}
        </DescriptionItem>
        <DescriptionItem term="Roles">
          <Stack gap="4" className="mono-list">
            {manifest.roles.map((role) => (
              <span key={role.key}>
                {role.display} <code>{role.key}</code>
                {role.default ? ' · suggested' : ''}
              </span>
            ))}
          </Stack>
        </DescriptionItem>
      </DescriptionList>
    </Section>
  );
}

const same = (a: Record<string, string>, b: Record<string, string>): boolean =>
  Object.keys({ ...a, ...b }).every((key) => (a[key] ?? '') === (b[key] ?? ''));

function Form({ preset }: { preset: PresetSummary }) {
  const { ask, prompt } = useStepUp();
  const [values, setValues] = useState<Record<string, string>>(() =>
    Object.fromEntries(preset.inputs.map((input) => [input.key, input.default ?? ''])),
  );
  const [problems, setProblems] = useState<Problem[]>([]);
  const [failure, setFailure] = useState<string | undefined>();
  const [preview, setPreview] = useState<Preview | undefined>();
  const [registration, setRegistration] = useState<Registration | undefined>();
  const [busy, setBusy] = useState(false);
  const top = useRef<HTMLDivElement>(null);

  // A form-level failure takes focus, so it is read before anything else (Forms pattern).
  useEffect(() => {
    if (failure || problems.length > 0) top.current?.focus();
  }, [failure, problems]);

  const trimmed = Object.fromEntries(Object.entries(values).map(([key, value]) => [key, value.trim()]));
  // The preview describes the fields only until one of them is edited.
  const current = preview !== undefined && same(trimmed, preview.sent);

  const readFailure = (err: unknown): void => {
    if (err instanceof ApiError && Array.isArray(err.body.problems)) {
      setProblems(err.body.problems as Problem[]);
      return;
    }
    setFailure(err instanceof ApiError ? err.message : 'The console could not reach the server. Nothing was registered.');
  };

  async function check() {
    setBusy(true);
    setProblems([]);
    setFailure(undefined);
    try {
      const answer = await api.post<{ inputs: Record<string, string>; manifest: Manifest; diff: ManifestDiff }>(
        `/api/admin/app-presets/${encodeURIComponent(preset.key)}/preview`,
        { inputs: trimmed },
      );
      setPreview({ sent: trimmed, manifest: answer.manifest, diff: answer.diff });
    } catch (err) {
      setPreview(undefined);
      readFailure(err);
    } finally {
      setBusy(false);
    }
  }

  async function register() {
    setBusy(true);
    setProblems([]);
    setFailure(undefined);
    try {
      setRegistration(await api.post<Registration>('/api/admin/apps/from-preset', { preset: preset.key, inputs: trimmed }));
    } catch (err) {
      // Hold the click: once they have proved it is them, it registers.
      if (ask(err, `registering ${preset.name}`, () => void register())) return;
      readFailure(err);
    } finally {
      setBusy(false);
    }
  }

  if (registration) return <Registered registration={registration} />;

  const errorFor = (key: string): string | undefined => problems.find((problem) => problem.field === key)?.message;
  const unplaced = problems.filter((problem) => !preset.inputs.some((input) => input.key === problem.field));

  return (
    <Page width="narrow">
      <PageHeader back={<Back />} title={`Add ${preset.name}`} description={`${preset.summary}. Answer this, check what it registers, then register it.`} />

      <Stack
        as="form"
        gap="24"
        aria-label={`Add ${preset.name}`}
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          void (current && preview.diff.isNew ? register() : check());
        }}
      >
        {failure ? (
          <Alert ref={top} tabIndex={-1} tone="danger" dynamic title={`${preset.name} was not registered`}>
            {failure}
          </Alert>
        ) : problems.length > 0 ? (
          <Alert ref={top} tabIndex={-1} tone="danger" dynamic title={`${preset.name} was not registered`}>
              {problems.length === 1 ? 'One answer needs changing.' : `${String(problems.length)} answers need changing.`} Nothing was saved.
              {unplaced.length > 0 ? (
                <ul>
                  {unplaced.map((problem) => (
                    <li key={problem.message}>{problem.message}</li>
                  ))}
                </ul>
              ) : null}
          </Alert>
        ) : null}

        <Section title={`Where ${preset.name} is`}>
          {preset.inputs.map((input) => {
            const error = errorFor(input.key);
            return (
              <FormField
                key={input.key}
                label={input.label}
                help={input.help}
                width={input.kind === 'client_id' ? 'sm' : 'full'}
                {...(error ? { error } : {})}
              >
                <Input
                  name={input.key}
                  type={input.kind === 'address' ? 'url' : 'text'}
                  inputMode={input.kind === 'address' ? 'url' : 'text'}
                  autoComplete="off"
                  autoCapitalize="none"
                  spellCheck={false}
                  {...(input.placeholder ? { placeholder: input.placeholder } : {})}
                  value={values[input.key] ?? ''}
                  onChange={(event) => {
                    setValues((before) => ({ ...before, [input.key]: event.target.value }));
                  }}
                />
              </FormField>
            );
          })}
        </Section>

        {current ? <WhatItRegisters preview={preview} /> : null}

        <FormActions
          leading={
            <Button
              variant="ghost"
              disabled={busy}
              onClick={() => {
                window.location.assign('/admin/apps/new');
              }}
            >
              Cancel
            </Button>
          }
        >
          <Button type="submit" variant="primary" loading={busy}>
            {current && preview.diff.isNew ? `Register ${preset.name}` : 'Check what it registers'}
          </Button>
        </FormActions>
      </Stack>
      {prompt}
    </Page>
  );
}

export function PresetForm({ presetKey }: { presetKey: string }) {
  const me = useMe();
  const { state, retry } = useLoad(() => api.get<{ presets: PresetSummary[] }>('/api/admin/app-presets').then((answer) => answer.presets), presetKey);

  if (state.status === 'ready') {
    const preset = state.data.find((candidate) => candidate.key === presetKey);
    if (preset) return <Form preset={preset} />;
    return (
      <Page width="narrow">
        <PageHeader back={<Back />} title="Add an app" />
        <EmptyState
          kind="empty"
          headingLevel={2}
          heading="D3 Auth does not know that app"
          action={
            <Link variant="standalone" href="/admin/apps/new">
              See the apps it knows
            </Link>
          }
        >
          It may be listed under another name, or you can register it from its manifest.
        </EmptyState>
      </Page>
    );
  }

  return (
    <Page width="narrow" {...(state.status === 'loading' ? { 'aria-busy': true } : {})}>
      <PageHeader back={<Back />} title="Add an app" />
      {state.status === 'loading' ? (
        <FactsSkeleton title="Where the app is" rows={2} />
      ) : state.status === 'denied' ? (
        <Denied heading="Apps are the owner’s to manage">
          You can give people access to apps from their page in People, but only {me?.operatorDisplayName ?? 'the owner'} adds an app.
        </Denied>
      ) : (
        <LoadFailed what="The app" message={state.message} onRetry={retry} />
      )}
    </Page>
  );
}
