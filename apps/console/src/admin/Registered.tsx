import { Alert, Button, FormActions, Link, Page, PageHeader } from '@d3cloud/ui';
import { ArrowLeft } from 'lucide-react';
import type { Registration } from '../api';
import { icon } from '../shared/icons';
import { ConnectionSection, PresetSheetSection } from './connection';

// C-6, the end of registering: the one screen the client secret is ever shown on, with everything
// else the app needs beside it (REQ-142). The same screen for a preset and a pasted manifest — a
// preset adds the other app's own settings screen, first, because that is where the owner goes next.

export function Registered({ registration }: { registration: Registration }) {
  const { app, secret, connection } = registration;
  const detail = `/admin/apps/${encodeURIComponent(app.clientId)}`;

  return (
    <Page width="narrow">
      <PageHeader
        back={
          <Link variant="muted" href="/admin/apps">
            {icon(ArrowLeft, 14)}
            Apps
          </Link>
        }
        title={`${app.name} is registered`}
        description={connection.preset ? `Now paste these into ${app.name}, then give people access.` : 'Put these in the app, then give people access.'}
      />

      {secret ? (
        <Alert tone="warning" dynamic title="This is the only time the client secret is shown">
          Copy it into the app now. Nothing here can show it again — if it is lost, rotate it from the app’s page.
        </Alert>
      ) : (
        <Alert tone="info" title="No client secret">
          A native app holds no secret. It proves itself with PKCE instead.
        </Alert>
      )}

      {connection.preset ? <PresetSheetSection sheet={connection.preset} secretCopyable /> : null}
      <ConnectionSection
        connection={connection}
        secretCopyable
        {...(connection.preset
          ? { description: `The same values in D3 Auth’s words, for when ${app.name} asks for one differently.` }
          : {})}
      />

      <FormActions>
        <Button
          variant="primary"
          onClick={() => {
            window.location.assign(`${detail}#who-can-sign-in`);
          }}
        >
          Next: give people access
        </Button>
      </FormActions>
    </Page>
  );
}
