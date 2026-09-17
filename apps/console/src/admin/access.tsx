import { Button, Cluster, DataList, DataListRow, EmptyState } from '@d3cloud/ui';
import { AppWindow } from 'lucide-react';
import type { App } from '../api';
import { icon } from '../shared/icons';

// The grants editor a person's page and a group's page share: every app, whether this one reaches
// it, and the roles it has there. Access is deny-by-default (REQ-051), so this list is where
// somebody stops being locked out of everything.
//
// Roles are toggle buttons (`aria-pressed`), not a primary/secondary pair: "on" is a state, and a
// screen reader should say "Administrator, toggle button, pressed" rather than guess from a colour.

export interface Grant {
  clientId: string;
  name: string;
  roles: string[];
}

interface Props {
  /** Every enabled app, when the viewer may list them (the owner). Empty for an admin. */
  apps: App[];
  grants: Grant[];
  busy: boolean;
  /** Called with the complete role list the grant should have; `[]` gives access with no roles. */
  onGrant: (app: { clientId: string; name: string }, roles: string[], said: string) => void;
  onRevoke: (app: { clientId: string; name: string }) => void;
  /** What to say once it is done: "Administrator given.", "Editors can reach Bindery." */
  say: { role: (role: string, on: boolean) => string; given: (app: string) => string };
  label: string;
  emptyHeading: string;
  emptyText: string;
}

export function AccessList({ apps, grants, busy, onGrant, onRevoke, say, label, emptyHeading, emptyText }: Props) {
  const granted = new Map(grants.map((grant) => [grant.clientId, grant.roles]));
  // An admin cannot list apps, but still sees — and can revoke — the access that exists.
  const rows: { clientId: string; name: string; roles: App['roles'] | null }[] =
    apps.length > 0 ? apps.map((app) => ({ clientId: app.clientId, name: app.name, roles: app.roles })) : grants.map((grant) => ({ ...grant, roles: null }));

  return (
    <DataList
      aria-label={label}
      empty={
        <EmptyState kind="empty" size="inline" headingLevel={3} heading={emptyHeading}>
          {emptyText}
        </EmptyState>
      }
    >
      {rows.map((app) => {
        const roles = granted.get(app.clientId);
        const hasAccess = roles !== undefined;
        return (
          <DataListRow
            key={app.clientId}
            truncate={false}
            leading={icon(AppWindow, 20)}
            title={app.name}
            description={hasAccess ? (roles.length > 0 ? `Roles: ${roles.join(', ')}` : 'Can sign in, with no roles') : 'No access'}
            actions={
              <Cluster gap="8" justify="end">
                {app.roles
                  ? app.roles.map((role) => {
                      const on = roles?.includes(role.key) ?? false;
                      return (
                        <Button
                          key={role.key}
                          size="sm"
                          pressed={on}
                          disabled={busy}
                          onClick={() => {
                            onGrant(
                              app,
                              on ? (roles ?? []).filter((key) => key !== role.key) : [...(roles ?? []), role.key],
                              say.role(role.displayName, on),
                            );
                          }}
                        >
                          {role.displayName}
                        </Button>
                      );
                    })
                  : null}
                {hasAccess ? (
                  <Button
                    size="sm"
                    variant="ghost"
                    disabled={busy}
                    onClick={() => {
                      onRevoke(app);
                    }}
                  >
                    Revoke
                  </Button>
                ) : (
                  <Button
                    size="sm"
                    disabled={busy}
                    onClick={() => {
                      onGrant(app, [], say.given(app.name));
                    }}
                  >
                    Give access
                  </Button>
                )}
              </Cluster>
            }
          />
        );
      })}
    </DataList>
  );
}
