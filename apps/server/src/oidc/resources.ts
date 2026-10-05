import { effectiveAccess } from '../authz/effective-roles.js';
import type { Db } from '../db.js';

// RFC 8707 resource servers (AUTH-T-9.3, AUTH-ADR-008). Three kinds, and nothing else:
//
// - **listed** — `RESOURCE_SERVERS`, for resources that are not apps (Foreman's `/mcp`). Any client
//   may name one, as before.
// - **self** — D3 Auth's own issuer, the audience of its account and admin APIs for a native client.
// - **app** — the origin of an enabled app's `homeUrl`, read from the database on every request,
//   so registering an app makes its audience requestable without a restart.
//
// The last two are minted only for D3 Constellation's client (the `constellation` preset), and an
// app's audience only while the person holds a grant to that app. A resource that resolves to none
// of them is refused by the provider as `invalid_target` — never quietly granted.

/** The preset that builds D3 Constellation's client (AUTH-T-9.2). */
export const CONSTELLATION_PRESET = 'constellation';

export type ResolvedResource = { kind: 'listed' } | { kind: 'self' } | { kind: 'app'; clientId: string };

export interface ResourceRegistry {
  resolve(resource: string): Promise<ResolvedResource | null>;
  /** Whether this client may ask for a self or app resource: only D3 Constellation's. */
  mayMintForOthers(clientId: string): Promise<boolean>;
  /**
   * Whether `resource` may be granted to this client for this person. An app's resource needs the
   * person's own grant to that app — deny by default (REQ-051), for audiences as for sign-in.
   */
  allowed(resource: string, clientId: string, accountId: string | undefined): Promise<boolean>;
}

/** An origin, exactly: scheme, host and port, nothing after. Anything else is not a resource here. */
function originOf(value: string): string | null {
  try {
    return new URL(value).origin;
  } catch {
    return null;
  }
}

export function createResourceRegistry(db: Db, issuer: string, listed: readonly string[]): ResourceRegistry {
  const listedSet = new Set(listed);
  const self = issuer.replace(/\/+$/, '');

  const registry: ResourceRegistry = {
    async resolve(resource) {
      if (listedSet.has(resource)) return { kind: 'listed' };
      if (resource === self) return { kind: 'self' };
      // A resource is named by its origin and nothing else, so `https://bindery.example/x` or a
      // trailing slash is not Bindery's audience.
      if (originOf(resource) !== resource) return null;
      const apps = await db.app.findMany({ where: { enabled: true, homeUrl: { not: null } }, select: { clientId: true, homeUrl: true } });
      const app = apps.find((row) => row.homeUrl !== null && originOf(row.homeUrl) === resource);
      return app ? { kind: 'app', clientId: app.clientId } : null;
    },

    async mayMintForOthers(clientId) {
      const app = await db.app.findUnique({ where: { clientId }, select: { preset: true, enabled: true, clientType: true } });
      return app !== null && app.enabled && app.preset === CONSTELLATION_PRESET && app.clientType === 'public_native';
    },

    async allowed(resource, clientId, accountId) {
      const resolved = await registry.resolve(resource);
      if (resolved === null) return false;
      if (resolved.kind === 'listed') return true;
      if (!(await registry.mayMintForOthers(clientId))) return false;
      if (resolved.kind === 'self') return true;
      // Not yet known who is asking (the authorization request, before sign-in): the grant built
      // after sign-in is checked again, and so is every refresh.
      if (accountId === undefined) return true;
      return (await effectiveAccess(db, { userId: accountId, clientId: resolved.clientId })).hasGrant;
    },
  };
  return registry;
}
