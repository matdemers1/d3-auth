import { z } from 'zod';

// The app manifest (REQ-046, REQ-047). An app is registered by pasting this, or by the seed file
// in T-4.6 — never by a form that invents roles of its own.
//
// The manifest is the app's own description of itself: what it is called, where it may be sent
// back to, and which roles it understands. Roles are declared here and nowhere else, so the
// console cannot grant somebody a role the app has never heard of.

/** Client ids appear in URLs, logs and token audiences, so they stay short and boring. */
const CLIENT_ID = /^[a-z0-9][a-z0-9._-]{1,63}$/;

/**
 * Redirect URIs are matched exactly, never by pattern (REQ-005). The rules below are the ones an
 * exact match cannot save you from: a fragment silently changes what the browser sends back, and
 * plain http on a real host is somebody's authorization code travelling in the clear.
 */
function checkRedirectUri(value: string, native: boolean, at: z.RefinementCtx): void {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    at.addIssue({ code: 'custom', message: `${value} is not an absolute URL.` });
    return;
  }
  if (value.includes('*')) {
    at.addIssue({ code: 'custom', message: `${value} contains a wildcard. Redirect URIs are matched exactly.` });
  }
  if (url.hash) {
    at.addIssue({ code: 'custom', message: `${value} has a fragment. Drop everything from the "#".` });
  }
  const loopback = url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '[::1]';
  if (url.protocol === 'https:') return;
  if (native && (url.protocol !== 'http:' || loopback)) return;
  if (url.protocol === 'http:' && loopback) return;
  at.addIssue({
    code: 'custom',
    message: native
      ? `${value} must be https, a loopback http address, or the app's own scheme.`
      : `${value} must be https (or http on localhost for development).`,
  });
}

const roleSchema = z.object({
  key: z.string().regex(/^[a-z0-9][a-z0-9._-]{0,31}$/, 'Role keys are lower-case: letters, numbers, dot, dash or underscore.'),
  display: z.string().min(1),
  description: z.string().default(''),
  /** Suggested when an admin grants access for the first time. Not applied automatically. */
  default: z.boolean().default(false),
});

export const manifestSchema = z
  .object({
    client_id: z.string().regex(CLIENT_ID, 'Client ids are 2–64 characters: lower-case letters, numbers, dot, dash or underscore.'),
    name: z.string().min(1),
    description: z.string().default(''),
    client_type: z.enum(['confidential_web', 'public_native']),
    redirect_uris: z.array(z.string().min(1)).min(1, 'An app needs at least one redirect URI.'),
    post_logout_redirect_uris: z.array(z.string().min(1)).default([]),
    /** Absent means the app cannot be told to sign somebody out — the console calls that *slow revoke*. */
    backchannel_logout_uri: z.string().min(1).optional(),
    roles: z.array(roleSchema).default([]),
  })
  .superRefine((manifest, at) => {
    const native = manifest.client_type === 'public_native';
    for (const uri of manifest.redirect_uris) checkRedirectUri(uri, native, at);
    for (const uri of manifest.post_logout_redirect_uris) checkRedirectUri(uri, native, at);
    if (manifest.backchannel_logout_uri) checkRedirectUri(manifest.backchannel_logout_uri, false, at);

    const keys = manifest.roles.map((role) => role.key);
    const duplicate = keys.find((key, index) => keys.indexOf(key) !== index);
    if (duplicate) at.addIssue({ code: 'custom', message: `The role "${duplicate}" is declared twice.` });
  });

export type Manifest = z.output<typeof manifestSchema>;

export interface ManifestProblem {
  field: string;
  message: string;
}

export type ParseResult = { ok: true; manifest: Manifest } | { ok: false; problems: ManifestProblem[] };

/** Parses a pasted manifest into something the rest of the system can trust, or says why not. */
export function parseManifest(input: unknown): ParseResult {
  const parsed = manifestSchema.safeParse(input);
  if (parsed.success) return { ok: true, manifest: parsed.data };
  return {
    ok: false,
    problems: parsed.error.issues.map((issue) => ({
      field: issue.path.join('.') || 'manifest',
      message: issue.message,
    })),
  };
}

export interface RoleChange {
  key: string;
  display: string;
  /** How many people hold this role right now. Removing one that is in use needs confirmation. */
  granted?: number;
}

export interface ManifestDiff {
  /** True when this manifest would create the app rather than change it. */
  isNew: boolean;
  changed: { field: string; from: string; to: string }[];
  redirectUris: { added: string[]; removed: string[] };
  roles: { added: RoleChange[]; removed: RoleChange[]; changed: RoleChange[] };
  /** Roles that would be removed while somebody still holds them (REQ-048). */
  blocking: RoleChange[];
}

export interface ExistingApp {
  name: string;
  description: string;
  clientType: string;
  backchannelLogoutUri: string | null;
  postLogoutRedirectUris: string[];
  redirectUris: { uri: string }[];
  roles: { key: string; displayName: string; description: string; sortOrder: number; isDefault: boolean; _count?: { grantRoles: number } }[];
}

const listDiff = (before: readonly string[], after: readonly string[]) => ({
  added: after.filter((value) => !before.includes(value)),
  removed: before.filter((value) => !after.includes(value)),
});

/**
 * What re-registering this manifest would do (REQ-048).
 *
 * The part that matters is `blocking`: a role that disappears from a manifest takes its grants
 * with it, and people would silently lose access they were given deliberately. So a removal that
 * is in use is reported rather than applied, and the caller has to say it meant it.
 */
export function diffManifest(manifest: Manifest, existing: ExistingApp | null): ManifestDiff {
  if (!existing) {
    return {
      isNew: true,
      changed: [],
      redirectUris: { added: manifest.redirect_uris, removed: [] },
      roles: { added: manifest.roles.map((role) => ({ key: role.key, display: role.display })), removed: [], changed: [] },
      blocking: [],
    };
  }

  const changed: ManifestDiff['changed'] = [];
  const compare = (field: string, from: string, to: string): void => {
    if (from !== to) changed.push({ field, from, to });
  };
  compare('name', existing.name, manifest.name);
  compare('description', existing.description, manifest.description);
  compare('client_type', existing.clientType, manifest.client_type);
  compare('backchannel_logout_uri', existing.backchannelLogoutUri ?? '', manifest.backchannel_logout_uri ?? '');
  compare('post_logout_redirect_uris', existing.postLogoutRedirectUris.join(' '), manifest.post_logout_redirect_uris.join(' '));

  const before = new Map(existing.roles.map((role) => [role.key, role]));
  const after = new Map(manifest.roles.map((role) => [role.key, role]));

  const added = manifest.roles.filter((role) => !before.has(role.key)).map((role) => ({ key: role.key, display: role.display }));
  const removed: (RoleChange & { granted: number })[] = existing.roles
    .filter((role) => !after.has(role.key))
    .map((role) => ({ key: role.key, display: role.displayName, granted: role._count?.grantRoles ?? 0 }));
  const roleChanged = manifest.roles
    .filter((role) => {
      const was = before.get(role.key);
      return was !== undefined && (was.displayName !== role.display || was.description !== role.description);
    })
    .map((role) => ({ key: role.key, display: role.display }));

  return {
    isNew: false,
    changed,
    redirectUris: listDiff(
      existing.redirectUris.map((row) => row.uri),
      manifest.redirect_uris,
    ),
    roles: { added, removed, changed: roleChanged },
    blocking: removed.filter((role) => role.granted > 0),
  };
}
