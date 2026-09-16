import { randomBytes } from 'node:crypto';
import { AUDIT_EVENTS } from '../audit/events.js';
import type { AuditWriter } from '../audit/writer.js';
import type { Db } from '../db.js';
import type { SecretHasher } from '../security/hash.js';
import { diffManifest, type ExistingApp, type Manifest, type ManifestDiff } from './manifest.js';

// Registering and changing apps (T-3.1, REQ-046–REQ-048, REQ-054, REQ-055, REQ-015).
//
// Everything here writes to the App table, and the provider reads clients from that table on
// every authorization request — so a registration takes effect immediately, with no restart.
//
// Two rules are worth stating out loud. A client secret is generated here, hashed with Argon2id
// and shown exactly once; nothing in the system can print it again. And disabling an app is not
// a flag: its live tokens go too, or "disabled" would mean "disabled for people who sign in
// again later".

export interface AppSummary {
  id: string;
  clientId: string;
  name: string;
  description: string;
  clientType: string;
  enabled: boolean;
  /** Apps with no back-channel URI are *slow revoke*: nothing can push them a sign-out. */
  backchannelLogoutUri: string | null;
  rolesClaimName: string;
  redirectUris: string[];
  postLogoutRedirectUris: string[];
  roles: { key: string; displayName: string; description: string; sortOrder: number; isDefault: boolean; granted: number }[];
  people: number;
  createdAt: Date;
}

export interface Registered {
  app: AppSummary;
  /** Present only for a confidential app, and only at the moment it is created or rotated. */
  secret?: string;
  diff: ManifestDiff;
}

export class AppError extends Error {
  constructor(
    readonly code: 'not_found' | 'already_exists' | 'roles_in_use' | 'not_confidential',
    message: string,
    readonly detail?: unknown,
  ) {
    super(message);
    this.name = 'AppError';
  }
}

export interface Apps {
  list(): Promise<AppSummary[]>;
  get(clientId: string): Promise<AppSummary | undefined>;
  /** What this manifest would do, without doing it. */
  preview(manifest: Manifest): Promise<ManifestDiff>;
  register(input: { manifest: Manifest; actorUserId: string; ip?: string | undefined; userAgent?: string | undefined }): Promise<Registered>;
  update(input: {
    manifest: Manifest;
    actorUserId: string;
    /** Required when the diff would remove a role somebody holds (REQ-048). */
    confirmRoleRemoval?: boolean;
    ip?: string | undefined;
    userAgent?: string | undefined;
  }): Promise<Registered>;
  rotateSecret(input: { clientId: string; actorUserId: string; ip?: string | undefined }): Promise<{ secret: string }>;
  setEnabled(input: { clientId: string; enabled: boolean; actorUserId: string; ip?: string | undefined }): Promise<{ tokensRevoked: number }>;
  remove(input: { clientId: string; actorUserId: string; ip?: string | undefined }): Promise<{ tokensRevoked: number }>;
}

const newSecret = (): string => randomBytes(32).toString('base64url');

/** The shape the diff needs, including how many people hold each role. */
const EXISTING = {
  redirectUris: { select: { uri: true } },
  roles: {
    orderBy: { sortOrder: 'desc' },
    include: { _count: { select: { grantRoles: true } } },
  },
  _count: { select: { grants: true } },
} as const;

type AppRow = ExistingApp & {
  id: string;
  clientId: string;
  enabled: boolean;
  createdAt: Date;
  roles: { key: string; displayName: string; description: string; sortOrder: number; isDefault: boolean; _count: { grantRoles: number } }[];
  _count: { grants: number };
};

const summarise = (app: AppRow): AppSummary => ({
  id: app.id,
  clientId: app.clientId,
  name: app.name,
  description: app.description,
  clientType: app.clientType,
  enabled: app.enabled,
  backchannelLogoutUri: app.backchannelLogoutUri,
  rolesClaimName: app.rolesClaimName,
  redirectUris: app.redirectUris.map((row) => row.uri),
  postLogoutRedirectUris: app.postLogoutRedirectUris,
  roles: app.roles.map((role) => ({
    key: role.key,
    displayName: role.displayName,
    description: role.description,
    sortOrder: role.sortOrder,
    isDefault: role.isDefault,
    granted: role._count?.grantRoles ?? 0,
  })),
  people: app._count.grants,
  createdAt: app.createdAt,
});

export function createApps(deps: { db: Db; hasher: SecretHasher; audit: AuditWriter }): Apps {
  const { db, hasher, audit } = deps;

  const load = (clientId: string) => db.app.findUnique({ where: { clientId }, include: EXISTING });

  /** After a write the row is certainly there; this keeps the callers free of impossible branches. */
  const loadOrThrow = (clientId: string) => db.app.findUniqueOrThrow({ where: { clientId }, include: EXISTING });

  /**
   * Everything the provider issued to this app, gone (REQ-054).
   *
   * The payload table holds one row per artifact with the client id inside the JSON, so this is
   * one statement rather than a walk over six model kinds — and it cannot miss a kind somebody
   * adds later.
   */
  const revokeTokens = (clientId: string): Promise<number> =>
    db.$executeRaw`DELETE FROM oidc_payload WHERE payload->>'clientId' = ${clientId}`;

  /** Writes the manifest onto an app row, roles and redirect URIs included. */
  async function apply(manifest: Manifest, appId: string): Promise<void> {
    await db.$transaction(async (tx) => {
      await tx.app.update({
        where: { id: appId },
        data: {
          name: manifest.name,
          description: manifest.description,
          clientType: manifest.client_type,
          backchannelLogoutUri: manifest.backchannel_logout_uri ?? null,
          postLogoutRedirectUris: manifest.post_logout_redirect_uris,
          rolesClaimName: manifest.roles_claim_name,
        },
      });

      await tx.redirectUri.deleteMany({ where: { appId, uri: { notIn: manifest.redirect_uris } } });
      for (const uri of manifest.redirect_uris) {
        await tx.redirectUri.upsert({ where: { appId_uri: { appId, uri } }, create: { appId, uri }, update: {} });
      }

      const keys = manifest.roles.map((role) => role.key);
      // Grants on a removed role go with it (the caller has confirmed that by now).
      await tx.role.deleteMany({ where: { appId, key: { notIn: keys } } });
      // Highest first in the manifest, so the first entry sorts highest.
      const total = manifest.roles.length;
      for (const [index, role] of manifest.roles.entries()) {
        const data = { displayName: role.display, description: role.description, sortOrder: total - index, isDefault: role.default };
        await tx.role.upsert({ where: { appId_key: { appId, key: role.key } }, create: { appId, key: role.key, ...data }, update: data });
      }
    });
  }

  return {
    async list() {
      const apps = await db.app.findMany({ orderBy: { name: 'asc' }, include: EXISTING });
      return apps.map((app) => summarise(app));
    },

    async get(clientId) {
      const app = await load(clientId);
      return app ? summarise(app) : undefined;
    },

    async preview(manifest) {
      return diffManifest(manifest, await load(manifest.client_id));
    },

    async register({ manifest, actorUserId, ip, userAgent }) {
      if (await load(manifest.client_id)) {
        throw new AppError('already_exists', `An app with the client id "${manifest.client_id}" is already registered.`);
      }

      const secret = manifest.client_type === 'confidential_web' ? newSecret() : undefined;
      const created = await db.app.create({
        data: {
          clientId: manifest.client_id,
          name: manifest.name,
          description: manifest.description,
          clientType: manifest.client_type,
          clientSecretHash: secret ? await hasher.hash(secret) : null,
          backchannelLogoutUri: manifest.backchannel_logout_uri ?? null,
          postLogoutRedirectUris: manifest.post_logout_redirect_uris,
          rolesClaimName: manifest.roles_claim_name,
        },
      });
      await apply(manifest, created.id);

      await audit.write({
        event: AUDIT_EVENTS.appRegistered,
        actorUserId,
        targetType: 'app',
        targetId: created.id,
        ip,
        userAgent,
        detail: { clientId: manifest.client_id, roles: manifest.roles.map((role) => role.key) },
      });

      const app = summarise(await loadOrThrow(manifest.client_id));
      return { app, ...(secret ? { secret } : {}), diff: diffManifest(manifest, null) };
    },

    async update({ manifest, actorUserId, confirmRoleRemoval = false, ip, userAgent }) {
      const existing = await load(manifest.client_id);
      if (!existing) throw new AppError('not_found', `No app is registered with the client id "${manifest.client_id}".`);

      const diff = diffManifest(manifest, existing);
      if (diff.blocking.length > 0 && !confirmRoleRemoval) {
        throw new AppError(
          'roles_in_use',
          'That manifest removes a role somebody still holds. Confirm to remove it and their access with it.',
          diff.blocking,
        );
      }

      await apply(manifest, existing.id);
      await audit.write({
        event: AUDIT_EVENTS.appUpdated,
        actorUserId,
        targetType: 'app',
        targetId: existing.id,
        ip,
        userAgent,
        detail: {
          clientId: manifest.client_id,
          changed: diff.changed.map((change) => change.field),
          rolesAdded: diff.roles.added.map((role) => role.key),
          rolesRemoved: diff.roles.removed.map((role) => role.key),
        },
      });
      return { app: summarise(await loadOrThrow(manifest.client_id)), diff };
    },

    async rotateSecret({ clientId, actorUserId, ip }) {
      const app = await load(clientId);
      if (!app) throw new AppError('not_found', `No app is registered with the client id "${clientId}".`);
      if (app.clientType !== 'confidential_web') throw new AppError('not_confidential', 'Public apps have no client secret.');

      const secret = newSecret();
      await db.app.update({ where: { id: app.id }, data: { clientSecretHash: await hasher.hash(secret) } });
      await audit.write({
        event: AUDIT_EVENTS.appSecretRotated,
        actorUserId,
        targetType: 'app',
        targetId: app.id,
        ip,
        detail: { clientId },
      });
      // Shown once. Nothing here can print it again.
      return { secret };
    },

    async setEnabled({ clientId, enabled, actorUserId, ip }) {
      const app = await load(clientId);
      if (!app) throw new AppError('not_found', `No app is registered with the client id "${clientId}".`);

      await db.app.update({ where: { id: app.id }, data: { enabled } });
      const tokensRevoked = enabled ? 0 : await revokeTokens(clientId);
      await audit.write({
        event: enabled ? AUDIT_EVENTS.appEnabled : AUDIT_EVENTS.appDisabled,
        actorUserId,
        targetType: 'app',
        targetId: app.id,
        ip,
        detail: { clientId, tokensRevoked },
      });
      return { tokensRevoked };
    },

    async remove({ clientId, actorUserId, ip }) {
      const app = await load(clientId);
      if (!app) throw new AppError('not_found', `No app is registered with the client id "${clientId}".`);

      const tokensRevoked = await revokeTokens(clientId);
      await db.app.delete({ where: { id: app.id } });
      await audit.write({
        event: AUDIT_EVENTS.appRemoved,
        actorUserId,
        targetType: 'app',
        targetId: app.id,
        ip,
        detail: { clientId, tokensRevoked },
      });
      return { tokensRevoked };
    },
  };
}
