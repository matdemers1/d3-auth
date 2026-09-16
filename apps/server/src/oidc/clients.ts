import { createHash } from 'node:crypto';
import type { Adapter, ClientMetadata } from 'oidc-provider';
import type Provider from 'oidc-provider';
import type { Db } from '../db.js';
import type { SecretHasher } from '../security/hash.js';

// Where the provider's clients come from: the App table, looked up per request (T-3.1).
//
// They used to be a list built at boot, which meant registering an app needed a restart of the
// service every other app signs in through. `oidc-provider` falls back to the `Client` adapter
// for any client it has no static entry for, so serving that adapter from our own table makes
// registration take effect immediately. The provider caches by a hash of the metadata, so a
// changed manifest is picked up and an unchanged one costs nothing.
//
// Secrets are hashed at rest (REQ-015) but `oidc-provider` compares them in plaintext, so every
// confidential client carries a placeholder `client_secret` derived from its hash — stable, so
// the provider's cache works, and useless, because `compareClientSecret` below is what actually
// decides. Symmetric signing algorithms are disabled, so the placeholder is never used as a key.

export interface AppClient {
  clientId: string;
  name: string;
  clientType: string;
  clientSecretHash: string | null;
  postLogoutRedirectUris: string[];
  backchannelLogoutUri: string | null;
  redirectUris: { uri: string }[];
}

/** A value that changes when the secret changes and reveals nothing about it. */
const placeholderSecret = (hash: string): string => createHash('sha256').update(`client-secret-placeholder:${hash}`).digest('base64url');

export type ClientResult = { ok: true; metadata: ClientMetadata } | { ok: false; reason: string };

/** The provider's view of one app row, or why that app cannot be served. */
export function clientMetadataFor(app: AppClient): ClientResult {
  const redirectUris = app.redirectUris.map((row) => row.uri);
  if (redirectUris.length === 0) return { ok: false, reason: 'no redirect URIs' };

  const common: ClientMetadata = {
    client_id: app.clientId,
    client_name: app.name,
    redirect_uris: redirectUris,
    post_logout_redirect_uris: app.postLogoutRedirectUris,
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    // The code comes back in the query string and nowhere else. form_post and fragment responses are
    // refused per client: nothing here uses them, and form_post is the one mode that would need the
    // provider's pages to allow a form to post off-site (T-5.4).
    response_modes: ['query'],
    id_token_signed_response_alg: 'ES256',
    ...(app.backchannelLogoutUri ? { backchannel_logout_uri: app.backchannelLogoutUri, backchannel_logout_session_required: true } : {}),
  };

  if (app.clientType === 'public_native') {
    return { ok: true, metadata: { ...common, application_type: 'native', token_endpoint_auth_method: 'none' } };
  }
  if (!app.clientSecretHash) return { ok: false, reason: 'confidential app has no client secret' };

  return {
    ok: true,
    metadata: {
      ...common,
      application_type: 'web',
      token_endpoint_auth_method: 'client_secret_basic',
      client_secret: placeholderSecret(app.clientSecretHash),
    },
  };
}

const APP_SELECT = {
  clientId: true,
  name: true,
  clientType: true,
  clientSecretHash: true,
  postLogoutRedirectUris: true,
  backchannelLogoutUri: true,
  redirectUris: { select: { uri: true } },
} as const;

/**
 * The `Client` kind of the provider's storage. Only `find` is meaningful: clients are registered
 * through the console (REQ-046), never by the provider itself — dynamic registration is off.
 */
export function createClientAdapter(db: Db): Adapter {
  const unsupported = (): Promise<undefined> => Promise.resolve(undefined);
  return {
    async find(clientId: string) {
      // A disabled app is not a client at all, so its authorizations fail at the door (REQ-054).
      const app = await db.app.findFirst({ where: { clientId, enabled: true }, select: APP_SELECT });
      if (!app) return undefined;
      const result = clientMetadataFor(app);
      return result.ok ? result.metadata : undefined;
    },
    upsert: () => Promise.resolve(),
    findByUserCode: unsupported,
    findByUid: unsupported,
    consume: () => Promise.resolve(),
    destroy: () => Promise.resolve(),
    revokeByGrantId: () => Promise.resolve(),
  };
}

/** Boot-time sanity, for the log only: which apps the provider will and will not serve. */
export async function describeClients(db: Db): Promise<{ served: string[]; skipped: { clientId: string; reason: string }[] }> {
  const apps = await db.app.findMany({ where: { enabled: true }, select: APP_SELECT });
  const served: string[] = [];
  const skipped: { clientId: string; reason: string }[] = [];
  for (const app of apps) {
    const result = clientMetadataFor(app);
    if (result.ok) served.push(app.clientId);
    else skipped.push({ clientId: app.clientId, reason: result.reason });
  }
  return { served, skipped };
}

/** Replaces the plaintext secret comparison with an Argon2id verify against the stored hash. */
export function installHashedClientSecrets(provider: Provider, db: Db, hasher: SecretHasher): void {
  provider.Client.prototype.compareClientSecret = async function compareClientSecret(actual: string) {
    const app = await db.app.findFirst({ where: { clientId: this.clientId, enabled: true }, select: { clientSecretHash: true } });
    return app?.clientSecretHash ? hasher.verify(app.clientSecretHash, actual) : false;
  };
}
