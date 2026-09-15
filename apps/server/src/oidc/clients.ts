import { randomBytes } from 'node:crypto';
import type { ClientMetadata } from 'oidc-provider';
import type Provider from 'oidc-provider';
import type { Db } from '../db.js';
import type { SecretHasher } from '../security/hash.js';

// Static client list loaded from APP rows at boot (P0). T-3.1 moves this to live registration.
//
// oidc-provider compares client secrets in plaintext, but secrets are hashed at rest (REQ-015).
// Each confidential client therefore gets a random, never-stored placeholder `client_secret`
// (the schema requires one), and the comparison is replaced with an Argon2id verify.
// Symmetric algorithms are disabled, so the placeholder is never used as a key.

export interface LoadedClients {
  metadata: ClientMetadata[];
  secretHashes: ReadonlyMap<string, string>;
  /** Apps left out because they cannot work; one broken app must not take sign-in down for the rest. */
  skipped: { clientId: string; reason: string }[];
}

export async function loadClients(db: Db): Promise<LoadedClients> {
  const apps = await db.app.findMany({ where: { enabled: true }, include: { redirectUris: true } });
  const secretHashes = new Map<string, string>();
  const skipped: LoadedClients['skipped'] = [];
  const metadata: ClientMetadata[] = [];

  for (const app of apps) {
    const common: ClientMetadata = {
      client_id: app.clientId,
      client_name: app.name,
      redirect_uris: app.redirectUris.map((r) => r.uri),
      post_logout_redirect_uris: app.postLogoutRedirectUris,
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      id_token_signed_response_alg: 'ES256',
    };

    if (common.redirect_uris?.length === 0) {
      skipped.push({ clientId: app.clientId, reason: 'no redirect URIs' });
      continue;
    }
    if (app.clientType === 'public_native') {
      metadata.push({ ...common, application_type: 'native', token_endpoint_auth_method: 'none' });
      continue;
    }
    if (!app.clientSecretHash) {
      skipped.push({ clientId: app.clientId, reason: 'confidential app has no client secret' });
      continue;
    }
    secretHashes.set(app.clientId, app.clientSecretHash);
    metadata.push({
      ...common,
      application_type: 'web',
      token_endpoint_auth_method: 'client_secret_basic',
      client_secret: randomBytes(32).toString('base64url'),
    });
  }

  return { metadata, secretHashes, skipped };
}

export function installHashedClientSecrets(
  provider: Provider,
  secretHashes: ReadonlyMap<string, string>,
  hasher: SecretHasher,
): void {
  provider.Client.prototype.compareClientSecret = async function compareClientSecret(actual: string) {
    const hash = secretHashes.get(this.clientId);
    return hash ? hasher.verify(hash, actual) : false;
  };
}
