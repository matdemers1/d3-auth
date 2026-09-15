import type { Express } from 'express';
import type Provider from 'oidc-provider';
import { createApp } from './app.js';
import type { Config } from './config.js';
import { createDb, type Db } from './db.js';
import { devLoginRouter, INTERACTION_PREFIX } from './interaction/dev-login.js';
import { loadClients } from './oidc/clients.js';
import { loadSigningKeys } from './oidc/keys.js';
import { createProvider } from './oidc/provider.js';
import { createSecretHasher } from './security/hash.js';
import { createKekCrypto } from './security/kek.js';

export interface Service {
  app: Express;
  db: Db;
  provider: Provider;
  skippedClients: { clientId: string; reason: string }[];
  close(): Promise<void>;
}

type ServiceConfig = Pick<Config, 'ISSUER' | 'DATABASE_URL' | 'KEK' | 'PEPPER' | 'COOKIE_KEYS' | 'DEV_LOGIN_ENABLED'>;

export async function createService(config: ServiceConfig): Promise<Service> {
  const db = createDb(config.DATABASE_URL);
  const kek = createKekCrypto(config.KEK);
  const hasher = createSecretHasher(config.PEPPER);

  const keys = await loadSigningKeys(db, kek);
  const clients = await loadClients(db);
  const provider = createProvider({
    issuer: config.ISSUER,
    db,
    keys,
    clients: clients.metadata,
    clientSecretHashes: clients.secretHashes,
    hasher,
    cookieKeys: config.COOKIE_KEYS,
    interactionPath: (uid) => `${INTERACTION_PREFIX}/${uid}`,
  });

  const routers = config.DEV_LOGIN_ENABLED ? [devLoginRouter(provider, db, hasher)] : [];
  const app = createApp({ provider, routers });

  return {
    app,
    db,
    provider,
    skippedClients: clients.skipped,
    close: () => db.$disconnect(),
  };
}
