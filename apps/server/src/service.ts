import type { Express } from 'express';
import type Provider from 'oidc-provider';
import { createApp } from './app.js';
import type { Config } from './config.js';
import { createDb, type Db } from './db.js';
import { databaseReadiness } from './health.js';
import type { Logger } from './log.js';
import { devLoginRouter, INTERACTION_PREFIX } from './interaction/dev-login.js';
import { loadClients } from './oidc/clients.js';
import { loadSigningKeys } from './oidc/keys.js';
import { createProvider } from './oidc/provider.js';
import { createSecretHasher } from './security/hash.js';
import { consoleBuilt, consoleRouter, defaultConsoleDist } from './static.js';
import { createKekCrypto } from './security/kek.js';

export interface Service {
  app: Express;
  db: Db;
  provider: Provider;
  close(): Promise<void>;
}

type ServiceConfig = Pick<Config, 'ISSUER' | 'DATABASE_URL' | 'KEK' | 'PEPPER' | 'COOKIE_KEYS' | 'DEV_LOGIN_ENABLED'> &
  Partial<Pick<Config, 'CONFORMANCE_PKCE_EXEMPT_CLIENTS'>> &
  Partial<Pick<Config, 'CONSOLE_DIST'>>;

const PROVIDER_ERROR_EVENTS = [
  'authorization.error',
  'grant.error',
  'end_session.error',
  'userinfo.error',
  'introspection.error',
  'revocation.error',
  'jwks.error',
  'discovery.error',
  'backchannel.error',
] as const;

export async function createService(config: ServiceConfig, logger: Logger): Promise<Service> {
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
    pkceExemptClientIds: config.CONFORMANCE_PKCE_EXEMPT_CLIENTS ?? [],
  });
  if (config.CONFORMANCE_PKCE_EXEMPT_CLIENTS?.length) {
    logger.warn({ clients: config.CONFORMANCE_PKCE_EXEMPT_CLIENTS }, 'PKCE exemption active for conformance clients — test issuers only');
  }

  provider.on('server_error', (ctx, err) => {
    logger.error({ err, route: ctx.oidc.route, client_id: ctx.oidc.client?.clientId }, 'provider server error');
  });
  for (const event of PROVIDER_ERROR_EVENTS) {
    // Every name here has the same (ctx, OIDCProviderError) listener signature.
    provider.on(event as 'grant.error', (ctx, err) => {
      logger.warn(
        { event, error: err.error, description: err.error_description, route: ctx.oidc.route, client_id: ctx.oidc.client?.clientId },
        'protocol error',
      );
    });
  }
  for (const skipped of clients.skipped) logger.warn(skipped, 'app not loaded');
  logger.info({ kids: keys.map((k) => k.kid), clients: clients.metadata.length }, 'provider ready');

  const consoleDist = config.CONSOLE_DIST ?? defaultConsoleDist();
  if (!consoleBuilt(consoleDist)) logger.warn({ consoleDist }, 'console build not found; /login, /account and /admin answer 503');

  const routers = [consoleRouter(consoleDist), ...(config.DEV_LOGIN_ENABLED ? [devLoginRouter(provider, db, hasher)] : [])];
  const app = createApp({ provider, routers, readiness: databaseReadiness(db), logger });

  return {
    app,
    db,
    provider,
    close: () => db.$disconnect(),
  };
}
