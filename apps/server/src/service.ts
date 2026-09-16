import type { Express } from 'express';
import type Provider from 'oidc-provider';
import { createApp } from './app.js';
import { createAuditWriter } from './audit/writer.js';
import type { Config } from './config.js';
import { createDb, type Db } from './db.js';
import { cached, databaseReadiness, type ReadinessProbe } from './health.js';
import { interactionRouter, loginPath } from './interaction/routes.js';
import { recordSessions } from './interaction/sessions.js';
import type { Logger } from './log.js';
import { createAdapterFactory } from './oidc/adapter.js';
import { loadClients } from './oidc/clients.js';
import { loadSigningKeys } from './oidc/keys.js';
import { createProvider } from './oidc/provider.js';
import { createSecretHasher } from './security/hash.js';
import { createKekCrypto } from './security/kek.js';
import { createPasswordVerifier, type PasswordVerifier } from './security/password.js';
import { createThrottle } from './security/throttle.js';
import { createFirstRunSetup } from './setup/first-run.js';
import { setupRouter } from './setup/routes.js';
import { consoleBuilt, consoleRouter, defaultConsoleDist, unavailableGate } from './static.js';

export interface Service {
  app: Express;
  db: Db;
  provider: Provider;
  readiness: ReadinessProbe;
  close(): Promise<void>;
}

type ServiceConfig = Pick<Config, 'ISSUER' | 'DATABASE_URL' | 'KEK' | 'PEPPER' | 'COOKIE_KEYS'> &
  Partial<Pick<Config, 'CONSOLE_DIST' | 'CONFORMANCE_PKCE_EXEMPT_CLIENTS' | 'OPERATOR_DISPLAY_NAME'>>;

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

/** Seams the tests use to watch or stub a dependency. Production passes nothing. */
export interface ServiceOverrides {
  passwords?: (real: PasswordVerifier) => PasswordVerifier;
}

export async function createService(config: ServiceConfig, logger: Logger, overrides: ServiceOverrides = {}): Promise<Service> {
  const db = createDb(config.DATABASE_URL);
  const kek = createKekCrypto(config.KEK);
  const hasher = createSecretHasher(config.PEPPER);
  const realPasswords = await createPasswordVerifier(hasher);
  const passwords = overrides.passwords ? overrides.passwords(realPasswords) : realPasswords;
  const throttle = createThrottle(db);
  const audit = createAuditWriter(db, logger);
  const adapterFactory = createAdapterFactory(db);

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
    interactionPath: loginPath,
    pkceExemptClientIds: config.CONFORMANCE_PKCE_EXEMPT_CLIENTS ?? [],
    operatorDisplayName: config.OPERATOR_DISPLAY_NAME ?? 'D3 Auth',
    secureCookies: config.ISSUER.startsWith('https://'),
  });

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
  recordSessions(provider, db, audit, logger);
  const consoleDist = config.CONSOLE_DIST ?? defaultConsoleDist();
  if (!consoleBuilt(consoleDist)) logger.warn({ consoleDist }, 'console build not found; /login, /account and /admin answer 503');
  if (config.CONFORMANCE_PKCE_EXEMPT_CLIENTS?.length) {
    logger.warn({ clients: config.CONFORMANCE_PKCE_EXEMPT_CLIENTS }, 'PKCE exemption active for conformance clients — test issuers only');
  }
  for (const skipped of clients.skipped) logger.warn(skipped, 'app not loaded');
  logger.info({ kids: keys.map((k) => k.kid), clients: clients.metadata.length }, 'provider ready');

  // An instance with no accounts can be claimed once, from the browser, with the code logged here.
  const setup = createFirstRunSetup(db, adapterFactory, hasher, audit, logger);
  await setup.prepare();

  const readiness = cached(databaseReadiness(db));
  const app = createApp({
    provider,
    routers: [
      interactionRouter({
        provider,
        adapterFactory,
        db,
        passwords,
        throttle,
        audit,
        logger,
        operatorDisplayName: config.OPERATOR_DISPLAY_NAME ?? 'the operator',
        consoleDist,
      }),
      setupRouter({ setup, consoleDist, operatorDisplayName: config.OPERATOR_DISPLAY_NAME ?? 'the operator' }),
      consoleRouter(consoleDist),
    ],
    beforeRouters: [unavailableGate(readiness)],
    readiness,
    logger,
    hsts: config.ISSUER.startsWith('https://'),
  });

  return {
    app,
    db,
    provider,
    readiness,
    close: () => db.$disconnect(),
  };
}
