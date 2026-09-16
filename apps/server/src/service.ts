import type { Express } from 'express';
import type Provider from 'oidc-provider';
import { createApp } from './app.js';
import { createInvites, type Invites } from './admin/invites.js';
import { createApps, type Apps } from './admin/apps.js';
import { createGrants, type Grants } from './authz/grants.js';
import { adminRouter } from './admin/routes.js';
import { createAuditWriter } from './audit/writer.js';
import { accountRouter } from './account/routes.js';
import { createConsoleAuth } from './console/auth.js';
import type { Config } from './config.js';
import { createDb, type Db } from './db.js';
import { cached, databaseReadiness, type ReadinessProbe } from './health.js';
import { inviteRouter } from './interaction/invite-routes.js';
import { interactionRouter, loginPath } from './interaction/routes.js';
import { recordSessions } from './interaction/sessions.js';
import type { Logger } from './log.js';
import { createAdapterFactory } from './oidc/adapter.js';
import { describeClients } from './oidc/clients.js';
import { loadSigningKeys } from './oidc/keys.js';
import { createProvider, deviceCookieNameFor } from './oidc/provider.js';
import { createSecretHasher } from './security/hash.js';
import { createKekCrypto } from './security/kek.js';
import { createMailAdapter, type MailAdapter } from './mail/adapter.js';
import { logDriver } from './mail/log-driver.js';
import { smtpDriver } from './mail/smtp.js';
import { workerRelayDriver } from './mail/worker-relay.js';
import { createPasswordVerifier, type PasswordVerifier } from './security/password.js';
import { createThrottle } from './security/throttle.js';
import { createTotp, type Totp } from './security/totp.js';
import { createSessionControl } from './security/sessions.js';
import { createTrustedDevices, type TrustedDevices } from './security/trusted-device.js';
import { createWebAuthn, type WebAuthn } from './security/webauthn.js';
import { createFirstRunSetup } from './setup/first-run.js';
import { createRecovery, type Recovery } from './setup/recovery.js';
import { setupRouter } from './setup/routes.js';
import { consoleBuilt, consoleRouter, defaultConsoleDist, unavailableGate } from './static.js';

export interface Service {
  app: Express;
  db: Db;
  provider: Provider;
  readiness: ReadinessProbe;
  mail: MailAdapter;
  invites: Invites;
  apps: Apps;
  grants: Grants;
  totp: Totp;
  webauthn: WebAuthn;
  trustedDevices: TrustedDevices;
  recovery: Recovery;
  close(): Promise<void>;
}

/** Picks the mail driver from configuration, falling back to the log so nothing silently fails. */
function buildMail(config: ServiceConfig, logger: Logger): MailAdapter {
  const from: string = config.MAIL_FROM ?? 'no-reply@localhost';
  const relayUrl = config.MAIL_RELAY_URL;
  const relaySecret = config.MAIL_RELAY_SECRET;
  const smtpUrl = config.SMTP_URL;
  if (config.MAIL_DRIVER === 'worker' && relayUrl && relaySecret) {
    return createMailAdapter(workerRelayDriver({ url: relayUrl, secret: relaySecret, from }), logger);
  }
  if (config.MAIL_DRIVER === 'smtp' && smtpUrl) {
    return createMailAdapter(smtpDriver({ url: smtpUrl, from }), logger);
  }
  if (config.MAIL_DRIVER !== 'log') {
    logger.warn({ driver: config.MAIL_DRIVER }, 'mail is not configured; invites will show a link to copy instead');
  }
  return createMailAdapter(logDriver(logger), logger);
}

type ServiceConfig = Pick<Config, 'ISSUER' | 'DATABASE_URL' | 'KEK' | 'PEPPER' | 'COOKIE_KEYS'> &
  Partial<
    Pick<
      Config,
      | 'CONSOLE_DIST'
      | 'CONFORMANCE_PKCE_EXEMPT_CLIENTS'
      | 'OPERATOR_DISPLAY_NAME'
      | 'MAIL_DRIVER'
      | 'MAIL_RELAY_URL'
      | 'MAIL_RELAY_SECRET'
      | 'MAIL_FROM'
      | 'SMTP_URL'
    >
  >;

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
  const provider = createProvider({
    issuer: config.ISSUER,
    db,
    keys,
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
  // Apps are served from the table per request; this is a boot-time report, not a load.
  const clients = await describeClients(db);
  for (const skipped of clients.skipped) logger.warn(skipped, 'app cannot be served');
  logger.info({ kids: keys.map((k) => k.kid), clients: clients.served.length }, 'provider ready');

  const operatorDisplayName = config.OPERATOR_DISPLAY_NAME ?? 'the operator';
  const mail = buildMail(config, logger);
  const consoleAuth = createConsoleAuth(db, adapterFactory, config.ISSUER.startsWith('https://'));
  const issuerUrl = new URL(config.ISSUER);
  const totp = createTotp(db, kek, operatorDisplayName === 'the operator' ? issuerUrl.host : `${operatorDisplayName} (D3 Auth)`);
  // The RP ID is the bare host and can never change without orphaning every passkey (REQ-034).
  const webauthn = createWebAuthn(db, adapterFactory, {
    rpId: issuerUrl.hostname,
    rpName: `${operatorDisplayName === 'the operator' ? 'D3 Auth' : operatorDisplayName} sign-in`,
    origin: issuerUrl.origin,
  });
  const secureCookies = config.ISSUER.startsWith('https://');
  const trustedDevices = createTrustedDevices(db);
  const sessionControl = createSessionControl(db, provider);
  const deviceCookieName = deviceCookieNameFor(secureCookies);
  const apps = createApps({ db, hasher, audit });
  const grants = createGrants({ db, audit });
  const invites = createInvites({
    db,
    mail,
    hasher,
    audit,
    template: { operatorDisplayName, issuer: config.ISSUER },
  });

  const recovery = createRecovery({
    db,
    adapterFactory,
    audit,
    sessions: sessionControl,
    trustedDevices,
    issuer: config.ISSUER,
  });

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
        totp,
        webauthn,
        trustedDevices,
        recovery,
        deviceCookieName,
        secureCookies,
        operatorDisplayName,
        consoleDist,
      }),
      inviteRouter({ invites, consoleDist, operatorDisplayName }),
      accountRouter({ db, sessions: sessionControl, auth: consoleAuth, hasher, passwords, throttle, totp, webauthn, trustedDevices, deviceCookieName, audit }),
      adminRouter({ db, apps, grants, operatorDisplayName, auth: consoleAuth, invites, sessions: sessionControl, trustedDevices, audit }),
      setupRouter({ setup, consoleDist, operatorDisplayName }),
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
    mail,
    invites,
    apps,
    grants,
    totp,
    webauthn,
    trustedDevices,
    recovery,
    close: () => db.$disconnect(),
  };
}
