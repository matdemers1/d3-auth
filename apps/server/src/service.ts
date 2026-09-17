import { signinRouter } from './console/signin.js';
import type { Express } from 'express';
import type Provider from 'oidc-provider';
import { createApp } from './app.js';
import { createInvites, type Invites } from './admin/invites.js';
import { createApps, type Apps } from './admin/apps.js';
import { createGrants, type Grants } from './authz/grants.js';
import { createGroups, type Groups } from './admin/groups.js';
import { adminRouter } from './admin/routes.js';
import { AUDIT_EVENTS } from './audit/events.js';
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
import { keysRouter } from './oidc/keys-routes.js';
import { createProvider, deviceCookieNameFor } from './oidc/provider.js';
import { DEFAULT_IDLE_DAYS } from './oidc/session-lifetime.js';
import { createSecretHasher } from './security/hash.js';
import { createKekCrypto } from './security/kek.js';
import type { MailAdapter } from './mail/adapter.js';
import { mailFromSettings } from './mail/from-settings.js';
import { createSettings, type Settings } from './admin/settings.js';
import { createPasswordVerifier, type PasswordVerifier } from './security/password.js';
import { registerInstanceWords } from './security/policy.js';
import { createThrottle } from './security/throttle.js';
import { createTotp, type Totp } from './security/totp.js';
import { createBackchannel, installSignOutDelivery, type Backchannel } from './oidc/backchannel.js';
import { revokeTokens, revokeTokensIfNoAccess } from './oidc/revoke-tokens.js';
import { createSessionControl, type SessionControl } from './security/sessions.js';
import { createTrustedDevices, type TrustedDevices } from './security/trusted-device.js';
import { createWebAuthn, type WebAuthn } from './security/webauthn.js';
import { seedOnBoot } from './boot/seed.js';
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
  groups: Groups;
  settings: Settings;
  totp: Totp;
  webauthn: WebAuthn;
  trustedDevices: TrustedDevices;
  recovery: Recovery;
  backchannel: Backchannel;
  sessions: SessionControl;
  close(): Promise<void>;
}

/** Picks the mail driver from configuration, falling back to the log so nothing silently fails. */
type ServiceConfig = Pick<Config, 'ISSUER' | 'DATABASE_URL' | 'KEK' | 'PEPPER' | 'COOKIE_KEYS'> &
  Partial<
    Pick<
      Config,
      | 'CONSOLE_DIST'
      | 'BACKUP_S3_BUCKET'
      | 'CONFORMANCE_PKCE_EXEMPT_CLIENTS'
      | 'OPERATOR_DISPLAY_NAME'
      | 'MAIL_DRIVER'
      | 'MAIL_RELAY_URL'
      | 'MAIL_RELAY_SECRET'
      | 'MAIL_FROM'
      | 'SMTP_URL'
      | 'SEED_FILE'
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

  // Before anything reads the App table: a mounted seed file declares what should exist (REQ-057).
  if (config.SEED_FILE) await seedOnBoot(db, config.SEED_FILE, { logger, audit });

  const keys = await loadSigningKeys(db, kek);
  // The idle session lifetime comes from Settings, which the provider reads synchronously; this keeps
  // a current copy (refreshed below, once settings exist) rather than making every save a query.
  let sessionIdleDays = DEFAULT_IDLE_DAYS;
  // Hoisted as a function so Settings, created further down, can call it when lifetimes change.
  async function refreshLifetimes(): Promise<void> {
    sessionIdleDays = (await settings.lifetimes()).sessionDays;
  }
  const consoleDist = config.CONSOLE_DIST ?? defaultConsoleDist();
  const provider = createProvider({
    consoleDist,
    sessionIdleDays: () => sessionIdleDays,
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
  // A refresh token presented twice (REQ-009) is either a bug or a stolen token. The provider has
  // already revoked the grant; this makes it an audit row, which the alert rules watch (REQ-114).
  provider.on('grant.error', (ctx, err) => {
    // The client is told only "grant request is invalid"; the reason lives in error_detail.
    if ((err as { error_detail?: string }).error_detail !== 'refresh token already used') return;
    const grant = ctx.oidc.entities.Grant as { accountId?: string } | undefined;
    void audit
      .write({
        event: AUDIT_EVENTS.tokenRefreshReused,
        actorUserId: grant?.accountId ?? null,
        targetType: 'app',
        targetId: ctx.oidc.client?.clientId ?? null,
        ip: ctx.get('cf-connecting-ip') || ctx.ip,
        detail: { clientId: ctx.oidc.client?.clientId },
      })
      .catch((writeErr: unknown) => {
        logger.error({ err: writeErr }, 'could not record a refresh token reuse');
      });
  });
  recordSessions(provider, db, audit, logger);
  if (!consoleBuilt(consoleDist)) logger.warn({ consoleDist }, 'console build not found; /login, /account and /admin answer 503');
  if (config.CONFORMANCE_PKCE_EXEMPT_CLIENTS?.length) {
    logger.warn({ clients: config.CONFORMANCE_PKCE_EXEMPT_CLIENTS }, 'PKCE exemption active for conformance clients — test issuers only');
  }
  // Apps are served from the table per request; this is a boot-time report, not a load.
  const clients = await describeClients(db);
  for (const skipped of clients.skipped) logger.warn(skipped, 'app cannot be served');
  logger.info({ kids: keys.map((k) => k.kid), clients: clients.served.length }, 'provider ready');

  const operatorDisplayName = config.OPERATOR_DISPLAY_NAME ?? 'the operator';
  const settings = createSettings({
    db,
    kek,
    audit,
    onLifetimesChanged: () => refreshLifetimes(),
    environment: {
      mailDriver: config.MAIL_DRIVER,
      from: config.MAIL_FROM,
      relayUrl: config.MAIL_RELAY_URL,
      relaySecret: config.MAIL_RELAY_SECRET,
      smtpUrl: config.SMTP_URL,
    },
  });
  await refreshLifetimes();
  const lifetimeTimer = setInterval(() => void refreshLifetimes().catch(() => undefined), 30_000);
  lifetimeTimer.unref();
  // Resolved per send, so changing it in the console takes effect without a deploy (REQ-071).
  const mail = mailFromSettings(settings, logger, (failure) =>
    audit.write({ event: AUDIT_EVENTS.mailFailed, detail: failure }).catch(() => undefined),
  );
  const consoleAuth = createConsoleAuth(db, adapterFactory, config.ISSUER.startsWith('https://'), new URL(config.ISSUER).origin);
  const issuerUrl = new URL(config.ISSUER);
  // A password built on this instance's own names is as guessable as one built on the product's
  // (ASVS 6.2.11). Short host labels like "auth" are left out: they would refuse "author".
  registerInstanceWords([
    operatorDisplayName === 'the operator' ? '' : operatorDisplayName,
    ...issuerUrl.hostname.split('.').slice(0, -1).filter((label) => label.length >= 6),
  ]);
  const totp = createTotp(db, kek, operatorDisplayName === 'the operator' ? issuerUrl.host : `${operatorDisplayName} (D3 Auth)`);
  // The RP ID is the bare host and can never change without orphaning every passkey (REQ-034).
  const webauthn = createWebAuthn(db, adapterFactory, {
    rpId: issuerUrl.hostname,
    rpName: `${operatorDisplayName === 'the operator' ? 'D3 Auth' : operatorDisplayName} sign-in`,
    origin: issuerUrl.origin,
  });
  const secureCookies = config.ISSUER.startsWith('https://');
  // The lifetime is read when a device is trusted, so changing it in the console applies next
  // time somebody says "don't ask again" rather than needing a deploy.
  const trustedDevices = createTrustedDevices(db, async () => (await settings.lifetimes()).trustedDeviceDays);
  const issuerHost = new URL(config.ISSUER).hostname;
  const testIssuer = issuerHost === 'localhost' || issuerHost.endsWith('.test');
  const backchannel = createBackchannel({
    provider,
    audit,
    logger,
    // `.test` is reserved for testing (RFC 6761) and localhost is not the internet: an issuer on
    // either is a development or test instance, where the apps live on loopback.
    allowPrivateEndpoints: testIssuer,
  });
  installSignOutDelivery(provider, backchannel, audit, testIssuer);
  const sessionControl = createSessionControl(db, provider, backchannel);
  const deviceCookieName = deviceCookieNameFor(secureCookies);
  const apps = createApps({ db, hasher, audit });
  const groups = createGroups({
    db,
    audit,
    // A group that changes is access that changes, for everybody in it (REQ-056).
    onAccessChanged: async ({ userIds, clientIds, reason }) => {
      for (const userId of userIds) {
        for (const clientId of clientIds) {
          await backchannel.notify({ userId, clientId, reason });
          // Only for people the change actually left without access (REQ-051).
          await revokeTokensIfNoAccess(db, userId, clientId);
        }
      }
    },
  });
  const grants = createGrants({
    db,
    audit,
    // A grant that changed is access that changed, so the app hears about it now rather than
    // when its tokens happen to expire (REQ-056).
    onChanged: async ({ userId, clientId, reason }) => {
      await backchannel.notify({ userId, clientId, reason: `grant_${reason}` });
      // A revoked grant takes its tokens with it: an app ignoring the logout still cannot use them.
      if (reason === 'revoked') await revokeTokens(db, userId, clientId);
    },
  });
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
        sessions: sessionControl,
        deviceCookieName,
        secureCookies,
        issuer: config.ISSUER,
        operatorDisplayName,
        consoleDist,
      }),
      keysRouter({
        db,
        kek,
        requireOwner: consoleAuth.requireOwner,
        requireFreshOwner: consoleAuth.requireFreshOwner,
        loadedKids: keys.map((key) => key.kid),
      }),
      inviteRouter({ invites, consoleDist, operatorDisplayName }),
      accountRouter({ db, grants, sessions: sessionControl, auth: consoleAuth, hasher, passwords, throttle, totp, webauthn, trustedDevices, deviceCookieName, audit }),
      adminRouter({ db, issuer: config.ISSUER, apps, grants, groups, settings, mail, operatorDisplayName, auth: consoleAuth, invites, sessions: sessionControl, trustedDevices, audit, readiness, backupsConfigured: Boolean(config.BACKUP_S3_BUCKET) }),
      setupRouter({ setup, consoleDist, operatorDisplayName }),
      signinRouter({ issuer: config.ISSUER, auth: consoleAuth, secureCookies, consoleDist }),
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
    groups,
    settings,
    totp,
    webauthn,
    trustedDevices,
    recovery,
    backchannel,
    sessions: sessionControl,
    close: () => db.$disconnect(),
  };
}
