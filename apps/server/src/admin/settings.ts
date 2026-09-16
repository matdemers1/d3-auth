import { z } from 'zod';
import { AUDIT_EVENTS } from '../audit/events.js';
import type { AuditWriter } from '../audit/writer.js';
import type { Db } from '../db.js';
import type { KekCrypto } from '../security/kek.js';

// Settings the operator can change without a deploy (REQ-071).
//
// Two rules shape this file. A secret never lives in `value`: the relay token and the SMTP URL
// (which carries a password) are sealed under the KEK, so exporting settings or reading the table
// gives nothing away. And the environment is the floor, not the ceiling — an instance with mail
// configured in its environment keeps working with no settings at all, and a setting overrides it
// only once somebody sets one.

export const MAIL_KEY = 'mail';
export const ALERTS_KEY = 'alerts';
export const LIFETIMES_KEY = 'lifetimes';

export const mailSettingsSchema = z.object({
  driver: z.enum(['worker', 'smtp', 'log']),
  from: z.email().optional(),
  /** Worker relay endpoint. Its bearer token is the sealed half. */
  relayUrl: z.url().optional(),
  /** SMTP URL *without* credentials; the whole URL is sealed when it carries any. */
  smtpHost: z.string().optional(),
});

export const alertSettingsSchema = z.object({
  /** Who hears about a readiness failure or a mail outage. */
  recipients: z.array(z.email()).max(10).default([]),
});

export const lifetimeSettingsSchema = z.object({
  /** How long "don't ask on this browser" lasts (REQ-036). */
  trustedDeviceDays: z.number().int().min(1).max(365).default(30),
  /** How long an idle SSO session survives. */
  sessionDays: z.number().int().min(1).max(365).default(30),
});

export type MailSettings = z.output<typeof mailSettingsSchema>;
export type AlertSettings = z.output<typeof alertSettingsSchema>;
export type LifetimeSettings = z.output<typeof lifetimeSettingsSchema>;

export interface SettingsView {
  mail: (MailSettings & { secretSet: boolean }) | null;
  alerts: AlertSettings;
  lifetimes: LifetimeSettings;
  /** What the environment provides, so a screen can say "already configured at the container". */
  fromEnvironment: { mailDriver: string | null; mailConfigured: boolean };
}

export interface Settings {
  view(): Promise<SettingsView>;
  /** The resolved mail configuration: settings first, environment second. */
  mail(): Promise<(MailSettings & { secret?: string | undefined }) | null>;
  lifetimes(): Promise<LifetimeSettings>;
  alerts(): Promise<AlertSettings>;
  setMail(input: { settings: MailSettings; secret?: string | undefined; actorUserId: string; ip?: string | undefined }): Promise<void>;
  setAlerts(input: { settings: AlertSettings; actorUserId: string; ip?: string | undefined }): Promise<void>;
  setLifetimes(input: { settings: LifetimeSettings; actorUserId: string; ip?: string | undefined }): Promise<void>;
}

export interface SettingsDeps {
  db: Db;
  kek: KekCrypto;
  audit: AuditWriter;
  /** Mail configuration from the container, used when no setting overrides it. */
  environment: { mailDriver?: string | undefined; from?: string | undefined; relayUrl?: string | undefined; relaySecret?: string | undefined; smtpUrl?: string | undefined };
}

const sealContext = (key: string): string => `setting:${key}`;

export function createSettings({ db, kek, audit, environment }: SettingsDeps): Settings {
  const read = async <T>(key: string, schema: z.ZodType<T>): Promise<{ value: T; secret?: string } | null> => {
    const row = await db.setting.findUnique({ where: { key } });
    if (!row) return null;
    const parsed = schema.safeParse(row.value);
    if (!parsed.success) return null;
    return {
      value: parsed.data,
      ...(row.secretEncrypted ? { secret: kek.decrypt(row.secretEncrypted, sealContext(key)).toString('utf8') } : {}),
    };
  };

  const write = async (key: string, value: unknown, secret: string | undefined, actorUserId: string, ip?: string): Promise<void> => {
    const data = {
      value: JSON.parse(JSON.stringify(value)) as object,
      // Undefined leaves an existing secret alone; an empty string clears it.
      ...(secret === undefined ? {} : { secretEncrypted: secret === '' ? null : kek.encrypt(Buffer.from(secret, 'utf8'), sealContext(key)) }),
      updatedById: actorUserId,
    };
    await db.setting.upsert({ where: { key }, create: { key, ...data }, update: data });
    await audit.write({
      event: AUDIT_EVENTS.settingsChanged,
      actorUserId,
      targetType: 'app',
      targetId: key,
      ip,
      // The value can carry a hostname but never the secret, which is why this is safe to log.
      detail: { key, value },
    });
  };

  return {
    async view() {
      const [mail, alerts, lifetimes] = await Promise.all([
        read(MAIL_KEY, mailSettingsSchema),
        read(ALERTS_KEY, alertSettingsSchema),
        read(LIFETIMES_KEY, lifetimeSettingsSchema),
      ]);
      return {
        mail: mail ? { ...mail.value, secretSet: mail.secret !== undefined } : null,
        alerts: alerts?.value ?? alertSettingsSchema.parse({}),
        lifetimes: lifetimes?.value ?? lifetimeSettingsSchema.parse({}),
        fromEnvironment: {
          mailDriver: environment.mailDriver ?? null,
          mailConfigured: Boolean((environment.relayUrl && environment.relaySecret) || environment.smtpUrl),
        },
      };
    },

    async mail() {
      const stored = await read(MAIL_KEY, mailSettingsSchema);
      if (stored) {
        return { ...stored.value, ...(stored.secret ? { secret: stored.secret } : {}) };
      }
      // Nothing set: fall back to whatever the container was given.
      if (!environment.mailDriver) return null;
      const driver = mailSettingsSchema.shape.driver.safeParse(environment.mailDriver);
      if (!driver.success) return null;
      return {
        driver: driver.data,
        ...(environment.from ? { from: environment.from } : {}),
        ...(environment.relayUrl ? { relayUrl: environment.relayUrl } : {}),
        ...(environment.smtpUrl ? { smtpHost: environment.smtpUrl } : {}),
        ...(environment.relaySecret ?? environment.smtpUrl ? { secret: environment.relaySecret ?? environment.smtpUrl } : {}),
      };
    },

    async lifetimes() {
      return (await read(LIFETIMES_KEY, lifetimeSettingsSchema))?.value ?? lifetimeSettingsSchema.parse({});
    },

    async alerts() {
      return (await read(ALERTS_KEY, alertSettingsSchema))?.value ?? alertSettingsSchema.parse({});
    },

    setMail: ({ settings, secret, actorUserId, ip }) => write(MAIL_KEY, settings, secret, actorUserId, ip),
    setAlerts: ({ settings, actorUserId, ip }) => write(ALERTS_KEY, settings, undefined, actorUserId, ip),
    setLifetimes: ({ settings, actorUserId, ip }) => write(LIFETIMES_KEY, settings, undefined, actorUserId, ip),
  };
}
