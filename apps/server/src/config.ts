import { z } from 'zod';

// Fail-fast configuration (REQ-117, REQ-024). Boot never proceeds on a missing or weak secret.

export class ConfigError extends Error {
  constructor(readonly problems: string[]) {
    super(`Refusing to start — configuration is invalid:\n  - ${problems.join('\n  - ')}`);
    this.name = 'ConfigError';
  }
}

const base64Bytes = (name: string, min: number, exact = false) =>
  z
    .string({ error: `${name} is required (generate with: openssl rand -base64 32)` })
    .trim()
    .min(1, `${name} is required (generate with: openssl rand -base64 32)`)
    .transform((value, ctx) => {
      const bytes = Buffer.from(value, 'base64');
      const canonical = bytes.toString('base64').replace(/=+$/, '') === value.replace(/=+$/, '');
      const sizeOk = exact ? bytes.length === min : bytes.length >= min;
      if (!canonical || !sizeOk) {
        ctx.addIssue({
          code: 'custom',
          message: `${name} must be base64 encoding ${exact ? 'exactly' : 'at least'} ${min} bytes`,
        });
        return z.NEVER;
      }
      return bytes;
    });

const flag = z
  .enum(['true', 'false', '1', '0', ''])
  .optional()
  .transform((v) => v === 'true' || v === '1');

const localIssuerHost = (host: string): boolean =>
  host === 'localhost' || host === '127.0.0.1' || host.endsWith('.test');

const schema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('production'),
    ISSUER: z
      .url({ error: 'ISSUER must be an absolute URL, e.g. https://auth.d3cloud.io' })
      .refine((v) => !v.endsWith('/'), 'ISSUER must not end with a slash'),
    INSECURE_HTTP_ISSUER: flag,
    PORT: z.coerce.number().int().min(1).max(65535).default(3000),
    DATABASE_URL: z.string({ error: 'DATABASE_URL is required' }).min(1, 'DATABASE_URL is required'),
    KEK: base64Bytes('KEK', 32, true),
    PEPPER: base64Bytes('PEPPER', 32),
    COOKIE_KEYS: z
      .string({ error: 'COOKIE_KEYS is required (comma-separated, first is current)' })
      .min(1, 'COOKIE_KEYS is required (comma-separated, first is current)')
      .transform((value, ctx) => {
        const keys = value.split(',').map((k) => k.trim()).filter(Boolean);
        if (keys.length === 0 || keys.some((k) => Buffer.from(k, 'base64').length < 32)) {
          ctx.addIssue({ code: 'custom', message: 'COOKIE_KEYS entries must each be base64 of at least 32 bytes' });
          return z.NEVER;
        }
        return keys;
      }),
    LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),
    OPERATOR_DISPLAY_NAME: z.string().default('the operator'),
    CONSOLE_DIST: z.string().optional(),
    /** A mounted state file applied on every boot, idempotently (REQ-057). */
    SEED_FILE: z.string().optional(),
    /** Where the pre-migration dump and, later, backup bundles are written. */
    BACKUP_DIR: z.string().default('/backups'),
    /** Conformance-suite clients only: the OpenID Basic plan does not send PKCE. Refused on real issuers. */
    CONFORMANCE_PKCE_EXEMPT_CLIENTS: z
      .string()
      .optional()
      .transform((v) => (v ?? '').split(',').map((c) => c.trim()).filter(Boolean)),
    /**
     * Resource servers that may be named in an RFC 8707 `resource` parameter, comma-separated.
     * An allowlist: a client may only obtain an audience-bound token for a URI listed here, and
     * unset leaves resource indicators off entirely. First consumer is Foreman's remote MCP
     * endpoint (Foreman ADR-013), e.g. `https://foreman.d3cloud.io/mcp`.
     */
    RESOURCE_SERVERS: z
      .string()
      .optional()
      .transform((v) => (v ?? '').split(',').map((r) => r.trim()).filter(Boolean)),
    MAIL_DRIVER: z.enum(['worker', 'smtp', 'log']).default('log'),
    MAIL_FROM: z.string().optional(),
    MAIL_RELAY_SECRET: z.string().optional(),
    MAIL_RELAY_URL: z.url().optional().or(z.literal('')),
    SMTP_URL: z.string().optional(),
    // Offsite backups (T-6.1, ADR-004). Unset bucket means no offsite copy — the service still runs,
    // and the alert rules say so. AWS credentials come from AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY.
    BACKUP_S3_BUCKET: z.string().optional().transform((v) => v || undefined),
    BACKUP_S3_REGION: z.string().default('us-east-1'),
    BACKUP_KMS_KEY_ID: z.string().optional().transform((v) => v || undefined),
    /** Only for S3-compatible stores in testing. */
    BACKUP_S3_ENDPOINT: z.url().optional().or(z.literal('')).transform((v) => v || undefined),
    /** UTC times of day, HH:MM. The drill follows the backup it restores. */
    BACKUP_AT: z.string().regex(/^([01]\d|2[0-3]):[0-5]\d$/, 'BACKUP_AT is HH:MM in UTC').default('02:30'),
    DRILL_AT: z.string().regex(/^([01]\d|2[0-3]):[0-5]\d$/, 'DRILL_AT is HH:MM in UTC').default('03:30'),
  })
  .superRefine((env, ctx) => {
    const issuer = new URL(env.ISSUER);
    if (issuer.protocol !== 'https:' && !(issuer.protocol === 'http:' && env.INSECURE_HTTP_ISSUER)) {
      ctx.addIssue({ code: 'custom', path: ['ISSUER'], message: 'ISSUER must use https (set INSECURE_HTTP_ISSUER=true only for local testing)' });
    }
    if (env.INSECURE_HTTP_ISSUER && !localIssuerHost(issuer.hostname)) {
      ctx.addIssue({ code: 'custom', path: ['INSECURE_HTTP_ISSUER'], message: 'INSECURE_HTTP_ISSUER is only allowed for localhost or *.test issuers' });
    }
    if (env.CONFORMANCE_PKCE_EXEMPT_CLIENTS.length > 0 && !issuer.hostname.endsWith('.test')) {
      ctx.addIssue({ code: 'custom', path: ['CONFORMANCE_PKCE_EXEMPT_CLIENTS'], message: 'CONFORMANCE_PKCE_EXEMPT_CLIENTS is only allowed for *.test issuers' });
    }
    if (env.BACKUP_S3_BUCKET && !env.BACKUP_KMS_KEY_ID) {
      ctx.addIssue({ code: 'custom', path: ['BACKUP_KMS_KEY_ID'], message: 'BACKUP_KMS_KEY_ID is required with BACKUP_S3_BUCKET: bundles are always written under a named key' });
    }
    if (env.PEPPER.equals(env.KEK)) {
      ctx.addIssue({ code: 'custom', path: ['PEPPER'], message: 'PEPPER must not reuse the KEK' });
    }
  });

export type Config = z.output<typeof schema>;

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const parsed = schema.safeParse(env);
  if (!parsed.success) {
    throw new ConfigError(
      parsed.error.issues.map((issue) => {
        const key = issue.path.join('.');
        return issue.message.startsWith(key) || key === '' ? issue.message : `${key}: ${issue.message}`;
      }),
    );
  }
  return parsed.data;
}
