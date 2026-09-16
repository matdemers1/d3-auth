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
    /** Conformance-suite clients only: the OpenID Basic plan does not send PKCE. Refused on real issuers. */
    CONFORMANCE_PKCE_EXEMPT_CLIENTS: z
      .string()
      .optional()
      .transform((v) => (v ?? '').split(',').map((c) => c.trim()).filter(Boolean)),
    MAIL_RELAY_URL: z.url().optional().or(z.literal('')),
    S3_ENDPOINT: z.url().optional().or(z.literal('')),
    S3_REGION: z.string().optional(),
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
