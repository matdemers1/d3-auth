import { destination, pino, stdSerializers, stdTimeFunctions, type DestinationStream, type Logger } from 'pino';

// Structured JSON to stdout (REQ-112). Logs never carry tokens, secrets, passwords or codes:
// sensitive keys are replaced wholesale, and string values are scrubbed for JWTs, bearer
// credentials, token-shaped values and credential query parameters, wherever they appear.

export type { Logger };

const REDACTED = '[redacted]';

const SENSITIVE_KEY_PARTS = ['password', 'passwd', 'secret', 'token', 'cookie', 'authorization', 'verifier', 'assertion', 'pepper', 'kek', 'otp', 'private', 'credential'];
const SENSITIVE_KEYS = new Set(['code', 'd', 'jwk', 'nonce', 'state', 'body']);
/** Identifiers that look token-shaped but are safe and useful to log. */
const SAFE_KEYS = new Set(['kid', 'kids', 'client_id', 'clientId', 'grantId', 'uid', 'sub', 'accountId', 'requestId']);

const JWT = /eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*/g;
const BEARER = /\b(Bearer|Basic|DPoP)\s+[A-Za-z0-9._~+/=-]+/gi;
const CREDENTIAL_PARAM = /([?&#;\s](?:code|token|access_token|refresh_token|id_token|id_token_hint|logout_token|code_verifier|client_secret|password|state|nonce)=)[^&#\s"']+/gi;
const TOKEN_SHAPED = /(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{40,}(?![A-Za-z0-9_-])/g;

export function scrubString(value: string): string {
  return value
    .replace(JWT, '[jwt]')
    .replace(BEARER, `$1 ${REDACTED}`)
    .replace(CREDENTIAL_PARAM, `$1${REDACTED}`)
    .replace(TOKEN_SHAPED, REDACTED);
}

function isSensitiveKey(key: string): boolean {
  const lower = key.toLowerCase();
  return SENSITIVE_KEYS.has(lower) || lower.endsWith('_code') || SENSITIVE_KEY_PARTS.some((part) => lower.includes(part));
}

export function scrub(value: unknown, key = '', depth = 0): unknown {
  if (key && SAFE_KEYS.has(key)) return value;
  if (key && isSensitiveKey(key)) return REDACTED;
  if (typeof value === 'string') return scrubString(value);
  if (depth > 8 || value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map((item) => scrub(item, '', depth + 1));
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) return REDACTED;
  return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, scrub(v, k, depth + 1)]));
}

export function createLogger(options: { level?: string; destination?: DestinationStream } = {}): Logger {
  return pino(
    {
      level: options.level ?? 'info',
      base: { service: 'd3auth' },
      timestamp: stdTimeFunctions.isoTime,
      messageKey: 'msg',
      formatters: {
        level: (label) => ({ level: label }),
        log: (object) => scrub(object) as Record<string, unknown>,
      },
      serializers: {
        err: (err: Error) => scrub(stdSerializers.err(err)) as ReturnType<typeof stdSerializers.err>,
      },
      hooks: {
        logMethod(args, method) {
          const scrubbed = args.map((arg) => (typeof arg === 'string' ? scrubString(arg) : arg)) as Parameters<typeof method>;
          method.apply(this, scrubbed);
        },
      },
    },
    options.destination ?? destination(1),
  );
}
