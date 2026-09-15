import { describe, expect, it } from 'vitest';
import { createLogger, scrub, scrubString } from '../../src/log.js';

const JWT = 'eyJhbGciOiJFUzI1NiIsImtpZCI6ImFiYyJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlLXZhbHVlLWhlcmU';
const OPAQUE = 'x7kP2mQ9vR4tY8wZ1aB3cD5eF6gH0iJ2kL4mN6oP8qR';

function capture(): { lines: string[]; logger: ReturnType<typeof createLogger> } {
  const lines: string[] = [];
  const logger = createLogger({ level: 'trace', destination: { write: (line: string) => { lines.push(line); } } });
  return { lines, logger };
}

describe('log scrubber (REQ-112)', () => {
  it('replaces sensitive keys wholesale', () => {
    const out = scrub({
      password: 'hunter2hunter2',
      client_secret: 'client-secret-value',
      access_token: OPAQUE,
      refreshToken: OPAQUE,
      code: 'short-code-value',
      code_verifier: 'pkce-verifier-value',
      headers: { authorization: 'Basic Zm9vOmJhcg==', cookie: '__Host-d3auth_session=cookie-value' },
      KEK: 'k',
      totpSecret: 'JBSWY3DPEHPK3PXP',
    });
    expect(JSON.stringify(out)).not.toMatch(/hunter2|client-secret-value|short-code-value|pkce-verifier-value|Zm9v|cookie-value|JBSWY3DPEHPK3PXP/);
    expect(JSON.stringify(out)).not.toContain(OPAQUE);
  });

  it('scrubs token-shaped values inside ordinary strings', () => {
    const text = `callback https://rp.test/cb?code=${OPAQUE}&state=s1&iss=x with ${JWT} and Bearer ${OPAQUE}`;
    const out = scrubString(text);
    expect(out).not.toContain(OPAQUE);
    expect(out).not.toContain(JWT);
    expect(out).not.toContain('state=s1');
    expect(out).toContain('iss=x');
  });

  it('keeps safe identifiers such as kid and client_id', () => {
    expect(scrub({ kid: OPAQUE, client_id: 'web-app', status: 200 })).toEqual({ kid: OPAQUE, client_id: 'web-app', status: 200 });
  });

  it('never writes a secret through the logger, including in errors and messages', () => {
    const { lines, logger } = capture();
    logger.info({ tokens: { id_token: JWT }, detail: `refresh ${OPAQUE}` }, `issued ${JWT}`);
    logger.error({ err: new Error(`token endpoint rejected Basic ${OPAQUE}`) }, 'failure');
    const output = lines.join('\n');
    expect(output).not.toContain(JWT);
    expect(output).not.toContain(OPAQUE);
    expect(lines).toHaveLength(2);
    const [first] = lines;
    expect(JSON.parse(first ?? '{}')).toMatchObject({ level: 'info', service: 'd3auth' });
  });
});
