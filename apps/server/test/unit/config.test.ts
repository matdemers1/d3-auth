import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { ConfigError, loadConfig } from '../../src/config.js';

const b64 = (n = 32): string => randomBytes(n).toString('base64');

const validEnv = (): NodeJS.ProcessEnv => ({
  ISSUER: 'https://auth.d3cloud.io',
  DATABASE_URL: 'postgresql://d3auth:d3auth@127.0.0.1:5432/d3auth',
  KEK: b64(),
  PEPPER: b64(),
  COOKIE_KEYS: `${b64()},${b64()}`,
});

function problems(env: NodeJS.ProcessEnv): string[] {
  try {
    loadConfig(env);
  } catch (err) {
    if (err instanceof ConfigError) return err.problems;
    throw err;
  }
  return [];
}

describe('config', () => {
  it('accepts a complete environment', () => {
    const config = loadConfig(validEnv());
    expect(config.KEK).toHaveLength(32);
    expect(config.COOKIE_KEYS).toHaveLength(2);
    expect(config.NODE_ENV).toBe('production');
  });

  it.each(['KEK', 'PEPPER', 'COOKIE_KEYS'])('refuses to start without %s', (name) => {
    const env = { ...validEnv(), [name]: undefined };
    expect(problems(env).join('\n')).toMatch(new RegExp(`${name} is required`));
  });

  it('refuses a short KEK', () => {
    expect(problems({ ...validEnv(), KEK: b64(16) }).join()).toMatch(/KEK must be base64 encoding exactly 32 bytes/);
  });

  it('refuses a weak cookie key', () => {
    expect(problems({ ...validEnv(), COOKIE_KEYS: `${b64()},short` }).join()).toMatch(/COOKIE_KEYS/);
  });

  it('refuses a pepper that reuses the KEK', () => {
    const env = validEnv();
    expect(problems({ ...env, PEPPER: env.KEK }).join()).toMatch(/must not reuse the KEK/);
  });

  it('refuses an http issuer unless explicitly allowed for a local host', () => {
    expect(problems({ ...validEnv(), ISSUER: 'http://localhost:3000' }).join()).toMatch(/must use https/);
    expect(problems({ ...validEnv(), ISSUER: 'http://localhost:3000', INSECURE_HTTP_ISSUER: 'true' })).toEqual([]);
    expect(
      problems({ ...validEnv(), ISSUER: 'http://auth.d3cloud.io', INSECURE_HTTP_ISSUER: 'true' }).join(),
    ).toMatch(/only allowed for localhost/);
  });

  it('refuses the dev login on a real issuer', () => {
    expect(problems({ ...validEnv(), DEV_LOGIN_ENABLED: 'true' }).join()).toMatch(/DEV_LOGIN_ENABLED/);
    expect(problems({ ...validEnv(), ISSUER: 'https://op.d3auth.test', DEV_LOGIN_ENABLED: 'true' })).toEqual([]);
  });

  it('boot exits non-zero with a clear message when KEK is missing', () => {
    const env = validEnv();
    delete env.KEK;
    const entry = fileURLToPath(new URL('../../src/index.ts', import.meta.url));
    const tsx = fileURLToPath(new URL('../../node_modules/.bin/tsx', import.meta.url));
    const result = spawnSync(tsx, [entry], {
      env: { PATH: process.env.PATH, ...env },
      encoding: 'utf8',
      timeout: 15_000,
    });
    expect(result.status).not.toBe(0);
    expect(result.stderr).toMatch(/Refusing to start/);
    expect(result.stderr).toMatch(/KEK is required/);
  });
});
