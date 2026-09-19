import * as client from 'openid-client';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { authorize, RP_CALLBACK, startHarness, webClientConfig, type Harness } from './oidc-harness.js';

/**
 * RFC 8707 resource indicators (Foreman ADR-013).
 *
 * Turned on for one consumer: Foreman's remote MCP endpoint, which as an OAuth 2.1 resource server
 * **MUST** reject any token not issued for it. That check is only possible if the token names its
 * audience, so a token requested for a resource comes back as a **JWT with `aud`** rather than the
 * opaque string every other grant still gets.
 *
 * The allowlist is the part worth testing hardest. Without it a client could ask for a token
 * audienced at any string it liked, and every resource server in the ecosystem would be one
 * careless audience check away from accepting it.
 */

const FOREMAN = 'https://foreman.d3cloud.io/mcp';

let h: Harness;
let config: client.Configuration;

beforeAll(async () => {
  h = await startHarness({ resourceServers: [FOREMAN] });
  config = await webClientConfig(h);
});

afterAll(async () => {
  await h.close();
});

const decode = (jwt: string): Record<string, unknown> =>
  JSON.parse(Buffer.from(jwt.split('.')[1] ?? '', 'base64url').toString('utf8')) as Record<
    string,
    unknown
  >;

async function tokensFor(resource?: string): Promise<client.TokenEndpointResponse> {
  const extra = resource === undefined ? {} : { resource };
  const { callback, verifier, state, nonce } = await authorize(h, config, extra);
  return client.authorizationCodeGrant(
    config,
    callback,
    { pkceCodeVerifier: verifier, expectedState: state, expectedNonce: nonce },
    resource === undefined ? {} : { resource },
  );
}

describe('resource indicators', () => {
  it('issues a JWT access token audienced at the resource that was asked for', async () => {
    const tokens = await tokensFor(FOREMAN);

    // Three segments: the whole point. An opaque token carries no audience, so a resource server
    // has nothing to check and must fall back to introspection on every single request.
    expect(tokens.access_token.split('.')).toHaveLength(3);

    const claims = decode(tokens.access_token);
    expect(claims['aud']).toBe(FOREMAN);
    expect(claims['iss']).toBe(config.serverMetadata().issuer);
  });

  it('leaves a request that names no resource exactly as it was', async () => {
    const tokens = await tokensFor();

    // Nothing that exists today changes shape underneath it: `defaultResource` returns undefined,
    // so the console and every current relying party keep their opaque tokens.
    expect(tokens.access_token.split('.')).not.toHaveLength(3);
  });

  it('refuses a resource that is not on the allowlist', async () => {
    // The load-bearing assertion. An attacker who can start a normal sign-in must not be able to
    // mint a token audienced at somebody else's resource server.
    await expect(tokensFor('https://not-foreman.example.com/mcp')).rejects.toThrow();
  });

  it('refuses an audience that merely looks like the allowed one', async () => {
    // Exact string match, not a prefix or a host comparison: these are the shapes a near-miss
    // takes, and each one is a different resource server.
    for (const near of [
      'https://foreman.d3cloud.io/mcp/',
      'https://foreman.d3cloud.io',
      'https://foreman.d3cloud.io/mcp/../mcp',
      'https://foreman.d3cloud.io.evil.example/mcp',
    ]) {
      await expect(tokensFor(near), near).rejects.toThrow();
    }
  });

  it('does not let the resource token stand in for an ID token', async () => {
    const tokens = await tokensFor(FOREMAN);
    const access = decode(tokens.access_token);

    // An access token audienced at a resource server is not a credential for the client, and the
    // two must not be confusable: the ID token is audienced at the client instead.
    expect(access['aud']).not.toBe(RP_CALLBACK);
    expect(tokens.id_token).toBeDefined();
    expect(decode(tokens.id_token ?? '')['aud']).not.toBe(FOREMAN);
  });
});
