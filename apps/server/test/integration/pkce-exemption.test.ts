import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Browser, ISSUER, NATIVE_CALLBACK, NATIVE_CLIENT, RP_CALLBACK, startHarness, WEB_CLIENT, type Harness } from './oidc-harness.js';

// ADR-002: the conformance PKCE exemption applies to the named clients and nobody else.
let h: Harness;

beforeAll(async () => {
  h = await startHarness({ pkceExemptClientIds: [WEB_CLIENT.clientId] });
});

afterAll(async () => {
  await h.close();
});

function authUrl(clientId: string, redirectUri: string): string {
  const url = new URL(`${ISSUER}/oidc/auth`);
  for (const [k, v] of Object.entries({ client_id: clientId, response_type: 'code', scope: 'openid', redirect_uri: redirectUri })) {
    url.searchParams.set(k, v);
  }
  return url.toString();
}

describe('conformance PKCE exemption (ADR-002)', () => {
  it('lets an exempt client start an authorization request without PKCE', async () => {
    const { response, leftTo } = await new Browser(h.opFetch).navigate(authUrl(WEB_CLIENT.clientId, RP_CALLBACK));
    expect(leftTo).toBeUndefined();
    expect(response.status).toBe(200);
    expect(await response.text()).toContain('name="password"');
  });

  it('still requires PKCE from every other client', async () => {
    const { leftTo } = await new Browser(h.opFetch).navigate(authUrl(NATIVE_CLIENT.clientId, NATIVE_CALLBACK));
    expect(leftTo?.searchParams.get('error')).toBe('invalid_request');
  });

  it('says so in the logs at boot', () => {
    expect(h.logLines.join('')).toMatch(/PKCE exemption active for conformance clients/);
  });
});
