// Rule tests for .semgrep/d3auth.yml. Run: semgrep --test .semgrep/
import { decodeJwt, jwtVerify } from 'jose';
import * as oidc from 'openid-client';

declare const token: string, keys: never, config: never, url: URL, claims: { email: string }, accounts: { email: string }[], db: never;

// ruleid: d3auth.jwt-verify-without-algorithms
await jwtVerify(token, keys);
// ruleid: d3auth.jwt-verify-without-algorithms
await jwtVerify(token, keys, { issuer: 'x' });
// ok: d3auth.jwt-verify-without-algorithms
await jwtVerify(token, keys, { issuer: 'x', algorithms: ['ES256', 'RS256'] });

// ruleid: d3auth.unverified-jwt-decode
const unverified = decodeJwt(token);

// ruleid: d3auth.code-grant-without-state-or-nonce
await oidc.authorizationCodeGrant(config, url, { pkceCodeVerifier: 'v' });
// ruleid: d3auth.code-grant-without-state-or-nonce
await oidc.authorizationCodeGrant(config, url, { pkceCodeVerifier: 'v', expectedState: 's' });
// ok: d3auth.code-grant-without-state-or-nonce
await oidc.authorizationCodeGrant(config, url, { pkceCodeVerifier: 'v', expectedState: 's', expectedNonce: 'n' });

// ruleid: d3auth.authorization-url-without-pkce-s256
oidc.buildAuthorizationUrl(config, { redirect_uri: 'x', scope: 'openid' });
// ruleid: d3auth.authorization-url-without-pkce-s256
oidc.buildAuthorizationUrl(config, { redirect_uri: 'x', code_challenge_method: 'plain' });
// ok: d3auth.authorization-url-without-pkce-s256
oidc.buildAuthorizationUrl(config, { redirect_uri: 'x', code_challenge: 'c', code_challenge_method: 'S256' });

// ruleid: d3auth.symmetric-or-none-alg
const header = { alg: 'HS256', kid: 'k' };
// ruleid: d3auth.symmetric-or-none-alg
const unsigned = { typ: 'JWT', alg: 'none' };
// ok: d3auth.symmetric-or-none-alg
const fine = { alg: 'ES256', kid: 'k' };

// ruleid: d3auth.email-as-identity
const linked = accounts.find((account) => account.email === claims.email);

void [unverified, header, unsigned, fine, linked, db];
