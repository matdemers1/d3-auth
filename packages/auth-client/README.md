# @d3cloudio/auth-client

The relying-party SDK for [D3 Auth](https://github.com/matdemers1/d3-auth), a small self-hosted
OpenID Connect provider. It exists so a consuming app gets the four things that are easiest to get
wrong for free: a pinned algorithm list, identity by `(iss, sub)` rather than email, roles refreshed
on every renewal, and a back-channel logout handler that is idempotent by `jti`.

It speaks plain OpenID Connect, so nothing here is D3 Auth-specific except the defaults.

```bash
npm install @d3cloudio/auth-client
```

Node 20 or newer. React is an optional peer dependency, needed only for the `/react` entry.

## Signing somebody in

```ts
import { createAuthClient } from '@d3cloudio/auth-client';

const auth = await createAuthClient({
  issuer: 'https://auth.example.com',
  clientId: 'your-app',
  clientSecret: process.env.D3AUTH_CLIENT_SECRET,
  redirectUri: 'https://your-app.example.com/callback',
  scope: 'openid profile email d3:roles',
});

// 1. Start: keep `state`, `verifier` and `nonce` in the session, send the person to `url`.
const { url, state, verifier, nonce } = await auth.beginSignIn();

// 2. Come back: the ID token's signature, issuer, audience and nonce are all checked here.
const session = await auth.completeSignIn(callbackUrl, { state, verifier, nonce });

session.identity;        // { iss, sub, claims } — store (iss, sub) on your user row
session.identity.claims; // the verified ID token payload, for display only
session.accessToken;     // keep it on your server
session.sid;             // the session the provider knows, for back-channel logout

// Roles change between renewals, so read them when you need them — never from a stale token.
const roles = await auth.rolesNow(session.accessToken, session.identity.sub);
```

**Link accounts by `identity`, never by email.** Addresses change hands; `(iss, sub)` does not:

```ts
import { identityKey, isSameIdentity } from '@d3cloudio/auth-client';

const key = identityKey(session.identity); // a stable string for a unique index
```

When the provider is unreachable, `createAuthClient` and `beginSignIn` throw `SsoUnavailable`, and
`auth.healthy()` answers before you offer the button — so an app with its own login can fall back to
it instead of showing a sign-in that cannot work.

## Back-channel logout

D3 Auth posts a signed logout token when somebody signs out or loses access. The handler verifies
it (`ES256`/`RS256` only, never `alg: none`), refuses replays by `jti`, and hands you the session
to end:

```ts
import { createBackchannelHandler, inMemorySeen } from '@d3cloudio/auth-client';

const handle = createBackchannelHandler({
  issuer: 'https://auth.example.com',
  clientId: 'your-app',
  seen: inMemorySeen(),  // swap in Redis or a table for more than one process
  // `sid` names one session; without it, sign out every session for that `sub`.
  endSession: async ({ sub, sid }) => endSessionsFor(sub, sid),
});

app.post('/auth/backchannel-logout', async (req, res) => {
  const result = await handle(req.body.logout_token);
  res.sendStatus(result.ok ? 204 : 400);
});
```

## The React button

```tsx
import { SignInWithD3Auth, useProviderHealth } from '@d3cloudio/auth-client/react';

<SignInWithD3Auth href="/auth/start" issuer="https://auth.example.com" ssoMode="optional" />;
```

It polls the provider's public readiness probe. In `optional` mode — an app that has its own login —
it hides itself when the provider is down rather than offering a sign-in that cannot work; in
`required` mode it says so plainly. Styling is yours: the button carries `d3auth-signin`, plus
`d3auth-signin--unavailable`, and any `className` you pass.

## What it will not do for you

Ten rules make up the [consumer contract](https://github.com/matdemers1/d3-auth/blob/main/docs/consumer-contract.md);
this SDK covers four. The rest are yours: keep tokens on the server, treat roles as this app's own,
end your session when the logout token arrives, and never accept an unsigned or unexpected
algorithm anywhere else in your code.

## Licence

[Apache-2.0](LICENSE).
