# The consumer contract

What an app has to do to sign people in with D3 Auth, and why each rule is there. Ten rules; the
SDKs (`@d3cloud/auth-client`, `d3auth-client`) implement most of them for you, and the ones they
cannot are called out below.

This mirrors §2 of the API Contract in the vault. If the two ever disagree, the vault is the
plan and this file is the implementation — fix whichever is wrong.

---

## 1. Use discovery. Never hard-code an endpoint or a key.

```
GET https://auth.d3cloud.io/.well-known/openid-configuration
```

Endpoints move and signing keys rotate — on purpose, on a schedule. An app with a pasted JWKS
keeps working right up until the day the key it pinned is retired, which is precisely the day
nobody wants to be debugging sign-in.

## 2. Authorization code with PKCE `S256`, plus `state` and `nonce` — and check both.

PKCE is required of every client, confidential ones included. `state` is what ties the callback
to the request your app started; `nonce` is what ties the ID token to it. Generating them is not
the point — **checking them on the way back** is.

## 3. Verify the ID token against a pinned algorithm list.

Check `iss` equals the issuer discovery gave you, `aud` contains your `client_id`, `nonce`
matches, `exp` has not passed, and the algorithm is one of `ES256` or `RS256`.

Never `alg=none` — it has no signature at all. Never an HMAC algorithm: the key that verifies is
the key that signs, so anyone who can check a token can also mint one.

## 4. Identify people by `(iss, sub)`. Never by email.

An email address can change, be reassigned, and be claimed by somebody who has not proved they
own it. `sub` is stable and opaque; `iss` says who vouched for it. Store both, together, and key
your local account on the pair.

Neither SDK offers a lookup by email. That is deliberate.

## 5. Ask for `d3:roles`, and refresh roles on every renewal.

Roles arrive in the `roles` claim, scoped to your app: you see yours and never another app's. But
a token is a snapshot. When an admin changes somebody's roles, that change should reach you
within minutes, not whenever the person happens to sign in again — so re-read `roles` from
`userinfo` on **every access-token renewal**, not just at sign-in.

```ts
const session = await auth.refresh(storedRefreshToken); // roles are refreshed with it
```

## 6. Implement a back-channel logout endpoint.

```
POST /your/backchannel-logout     (content-type: application/x-www-form-urlencoded)
logout_token=<signed JWT>
```

Verify it: signature against the provider's JWKS, `iss`, `aud`, `iat` recent, the
`http://schemas.openid.net/event/backchannel-logout` event present — and **no `nonce`**. A
logout token that carries a nonce is an ID token being replayed to sign somebody out.

End the session named by `sid`, or every session for `sub` when there is no `sid`. Answer `200`.
Be idempotent by `jti`: delivery is retried three times, and the second arrival must not end a
session the person has since started again.

An app with no such endpoint is marked **slow revoke** in the console: revoking access there is
honest about taking effect only when your tokens expire.

## 7. Own your own session. An ID token is not one.

The ID token says who somebody was at one moment. Your session is yours to issue, size and end.
Do not treat token expiry as session expiry, and do not keep the ID token around as a credential.

## 8. Provision on first sign-in, only when access exists.

D3 Auth is deny-by-default: nobody reaches your app without a grant. So a successful sign-in is
already proof that an admin meant them to be there — create the local account then, apply your
own quotas and isolation, and map `roles` onto whatever your app calls those things.

## 9. Dual-login apps link explicitly.

If your app also has its own login, do not auto-link by email. Ever. A person signed in locally
chooses *Connect D3 Auth*, completes an ordinary OIDC flow, and you store `(iss, sub)` on the
account they were already signed in to. Unlinking asks for their local password.

The failure this prevents: someone registers a local account with a name they do not own, and an
SSO sign-in silently hands them the real owner's data.

## 10. SSO-required mode keeps working through an outage.

If your app has no login of its own:

- existing sessions survive the provider being down — you own them, so nothing forces them out;
- new sign-ins show *sign-in unavailable*, not a stack trace. Poll `GET /readyz`, which is public
  and needs no credentials;
- a **local owner break-glass login** always exists. An app that can only be entered through an
  IdP is an app that can be locked shut by one container.

---

## The shortest conformant app

```ts
import { createAuthClient, createBackchannelHandler } from '@d3cloud/auth-client';

const auth = await createAuthClient({
  issuer: 'https://auth.d3cloud.io',
  clientId: 'your-app',
  clientSecret: process.env.CLIENT_SECRET,
  redirectUri: 'https://your-app.example/callback',
  ssoMode: 'optional',
});

// Start: keep verifier, state and nonce with the browser's own session.
const start = await auth.beginSignIn();

// Callback: everything in rules 2–5 happens here.
const session = await auth.completeSignIn(callbackUrl, start);
// session.identity is { iss, sub, claims, roles } — key your account on (iss, sub).

// Back-channel: rule 6, idempotent by jti.
const handle = createBackchannelHandler({
  issuer: 'https://auth.d3cloud.io',
  clientId: 'your-app',
  endSession: ({ sid, sub }) => yourStore.endSession({ sid, sub }),
});
```

## Registering

Apps are registered by the owner in the console, from a manifest. Roles are declared there and
nowhere else — the console cannot invent a role your app has never heard of.

```json
{
  "client_id": "your-app",
  "name": "Your App",
  "client_type": "confidential_web",
  "redirect_uris": ["https://your-app.example/callback"],
  "post_logout_redirect_uris": ["https://your-app.example/"],
  "backchannel_logout_uri": "https://your-app.example/backchannel-logout",
  "roles": [
    { "key": "admin", "display": "Administrator" },
    { "key": "member", "display": "Member", "default": true }
  ]
}
```

Redirect URIs are matched exactly: no wildcards, no fragments, https on anything that is not
localhost. The client secret is shown once, at registration, and can only be rotated afterwards —
never re-read.

## See also

- `examples/express` — a dual-login app implementing all ten rules
- `docs/runbooks/deploy.md` — where the provider itself runs
- The vault: `D3 Auth/API Contract`, `D3 Auth/Architecture`
