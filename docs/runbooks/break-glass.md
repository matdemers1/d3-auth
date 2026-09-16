# Break-glass: getting back in when the second factor is gone

**When to use this:** the only admin cannot complete the second step — the phone holding the
passkey is lost, wiped, or in the sea — and there is no second admin to reset the account.

**What it needs:** a shell on the host *and* the account's password. The link alone is not a way
in ([ADR-003](../../../D3%20Cloud%20Vault/D3%20Auth/ADR-003%20—%20Break-glass%20is%20a%20window,%20not%20a%20key.md)).

> [!warning] This leaves the account with no second factor
> Opening the link deletes that account's passkeys and authenticator apps. Enrol a new one the
> moment you are in, before you do anything else.

---

## Try these first

1. **Another admin.** People → their row → **Reset**. That emails them a link to set the account
   up again, keeps their account id, and needs no shell. Prefer it every time.
2. **A trusted browser.** If a browser was told to skip the second step in the last 30 days, it
   still will. Try the laptop before you try the host.

Break-glass is for when neither of those exists.

---

## 1. Mint the link

On the ZimaOS host, in the directory holding `docker-compose.yml`:

```bash
docker compose exec server node dist/cli/recover.js --user you@example.com --minutes 15
```

It prints a link and the moment it expires. `--minutes` defaults to 15 and is capped at 60: the
window is how long the account will accept a password on its own, so keep it short.

The command writes a `recovery.minted` audit row before it prints anything. There is no way to
use this quietly.

## 2. Open the link

Open it in the browser you are going to sign in from. It works **once**. Opening it:

- deletes every passkey and authenticator app on the account,
- forgets every trusted browser,
- ends every session the lost device might still hold,
- opens the window, counted from that moment.

The page says who the account is and when the window closes. It does not sign you in.

## 3. Sign in normally

Go to the app you were signing in to and sign in with your email and password. You will not be
asked for a second step. The sign-in is recorded with `amr: ["pwd","recovery"]`, in the id_token
and in the audit trail, so it is obvious afterwards that a door was opened.

The window closes as soon as that sign-in completes, whether or not minutes remain.

## 4. Enrol a factor, immediately

Account → **How you sign in** → *Add a passkey*. Until you do, the account is password-only, and
if it is an owner or admin account it is in a state the factor rule exists to prevent.

Then, so this does not happen again:

- enrol a **second** factor (a passkey on another device, or an authenticator app),
- make sure a **second admin** exists, whose factors live on different hardware.

---

## When it does not work

| What you see | What it means |
|---|---|
| `No account for …` | The email is wrong, or the account was never created. `docker compose exec postgres psql -U d3auth -d d3auth -c 'select email from "user";'` |
| The page says the link has expired | It was already opened, or the minutes ran out. Mint another. |
| Sign-in still asks for a code | The window closed (it is spent by one sign-in), or you are signing in as a different account than the link was for. |
| `KEK` errors on boot | Not this runbook. The service cannot decrypt its own secrets; see the deploy runbook and R-03. |

## What to check afterwards

```bash
docker compose exec postgres psql -U d3auth -d d3auth \
  -c "select event, target_id, at from audit_event where event like 'recovery%' order by id desc limit 10;"
```

Three rows tell the whole story: `recovery.minted` (someone on the host asked), `recovery.claimed`
(the link was opened and the factors cleared), `recovery.used` (the window was spent by a
sign-in). A `minted` with no `claimed` means a link is loose — it expires on its own, but mint no
more than you need.

## Signing everybody out at once

For an incident — a leaked database dump, a compromised device you cannot identify, a key you no
longer trust — end every sign-in and every token in one step (ASVS 5.0 7.4.5). Nobody is locked
out: people sign in again with what they already have, and apps are sent to do the same.

```bash
docker compose exec postgres psql -U d3auth -d d3auth -c "
  begin;
  delete from oidc_payload where kind in ('Session', 'Grant', 'AccessToken', 'RefreshToken', 'AuthorizationCode', 'Interaction');
  update session set revoked_at = now() where revoked_at is null;
  commit;"
```

Rotating `COOKIE_KEYS` is **not** a substitute: it invalidates the cookie's signature for the
provider, but the console finds a session by its id, and the session itself is still in the table.
Delete the sessions.

Apps are not told by back-channel logout this way — their own sessions end the next time they need
a token, within ten minutes for an access token. If that is too slow for the incident, disable the
app in the console too. Afterwards, write down why in the audit trail's absence: this is a
database operation, so it leaves no audit row of its own.
