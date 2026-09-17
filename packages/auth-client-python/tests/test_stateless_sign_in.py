"""REQ-094 — a sign-in an app can bind to the browser that started it.

The session-backed helpers need Starlette's `SessionMiddleware`. An app that already has its own
login — which is every app this provider is optional for — should not have to mount a second
session to hold three strings for ninety seconds. These are the twin of the TypeScript SDK's
`beginSignIn`/`completeSignIn`: they hand the app the verifier, state and nonce, and keep nothing.

The rule underneath is finding F-12: whatever the app does with them, it must be *per browser*.
A server-wide table keyed on `state` is readable by whoever supplies the state.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import pytest

from d3auth_client import D3AuthClient, SignInStart

ISSUER = "https://auth.example.test"
REDIRECT = "https://app.example.test/callback"

#: A real header segment: `_check_algorithm` reads it before anything is trusted, so a fixture
#: with a made-up first segment never reaches the code under test.
ES256_TOKEN = "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogIkpXVCJ9.body.signature"


class FakeApp:
    """The three Authlib calls the stateless flow makes."""

    def __init__(self, *, id_token_claims: dict | None = None, tokens: dict | None = None) -> None:
        self.claims = id_token_claims or {"iss": ISSUER, "sub": "a-person", "sid": "a-session", "roles": ["member"]}
        self.tokens = tokens or {"access_token": "an-access-token", "id_token": ES256_TOKEN, "refresh_token": "r"}
        self.exchanged: dict | None = None
        self.nonce_checked: str | None = None

    async def load_server_metadata(self) -> dict:
        return {"authorization_endpoint": f"{ISSUER}/oidc/auth", "token_endpoint": f"{ISSUER}/oidc/token",
                "userinfo_endpoint": f"{ISSUER}/oidc/me"}

    async def create_authorization_url(self, redirect_uri: str, **kwargs: object) -> dict:
        from urllib.parse import urlencode
        query = {"client_id": "an-app", "redirect_uri": redirect_uri, "response_type": "code",
                 "state": kwargs["state"], "nonce": kwargs["nonce"]}
        return {"url": f"{ISSUER}/oidc/auth?{urlencode(query)}", "state": kwargs["state"]}

    async def fetch_access_token(self, **kwargs: object) -> dict:
        self.exchanged = dict(kwargs)
        return self.tokens

    async def parse_id_token(self, tokens: dict, nonce: str, **_: object) -> dict:
        self.nonce_checked = nonce
        return self.claims


def client_with(app: FakeApp) -> D3AuthClient:
    client = D3AuthClient(issuer=ISSUER, client_id="an-app", client_secret="a-secret")
    client.app = app  # type: ignore[assignment]
    return client


async def test_a_start_hands_back_everything_the_callback_will_need():
    app = FakeApp()
    start = await client_with(app).start_sign_in(REDIRECT)

    assert isinstance(start, SignInStart)
    query = parse_qs(urlparse(start.url).query)
    assert query["state"] == [start.state]
    assert query["nonce"] == [start.nonce]
    # The verifier is the one thing that must never leave the app.
    assert start.verifier not in start.url
    assert len(start.verifier) >= 43, "a PKCE verifier is 43 characters at the very least"


async def test_two_sign_ins_share_nothing():
    client = client_with(FakeApp())
    first, second = await client.start_sign_in(REDIRECT), await client.start_sign_in(REDIRECT)
    assert {first.state, first.nonce, first.verifier}.isdisjoint({second.state, second.nonce, second.verifier})


async def test_a_callback_from_a_different_sign_in_is_refused_before_anything_is_exchanged():
    app = FakeApp()
    client = client_with(app)
    start = await client.start_sign_in(REDIRECT)
    theirs = await client.start_sign_in(REDIRECT)

    with pytest.raises(ValueError, match="different sign-in"):
        await client.finish_sign_in(f"{REDIRECT}?code=abc&state={theirs.state}", start=start, redirect_uri=REDIRECT)
    assert app.exchanged is None, "a code from somebody else's sign-in is never exchanged"


async def test_the_verifier_and_the_nonce_are_carried_into_the_exchange():
    app = FakeApp()
    client = client_with(app)
    start = await client.start_sign_in(REDIRECT)

    session = await client.finish_sign_in(
        f"{REDIRECT}?code=abc&state={start.state}&iss={ISSUER}", start=start, redirect_uri=REDIRECT
    )

    assert app.exchanged is not None
    assert app.exchanged["code_verifier"] == start.verifier, "PKCE proves this is the same browser"
    assert app.exchanged["redirect_uri"] == REDIRECT
    assert app.nonce_checked == start.nonce, "the nonce ties the ID token to this sign-in"
    assert session.identity.sub == "a-person"
    assert session.identity.roles == ["member"]
    assert session.sid == "a-session"


async def test_a_callback_naming_another_issuer_is_refused():
    """RFC 9207 — the provider names itself, so a code cannot be passed off as another's."""
    app = FakeApp()
    client = client_with(app)
    start = await client.start_sign_in(REDIRECT)

    with pytest.raises(ValueError, match="different issuer"):
        await client.finish_sign_in(
            f"{REDIRECT}?code=abc&state={start.state}&iss=https://evil.test", start=start, redirect_uri=REDIRECT
        )
    assert app.exchanged is None


async def test_the_providers_own_refusal_is_reported_not_swallowed():
    app = FakeApp()
    client = client_with(app)
    start = await client.start_sign_in(REDIRECT)

    with pytest.raises(ValueError, match="access_denied"):
        await client.finish_sign_in(
            f"{REDIRECT}?error=access_denied&state={start.state}", start=start, redirect_uri=REDIRECT
        )


async def test_an_id_token_signed_with_something_unacceptable_never_reaches_the_parser():
    """`alg: none` and HMAC are refused on the header alone, before any claim is read."""
    import base64
    import json

    unacceptable = base64.urlsafe_b64encode(json.dumps({"alg": "none"}).encode()).decode().rstrip("=")
    app = FakeApp(tokens={"access_token": "a", "id_token": f"{unacceptable}.body.signature"})
    client = client_with(app)
    start = await client.start_sign_in(REDIRECT)

    with pytest.raises(ValueError, match="refusing an ID token"):
        await client.finish_sign_in(f"{REDIRECT}?code=abc&state={start.state}", start=start, redirect_uri=REDIRECT)
    assert app.nonce_checked is None
