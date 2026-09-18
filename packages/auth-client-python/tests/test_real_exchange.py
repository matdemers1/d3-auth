"""One sign-in against a real Authlib client, over a stub provider.

Every other test here stands in for Authlib. That is the right shape for testing *our* rules —
state comparison, the pinned algorithm list, what happens when a provider answers nonsense — and
it is why this file exists: a stand-in cannot refuse a call the real library refuses.

`finish_sign_in` passed the token endpoint as `url=`. Authlib resolves that endpoint itself and
hands it to `fetch_token` **positionally**, so the keyword arrived as a second value for the same
parameter and every exchange raised `TypeError: got multiple values for argument 'url'`. The fake
took `**kwargs` and was happy. Twenty-eight tests passed, the SDK was released, Bindery consumed
it, and the first person to press the button in production got "D3 Auth could not sign you in".

So: the real `D3AuthClient`, the real Authlib, a real ES256 key, and an httpx transport that
answers the four documents a provider serves. Nothing here mocks the library under test.
"""

from __future__ import annotations

import time
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from joserfc import jwt
from joserfc.jwk import ECKey

from d3auth_client import D3AuthClient

ISSUER = "https://auth.example.test"
CLIENT_ID = "an-app"
REDIRECT = "https://app.example.test/api/auth/oidc/callback"


class StubProvider:
    """The four documents a sign-in touches, and a record of what was asked of them."""

    def __init__(self, key: ECKey, *, roles: list[str] | None = None) -> None:
        self.key = key
        self.roles = roles if roles is not None else ["member"]
        self.token_requests: list[dict[str, list[str]]] = []
        self.nonce = ""

    def id_token(self) -> str:
        claims = {
            "iss": ISSUER,
            "sub": "01J-a-stable-subject",
            "aud": CLIENT_ID,
            "exp": int(time.time()) + 300,
            "iat": int(time.time()),
            "nonce": self.nonce,
            "sid": "a-provider-session",
            "email": "someone@example.test",
            "roles": self.roles,
        }
        return jwt.encode({"alg": "ES256", "kid": self.key.kid}, claims, self.key)

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = urlparse(str(request.url)).path
        if path == "/.well-known/openid-configuration":
            return httpx.Response(200, json={
                "issuer": ISSUER,
                "authorization_endpoint": f"{ISSUER}/oidc/auth",
                "token_endpoint": f"{ISSUER}/oidc/token",
                "userinfo_endpoint": f"{ISSUER}/oidc/me",
                "jwks_uri": f"{ISSUER}/oidc/jwks",
                "id_token_signing_alg_values_supported": ["ES256"],
            })
        if path == "/oidc/jwks":
            return httpx.Response(200, json={"keys": [self.key.as_dict(private=False)]})
        if path == "/oidc/token":
            self.token_requests.append(parse_qs(request.content.decode()))
            return httpx.Response(200, json={
                "access_token": "an-access-token",
                "token_type": "Bearer",
                "expires_in": 600,
                "refresh_token": "a-refresh-token",
                "id_token": self.id_token(),
            })
        if path == "/oidc/me":
            return httpx.Response(200, json={
                "sub": "01J-a-stable-subject",
                "email": "someone@example.test",
                "roles": self.roles,
            })
        return httpx.Response(404, json={"error": path})


@pytest.fixture
def key() -> ECKey:
    return ECKey.generate_key("P-256", parameters={"kid": "a-signing-key"})


@pytest.fixture
def provider(key: ECKey) -> StubProvider:
    return StubProvider(key)


def client_for(provider: StubProvider) -> D3AuthClient:
    return D3AuthClient(
        issuer=ISSUER,
        client_id=CLIENT_ID,
        client_secret="a-client-secret",
        transport=httpx.MockTransport(provider.handle),
    )


async def test_a_whole_sign_in_against_the_library_it_actually_uses(provider) -> None:
    client = client_for(provider)

    start = await client.start_sign_in(REDIRECT)
    query = parse_qs(urlparse(start.url).query)
    assert query["code_challenge_method"] == ["S256"], "PKCE is not optional (REQ-094)"
    provider.nonce = start.nonce

    session = await client.finish_sign_in(
        f"{REDIRECT}?code=an-authorization-code&state={start.state}&iss={ISSUER}",
        start=start,
        redirect_uri=REDIRECT,
    )

    assert session.identity.sub == "01J-a-stable-subject"
    assert session.identity.iss == ISSUER
    assert session.identity.roles == ["member"]
    assert session.refresh_token == "a-refresh-token"
    assert session.sid == "a-provider-session"

    # The exchange the provider actually received, which is the half a stand-in cannot check.
    sent = provider.token_requests[-1]
    assert sent["grant_type"] == ["authorization_code"]
    assert sent["code"] == ["an-authorization-code"]
    assert sent["code_verifier"] == [start.verifier]
    assert sent["redirect_uri"] == [REDIRECT], (
        "the redirect URI is part of the exchange, and the provider compares it to the one the "
        "authorization request carried"
    )


async def test_a_renewal_goes_through_the_same_endpoint(provider) -> None:
    """`refresh()` had the same `url=` bug, and every linked account renews every ten minutes."""
    client = client_for(provider)

    renewed = await client.refresh("a-refresh-token")

    assert renewed.identity.sub == "01J-a-stable-subject"
    assert renewed.identity.roles == ["member"]
    assert provider.token_requests[-1]["grant_type"] == ["refresh_token"]


async def test_a_callback_from_a_different_sign_in_is_refused_before_any_exchange(provider) -> None:
    """The state check is the whole defence, so it has to happen before the network does."""
    client = client_for(provider)
    start = await client.start_sign_in(REDIRECT)

    with pytest.raises(ValueError, match="different sign-in"):
        await client.finish_sign_in(
            f"{REDIRECT}?code=a-code&state=somebody-elses-state&iss={ISSUER}",
            start=start,
            redirect_uri=REDIRECT,
        )

    assert provider.token_requests == [], "a refused callback must not spend the code"


async def test_a_token_signed_by_the_wrong_key_is_not_believed(provider, key) -> None:
    """The signature is verified against the published JWKS, not merely parsed.

    The stub keeps advertising the real key and signs with another one carrying the same `kid`,
    which is the shape of the attack: a token that looks right in every readable way.
    """
    client = client_for(provider)
    start = await client.start_sign_in(REDIRECT)
    provider.nonce = start.nonce
    provider.key = ECKey.generate_key("P-256", parameters={"kid": key.kid})
    published = key

    def handle(request: httpx.Request) -> httpx.Response:
        if urlparse(str(request.url)).path == "/oidc/jwks":
            return httpx.Response(200, json={"keys": [published.as_dict(private=False)]})
        return provider.handle(request)

    client.app.client_kwargs["transport"] = httpx.MockTransport(handle)

    with pytest.raises(Exception, match="(?i)signature|verif|invalid"):
        await client.finish_sign_in(
            f"{REDIRECT}?code=a-code&state={start.state}&iss={ISSUER}",
            start=start,
            redirect_uri=REDIRECT,
        )
