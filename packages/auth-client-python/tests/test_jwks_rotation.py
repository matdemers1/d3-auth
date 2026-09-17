"""REQ-098 — a signing key rotates and logout tokens keep verifying."""

from __future__ import annotations

import time
from typing import Any

import pytest
from joserfc import jwt
from joserfc.jwk import ECKey, KeySet

from d3auth_client import LOGOUT_EVENT, LogoutTokenError, verify_logout_token

ISSUER = "https://auth.example.test"
CLIENT_ID = "an-app"

# ---------------------------------------------------------------------------
# REQ-098 — signing keys rotate, and a logout token signed by the new one must still work.
#
# `KeySet` fetched the provider's keys once and kept them. Its own docstring promised a refetch
# when a token named a key it did not have, and nothing ever called it: the day D3 Auth rotated
# its signing key, every logout token would have been rejected as unverifiable until the app was
# restarted — silently, because a rejected logout token is a 400 the provider retries twice and
# then records as `logout.failed`.
# ---------------------------------------------------------------------------


class FakeJwks:
    """The provider's JWKS endpoint, which returns a different key after it rotates."""

    def __init__(self, key: Any) -> None:
        self.served = KeySet([key])
        self.fetches = 0

    def rotate_to(self, key: Any) -> None:
        self.served = KeySet([key])

    def get(self, _url: str) -> Any:
        self.fetches += 1
        served = self.served

        class Response:
            def json(self) -> Any:
                return served.as_dict(private=False)

        return Response()


def key_set_over(jwks: FakeJwks) -> Any:
    from d3auth_client.logout_token import KeySet as ClientKeySet

    # No cooldown in tests: a rotation here happens microseconds after the first fetch.
    return ClientKeySet(ISSUER, client=jwks, min_refetch_seconds=0)  # type: ignore[arg-type]


def mint_with(key: Any, **overrides: Any) -> str:
    claims: dict[str, Any] = {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "sub": "a-person",
        "sid": "a-session",
        "jti": "an-event",
        "iat": int(time.time()),
        "events": {LOGOUT_EVENT: {}},
        **overrides,
    }
    return jwt.encode({"alg": "ES256", "typ": "logout+jwt"}, claims, key)


def test_a_token_signed_by_a_rotated_key_is_verified_after_one_refetch():
    first = ECKey.generate_key("P-256", parameters={"alg": "ES256"})
    jwks = FakeJwks(first)
    key_set = key_set_over(jwks)

    verify_logout_token(mint_with(first), issuer=ISSUER, client_id=CLIENT_ID, key_set=key_set)
    assert jwks.fetches == 1, "the first verification fetches the keys"

    rotated = ECKey.generate_key("P-256", parameters={"alg": "ES256"})
    jwks.rotate_to(rotated)

    verified = verify_logout_token(
        mint_with(rotated, jti="after-rotation"), issuer=ISSUER, client_id=CLIENT_ID, key_set=key_set
    )
    assert verified.jti == "after-rotation"
    assert jwks.fetches == 2, "an unknown key id is what triggers the refetch"


def test_a_known_key_is_not_refetched_every_time():
    """The cache still has to be a cache: one fetch, then none."""
    signing = ECKey.generate_key("P-256", parameters={"alg": "ES256"})
    jwks = FakeJwks(signing)
    key_set = key_set_over(jwks)

    for n in range(3):
        verify_logout_token(mint_with(signing, jti=f"event-{n}"), issuer=ISSUER, client_id=CLIENT_ID, key_set=key_set)
    assert jwks.fetches == 1


def test_a_forged_token_does_not_become_valid_by_refetching():
    """An unknown key id is not a licence to trust the signature that names it."""
    jwks = FakeJwks(ECKey.generate_key("P-256", parameters={"alg": "ES256"}))
    key_set = key_set_over(jwks)
    forger = ECKey.generate_key("P-256", parameters={"alg": "ES256"})

    with pytest.raises(LogoutTokenError):
        verify_logout_token(mint_with(forger), issuer=ISSUER, client_id=CLIENT_ID, key_set=key_set)


def test_a_flood_of_forged_tokens_does_not_become_a_flood_of_key_fetches():
    """The refetch is how a rotation is survived; it must not become a way to lean on the provider.

    Without the cooldown, every unverifiable token — which is to say every token an attacker
    can mint for free — costs one request to the provider's JWKS endpoint.
    """
    from d3auth_client.logout_token import KeySet as ClientKeySet

    jwks = FakeJwks(ECKey.generate_key("P-256", parameters={"alg": "ES256"}))
    key_set = ClientKeySet(ISSUER, client=jwks, min_refetch_seconds=30)  # type: ignore[arg-type]
    forger = ECKey.generate_key("P-256", parameters={"alg": "ES256"})

    for n in range(5):
        with pytest.raises(LogoutTokenError):
            verify_logout_token(
                mint_with(forger, jti=f"forged-{n}"), issuer=ISSUER, client_id=CLIENT_ID, key_set=key_set
            )

    assert jwks.fetches == 1, "one fetch to populate the cache, and none bought by the forgeries"
