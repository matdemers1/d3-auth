"""REQ-098, REQ-099, REQ-095 — the same rules as the TypeScript SDK, in the same order.

A logout token arrives unauthenticated, from anybody who can reach the endpoint, and asks an app
to sign somebody out. Every one of these rules is the difference between that being a feature and
being a denial-of-service with extra steps.
"""

from __future__ import annotations

import time
from typing import Any

import pytest
from joserfc import jwt
from joserfc.jwk import ECKey, KeySet

from d3auth_client import (
    LOGOUT_EVENT,
    BackchannelHandler,
    LogoutTokenError,
    SeenEvents,
    verify_logout_token,
)

ISSUER = "https://auth.example.test"
CLIENT_ID = "an-app"

_SENTINEL = object()

signer = ECKey.generate_key("P-256", parameters={"alg": "ES256"})
keys = KeySet([signer])


def mint(alg: str = "ES256", typ: str = "logout+jwt", **overrides: Any) -> str:
    """Mints a logout token, with any single rule deliberately broken."""
    claims: dict[str, Any] = {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "sub": "a-person",
        "sid": "a-session",
        "jti": f"jti-{time.time_ns()}",
        "iat": int(time.time()),
        "exp": int(time.time()) + 120,
        "events": {LOGOUT_EVENT: {}},
    }
    for key, value in overrides.items():
        if value is _SENTINEL:
            claims.pop(key, None)
        else:
            claims[key] = value
    return jwt.encode({"alg": alg, "typ": typ}, claims, signer)


def verify(token: str):
    return verify_logout_token(token, issuer=ISSUER, client_id=CLIENT_ID, key_set=keys)


def test_accepts_a_real_one_and_says_which_session_to_end():
    verified = verify(mint())
    assert verified.sub == "a-person"
    assert verified.sid == "a-session"
    assert verified.jti


def test_refuses_one_signed_by_somebody_else():
    other = ECKey.generate_key("P-256", parameters={"alg": "ES256"})
    forged = jwt.encode(
        {"alg": "ES256", "typ": "logout+jwt"},
        {"iss": ISSUER, "aud": CLIENT_ID, "sub": "a-person", "jti": "x", "iat": int(time.time()), "events": {LOGOUT_EVENT: {}}},
        other,
    )
    with pytest.raises(LogoutTokenError):
        verify(forged)


def test_refuses_the_wrong_issuer_and_the_wrong_audience():
    with pytest.raises(LogoutTokenError, match="wrong issuer"):
        verify(mint(iss="https://somewhere.else.test"))
    with pytest.raises(LogoutTokenError, match="not addressed to this app"):
        verify(mint(aud="a-different-app"))


def test_refuses_a_token_carrying_a_nonce_which_would_be_an_id_token_replayed():
    with pytest.raises(LogoutTokenError, match="must not carry a nonce"):
        verify(mint(nonce="from-a-sign-in"))


def test_refuses_anything_that_is_not_a_back_channel_logout_event():
    with pytest.raises(LogoutTokenError, match="not a back-channel logout"):
        verify(mint(events={"http://example.test/other": {}}))
    with pytest.raises(LogoutTokenError, match="not a back-channel logout"):
        verify(mint(events=_SENTINEL))


def test_refuses_one_with_no_jti_because_it_could_not_be_applied_once():
    with pytest.raises(LogoutTokenError, match="no jti"):
        verify(mint(jti=_SENTINEL))


def test_refuses_one_that_names_neither_a_subject_nor_a_session():
    with pytest.raises(LogoutTokenError, match="neither a subject nor a session"):
        verify(mint(sub=_SENTINEL, sid=_SENTINEL))


def test_refuses_one_that_is_too_old_to_be_about_now():
    with pytest.raises(LogoutTokenError, match="too old|expired"):
        verify(mint(iat=int(time.time()) - 600, exp=int(time.time()) + 120))


async def test_ends_the_session_once_however_many_times_the_event_arrives():
    ended: list[str] = []
    handler = BackchannelHandler(
        issuer=ISSUER,
        client_id=CLIENT_ID,
        key_set=keys,
        end_session=lambda logout: ended.append(logout.sid or logout.sub),
    )

    token = mint()
    assert (await handler.handle(token)).ok
    # The provider retries three times; the second and third must be no-ops.
    repeated = await handler.handle(token)
    assert repeated.ok and repeated.repeated
    assert (await handler.handle(token)).repeated
    assert ended == ["a-session"]


async def test_says_no_without_raising_so_a_bad_token_is_not_an_outage():
    handler = BackchannelHandler(issuer=ISSUER, client_id=CLIENT_ID, key_set=keys, end_session=lambda _: None)
    assert not (await handler.handle("not.a.token")).ok
    result = await handler.handle(mint(nonce="x"))
    assert not result.ok
    assert "nonce" in (result.reason or "")


async def test_awaits_an_async_end_session():
    ended: list[str] = []

    async def end(logout):
        ended.append(logout.sid or "")

    handler = BackchannelHandler(issuer=ISSUER, client_id=CLIENT_ID, key_set=keys, end_session=end)
    await handler.handle(mint(sid="one"))
    await handler.handle(mint(sid="two"))
    assert ended == ["one", "two"]


def test_seen_events_forgets_the_oldest_rather_than_growing_without_end():
    seen = SeenEvents(limit=2)
    for jti in ("a", "b", "c"):
        seen.add(jti)
    assert "a" not in seen
    assert "c" in seen

