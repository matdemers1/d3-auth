"""Verifying a back-channel logout token (REQ-098, REQ-095, REQ-099).

A logout token arrives unauthenticated, from anybody who can reach the endpoint, and asks the app
to end somebody's session. So every check matters — and one of them is unusual enough to state
plainly: a logout token must **not** carry a ``nonce``. That is what stops an ID token from being
replayed at the logout endpoint to sign somebody out at will.
"""

from __future__ import annotations

import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import httpx
from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import KeySet as JoseKeySet

LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"

#: Asymmetric only. ``alg=none`` has no signature; HMAC means the verifier could have forged it.
ALLOWED_ALGORITHMS = ["ES256", "RS256", "ES384", "RS384", "ES512", "RS512"]

#: How old a logout token may be. Two minutes, like the provider's own lifetime.
DEFAULT_MAX_AGE_SECONDS = 120


class LogoutTokenError(Exception):
    """A logout token that cannot be trusted, and the rule it broke."""

    def __init__(self, reason: str) -> None:
        super().__init__(f"logout token rejected: {reason}")
        self.reason = reason


@dataclass(frozen=True)
class VerifiedLogout:
    """What a good logout token says."""

    sub: str
    jti: str
    #: Which session to end. Absent when the provider means every session for ``sub``.
    sid: str | None = None


class KeySet:
    """The provider's public keys, fetched once and reused.

    Keys rotate on a schedule, so a set that could never be refetched would work right up until
    the day it stopped. ``refresh()`` is called when a token names a key this set does not have.
    """

    def __init__(self, issuer: str, *, client: httpx.Client | None = None) -> None:
        self._url = f"{issuer.rstrip('/')}/oidc/jwks"
        self._client = client or httpx.Client(timeout=5.0)
        self._keys: Any | None = None

    def refresh(self) -> Any:
        self._keys = JoseKeySet.import_key_set(self._client.get(self._url).json())
        return self._keys

    def keys(self) -> Any:
        return self._keys if self._keys is not None else self.refresh()


def verify_logout_token(
    token: str,
    *,
    issuer: str,
    client_id: str,
    key_set: KeySet | Any | None = None,
    max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS,
) -> VerifiedLogout:
    """Check a logout token completely, or raise saying which rule it broke."""
    keys = key_set if key_set is not None else KeySet(issuer)
    resolved = keys.keys() if isinstance(keys, KeySet) else keys

    try:
        decoded = jwt.decode(token, resolved, algorithms=ALLOWED_ALGORITHMS)
        # Expiry is the only claim registry check worth making here; the rest are below, where
        # the error message can say which rule was broken.
        jwt.JWTClaimsRegistry().validate(decoded.claims)
    except (JoseError, ValueError) as err:  # signature, algorithm, or a malformed token
        raise LogoutTokenError(str(err)) from err

    claims = decoded.claims
    if claims.get("iss") != issuer:
        raise LogoutTokenError("wrong issuer")

    audience = claims.get("aud")
    audiences = audience if isinstance(audience, list) else [audience]
    if client_id not in audiences:
        raise LogoutTokenError("not addressed to this app")

    # An ID token would carry a nonce. Accepting one here would let a token minted for sign-in be
    # replayed as a sign-out.
    if "nonce" in claims:
        raise LogoutTokenError("a logout token must not carry a nonce")

    events = claims.get("events")
    if not isinstance(events, dict) or LOGOUT_EVENT not in events:
        raise LogoutTokenError("not a back-channel logout event")

    issued_at = claims.get("iat")
    if not isinstance(issued_at, int) or time.time() - issued_at > max_age_seconds:
        raise LogoutTokenError("too old")

    sub = claims.get("sub") or ""
    sid = claims.get("sid")
    if not sub and not sid:
        raise LogoutTokenError("names neither a subject nor a session")

    jti = claims.get("jti")
    if not jti:
        raise LogoutTokenError("has no jti, so it cannot be applied once")

    return VerifiedLogout(sub=sub, jti=jti, sid=sid)


class SeenEvents:
    """Remembers which logout events have been applied.

    Enough for one process. An app running more than one needs a shared store — Redis, or a
    table — or a retry will land on a process that has not seen the event and end a session the
    person has since started again.
    """

    def __init__(self, limit: int = 5000) -> None:
        self._seen: OrderedDict[str, None] = OrderedDict()
        self._limit = limit

    def __contains__(self, jti: str) -> bool:
        return jti in self._seen

    def add(self, jti: str) -> None:
        self._seen[jti] = None
        while len(self._seen) > self._limit:
            self._seen.popitem(last=False)


EndSession = Callable[[VerifiedLogout], Awaitable[None] | None]


@dataclass
class BackchannelResult:
    ok: bool
    repeated: bool = False
    reason: str | None = None


class BackchannelHandler:
    """The handler an app mounts at its back-channel endpoint (REQ-099).

    Idempotent by ``jti``, because delivery retries: the provider tries three times, and a second
    arrival of the same event must not end a session the person has since started again.
    """

    def __init__(
        self,
        *,
        issuer: str,
        client_id: str,
        end_session: EndSession,
        key_set: KeySet | Any | None = None,
        seen: SeenEvents | None = None,
    ) -> None:
        self._issuer = issuer
        self._client_id = client_id
        self._end_session = end_session
        self._key_set = key_set if key_set is not None else KeySet(issuer)
        self._seen = seen or SeenEvents()

    async def handle(self, logout_token: str) -> BackchannelResult:
        try:
            verified = verify_logout_token(
                logout_token,
                issuer=self._issuer,
                client_id=self._client_id,
                key_set=self._key_set,
            )
        except LogoutTokenError as err:
            # A bad token is a bad request, not an outage.
            return BackchannelResult(ok=False, reason=err.reason)

        if verified.jti in self._seen:
            return BackchannelResult(ok=True, repeated=True)
        self._seen.add(verified.jti)

        result = self._end_session(verified)
        if isinstance(result, Awaitable):
            await result
        return BackchannelResult(ok=True)
