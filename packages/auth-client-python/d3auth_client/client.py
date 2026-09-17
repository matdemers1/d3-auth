"""The relying-party half of a sign-in, for Starlette and FastAPI (REQ-090).

This wraps Authlib's OAuth client rather than reimplementing OAuth, and adds the four things a
consumer of *this* provider needs: a pinned algorithm list, identity by ``(iss, sub)``, roles
refreshed from ``userinfo`` on every token renewal, and an ``sso_mode`` so an app can decide what
to do when the provider is unreachable.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import parse_qs, urlparse

import httpx
from authlib.integrations.starlette_client import OAuth
from starlette.requests import Request

from .identity import Identity
from .logout_token import ALLOWED_ALGORITHMS

SsoMode = Literal["off", "optional", "required"]

DEFAULT_SCOPE = "openid profile email d3:roles offline_access"


class SsoUnavailable(Exception):
    """The provider could not be reached. In `required` mode this is a screen, not a crash."""


@dataclass(frozen=True)
class Session:
    """What an app keeps after a successful sign-in. The app's own session is separate."""

    identity: Identity
    access_token: str
    id_token: str
    refresh_token: str | None = None
    expires_at: int | None = None
    #: The session identifier the provider knows this by, for back-channel logout.
    sid: str | None = None


@dataclass(frozen=True)
class SignInStart:
    """A sign-in that has begun, and the three secrets the callback will need back.

    The app stores these **with the browser that started the sign-in** — its session, or a short
    random id in a short-lived ``HttpOnly`` cookie — and never in a server-wide table keyed on
    ``state``. A table keyed on ``state`` can be read by whoever supplies the state, which is the
    attacker: that is finding F-12, and it allowed login-CSRF and, through account linking, role
    theft.
    """

    url: str
    verifier: str
    state: str
    nonce: str


def _roles_of(claims: dict[str, Any] | None) -> list[str]:
    roles = (claims or {}).get("roles")
    return [role for role in roles if isinstance(role, str)] if isinstance(roles, list) else []


class D3AuthClient:
    """A registered app's view of D3 Auth."""

    def __init__(
        self,
        *,
        issuer: str,
        client_id: str,
        client_secret: str | None = None,
        scope: str = DEFAULT_SCOPE,
        sso_mode: SsoMode = "optional",
        http: httpx.Client | None = None,
    ) -> None:
        self.issuer = issuer.rstrip("/")
        self.client_id = client_id
        self.sso_mode: SsoMode = sso_mode
        self._http = http or httpx.Client(timeout=5.0)

        oauth = OAuth()
        oauth.register(
            name="d3auth",
            server_metadata_url=f"{self.issuer}/.well-known/openid-configuration",
            client_id=client_id,
            client_secret=client_secret,
            client_kwargs={
                "scope": scope,
                "code_challenge_method": "S256",
                # The pinned list (REQ-094, REQ-095): never `none`, never symmetric.
                "token_endpoint_auth_method": "client_secret_basic" if client_secret else "none",
            },
        )
        self._oauth = oauth
        self.app = oauth.create_client("d3auth")

    def healthy(self) -> bool:
        """Can people sign in right now? Used to decide whether to offer the button (REQ-102)."""
        try:
            return self._http.get(f"{self.issuer}/readyz").is_success
        except httpx.HTTPError:
            return False

    async def begin_sign_in(self, request: Request, redirect_uri: str, **extra: Any) -> Any:
        """Redirects to the provider. Authlib keeps state, nonce and the PKCE verifier.

        Convenient when the app already has Starlette's ``SessionMiddleware``. When it does not —
        or when it would rather bind the transaction to a cookie of its own — use
        :meth:`start_sign_in` and :meth:`finish_sign_in`, which keep nothing.
        """
        return await self.app.authorize_redirect(request, redirect_uri, **extra)

    async def start_sign_in(self, redirect_uri: str, **extra: Any) -> SignInStart:
        """Begin a sign-in and hand the app everything it must remember. Stores nothing.

        The twin of the TypeScript SDK's ``beginSignIn``. An app with its own session cookies —
        most apps that already have a login — should not have to mount a second session just to
        hold three strings for ninety seconds.
        """
        metadata = await self.app.load_server_metadata()
        verifier = secrets.token_urlsafe(64)
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        prepared = await self.app.create_authorization_url(
            redirect_uri, state=state, nonce=nonce, code_verifier=verifier, **extra
        )
        url = prepared["url"] if isinstance(prepared, dict) else prepared[0]
        return SignInStart(url=url, verifier=verifier, state=state, nonce=nonce)

    async def finish_sign_in(
        self, callback_url: str, *, start: SignInStart, redirect_uri: str
    ) -> Session:
        """Complete a sign-in begun by :meth:`start_sign_in`, checking it is the same one.

        ``start`` comes from wherever the app put it for this browser. A callback whose ``state``
        does not match is refused before anything is exchanged: that check is the whole defence
        against a sign-in somebody else began.
        """
        query = parse_qs(urlparse(str(callback_url)).query)
        first = lambda name: (query.get(name) or [None])[0]  # noqa: E731

        error = first("error")
        if error:
            raise ValueError(f"the provider refused the sign-in: {first('error_description') or error}")

        returned_state = first("state") or ""
        if not secrets.compare_digest(returned_state, start.state):
            raise ValueError("this callback belongs to a different sign-in")

        # RFC 9207: the provider names itself in the response, so a code cannot be passed off as
        # having come from somewhere else.
        returned_issuer = first("iss")
        if returned_issuer and returned_issuer.rstrip("/") != self.issuer:
            raise ValueError("the callback names a different issuer")

        code = first("code")
        if not code:
            raise ValueError("the callback carries no authorization code")

        metadata = await self.app.load_server_metadata()
        tokens = await self.app.fetch_access_token(
            url=metadata["token_endpoint"],
            grant_type="authorization_code",
            code=code,
            code_verifier=start.verifier,
            redirect_uri=redirect_uri,
        )

        id_token = tokens.get("id_token") or ""
        if not id_token:
            raise ValueError("the provider returned no ID token")
        _check_algorithm(id_token)
        claims = dict(await self.app.parse_id_token(tokens, nonce=start.nonce))

        sub = claims.get("sub") or ""
        if not sub:
            raise ValueError("the ID token has no subject")

        roles = _roles_of(claims)
        if not roles and tokens.get("access_token"):
            roles = await self.roles_now(tokens["access_token"])

        return Session(
            identity=Identity(iss=claims.get("iss") or self.issuer, sub=sub, claims=claims, roles=roles),
            access_token=tokens.get("access_token", ""),
            id_token=id_token,
            refresh_token=tokens.get("refresh_token"),
            expires_at=tokens.get("expires_at"),
            sid=claims.get("sid"),
        )

    async def complete_sign_in(self, request: Request) -> Session:
        """Exchanges the code and verifies the ID token, then reads the roles."""
        tokens = await self.app.authorize_access_token(request)
        claims: dict[str, Any] = dict(tokens.get("userinfo") or {})

        id_token = tokens.get("id_token") or ""
        if not id_token:
            raise ValueError("the provider returned no ID token")
        _check_algorithm(id_token)

        sub = claims.get("sub") or ""
        if not sub:
            raise ValueError("the ID token has no subject")

        roles = _roles_of(claims)
        if not roles and tokens.get("access_token"):
            roles = await self.roles_now(tokens["access_token"])

        return Session(
            identity=Identity(iss=claims.get("iss") or self.issuer, sub=sub, claims=claims, roles=roles),
            access_token=tokens.get("access_token", ""),
            id_token=id_token,
            refresh_token=tokens.get("refresh_token"),
            expires_at=tokens.get("expires_at"),
            sid=claims.get("sid"),
        )

    async def _userinfo(self, access_token: str) -> dict[str, Any]:
        """What the provider says about the holder of this access token, right now."""
        metadata = await self.app.load_server_metadata()
        response = await self.app.get(metadata["userinfo_endpoint"], token={"access_token": access_token, "token_type": "Bearer"})
        return response.json()

    async def roles_now(self, access_token: str) -> list[str]:
        """The roles this person has in this app right now (REQ-097)."""
        return _roles_of(await self._userinfo(access_token))

    async def refresh(self, refresh_token: str) -> Session:
        """Renews the access token *and* the roles, because roles change between renewals."""
        metadata = await self.app.load_server_metadata()
        tokens = await self.app.fetch_access_token(
            url=metadata["token_endpoint"], grant_type="refresh_token", refresh_token=refresh_token
        )
        # Userinfo answers both halves at once: whose token this is, and what they may do with
        # it. Asking only for the roles left every renewed session identified as `sub=""`, which
        # an app keying anything off the returned identity would have keyed off nothing.
        claims = await self._userinfo(tokens["access_token"])
        sub = claims.get("sub") or ""
        if not sub:
            raise ValueError("the provider returned no subject for this access token")
        roles = _roles_of(claims)
        return Session(
            identity=Identity(iss=self.issuer, sub=sub, claims=claims, roles=roles),
            access_token=tokens["access_token"],
            id_token=tokens.get("id_token", ""),
            refresh_token=tokens.get("refresh_token"),
            expires_at=tokens.get("expires_at"),
        )


def _check_algorithm(id_token: str) -> None:
    """Refuses an ID token signed with anything we are not willing to trust (REQ-095)."""
    import base64
    import json

    header_segment = id_token.split(".")[0]
    padding = "=" * (-len(header_segment) % 4)
    header = json.loads(base64.urlsafe_b64decode(header_segment + padding))
    alg = header.get("alg", "")
    if alg not in ALLOWED_ALGORITHMS:
        raise ValueError(f'refusing an ID token signed with "{alg or "none"}"')
