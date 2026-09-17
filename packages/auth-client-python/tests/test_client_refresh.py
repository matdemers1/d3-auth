"""REQ-097 — a renewed session still knows whose it is.

`refresh()` renews the access token and re-reads the roles, which is the whole point: a grant
changes between renewals and the app has to notice. But a session is `(iss, sub)` before it is
anything else, and the first version of this method built its identity from an empty claims
dict — so every renewed session claimed to belong to `sub=""`. An app that keyed anything off
the returned identity would have keyed it off nothing.
"""

from __future__ import annotations

import pytest

from d3auth_client import D3AuthClient

ISSUER = "https://auth.example.test"


class FakeApp:
    """Stands in for the Authlib client: the two calls `refresh()` makes, and what they return."""

    def __init__(self, userinfo: dict, tokens: dict) -> None:
        self._userinfo = userinfo
        self._tokens = tokens
        self.userinfo_calls = 0

    async def load_server_metadata(self) -> dict:
        return {"userinfo_endpoint": f"{ISSUER}/oidc/me", "token_endpoint": f"{ISSUER}/oidc/token"}

    async def fetch_access_token(self, **_: object) -> dict:
        return self._tokens

    async def get(self, _url: str, **_kwargs: object):
        self.userinfo_calls += 1

        class Response:
            def __init__(self, payload: dict) -> None:
                self._payload = payload

            def json(self) -> dict:
                return self._payload

        return Response(self._userinfo)


def client_with(app: FakeApp) -> D3AuthClient:
    client = D3AuthClient(issuer=ISSUER, client_id="an-app", client_secret="a-secret")
    client.app = app  # type: ignore[assignment]
    return client


async def test_a_renewed_session_carries_the_subject_it_belongs_to():
    app = FakeApp(
        userinfo={"sub": "a-person", "roles": ["member"]},
        tokens={"access_token": "new-access", "refresh_token": "new-refresh", "expires_at": 1},
    )
    session = await client_with(app).refresh("old-refresh")

    assert session.identity.sub == "a-person"
    assert session.identity.iss == ISSUER
    assert session.identity.roles == ["member"]
    assert session.access_token == "new-access"
    assert session.refresh_token == "new-refresh"


async def test_the_subject_and_the_roles_cost_one_call_between_them():
    """Both come from userinfo, so asking twice would be two round trips per renewal."""
    app = FakeApp(
        userinfo={"sub": "a-person", "roles": []},
        tokens={"access_token": "new-access"},
    )
    await client_with(app).refresh("old-refresh")
    assert app.userinfo_calls == 1


async def test_a_userinfo_answer_with_no_subject_is_refused():
    """An access token that identifies nobody cannot renew a session."""
    app = FakeApp(userinfo={"roles": ["member"]}, tokens={"access_token": "new-access"})
    with pytest.raises(ValueError, match="no subject"):
        await client_with(app).refresh("old-refresh")
