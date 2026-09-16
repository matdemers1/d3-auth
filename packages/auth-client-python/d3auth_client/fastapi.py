"""The back-channel logout endpoint, ready to mount (REQ-090, REQ-099).

    app.include_router(backchannel_router(handler))

Nothing here decides anything: the handler verifies the token and the app ends its own session.
This exists so every consumer does not have to remember the status codes.
"""

from __future__ import annotations

from fastapi import APIRouter, Form, Response

from .logout_token import BackchannelHandler


def backchannel_router(handler: BackchannelHandler, *, path: str = "/backchannel-logout") -> APIRouter:
    """A router with one POST endpoint that applies a logout token at most once."""
    router = APIRouter()

    @router.post(path)
    async def backchannel_logout(logout_token: str = Form(default="")) -> Response:
        result = await handler.handle(logout_token)
        # A rejected token is a bad request; a repeat is a success, because the session is
        # already gone and saying otherwise would make the provider retry for nothing.
        return Response(status_code=200 if result.ok else 400)

    return router
