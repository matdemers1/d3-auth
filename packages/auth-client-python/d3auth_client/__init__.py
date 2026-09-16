"""D3 Auth relying-party helper for FastAPI and Starlette.

Ten rules make up the consumer contract (docs/consumer-contract.md in the provider's repo); this
package exists so a consuming app gets the four easiest to get wrong for free: a pinned algorithm
list, identity by (iss, sub), roles refreshed on every renewal, and a back-channel logout handler
that is idempotent by jti.
"""

from .client import D3AuthClient, Session, SsoMode, SsoUnavailable
from .identity import Identity, identity_key, is_same_identity
from .logout_token import (
    ALLOWED_ALGORITHMS,
    LOGOUT_EVENT,
    BackchannelHandler,
    BackchannelResult,
    KeySet,
    LogoutTokenError,
    SeenEvents,
    VerifiedLogout,
    verify_logout_token,
)

__all__ = [
    "ALLOWED_ALGORITHMS",
    "LOGOUT_EVENT",
    "BackchannelHandler",
    "BackchannelResult",
    "D3AuthClient",
    "Identity",
    "KeySet",
    "LogoutTokenError",
    "SeenEvents",
    "Session",
    "SsoMode",
    "SsoUnavailable",
    "VerifiedLogout",
    "identity_key",
    "is_same_identity",
    "verify_logout_token",
]
