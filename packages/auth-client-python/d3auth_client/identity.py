"""Who somebody is, as far as a consuming app is concerned (REQ-093).

An identity is ``(iss, sub)`` and nothing else. Not the email — an email can change, can be
reassigned, and can be claimed by somebody who has not proved they own it. An app that keys its
accounts on the email address is one unverified sign-up away from handing over somebody else's
data, which is why this package offers no lookup helper that takes one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Identity:
    """The person a token describes, and what they may do in *this* app."""

    iss: str
    sub: str
    claims: dict[str, Any] = field(default_factory=dict)
    roles: list[str] = field(default_factory=list)


def identity_key(identity: Identity | tuple[str, str]) -> str:
    """The key to store on a local account.

    Both halves matter: two issuers can use the same ``sub``, and one issuer's ``sub`` means
    nothing at another.
    """
    if isinstance(identity, tuple):
        iss, sub = identity
        return f"{iss}#{sub}"
    return f"{identity.iss}#{identity.sub}"


def is_same_identity(stored: str, identity: Identity) -> bool:
    """True when this token describes the same person as the stored key."""
    return stored == identity_key(identity)
