"""Authentication: turn an `Authorization: Bearer <jwt>` header into a trusted principal.

Day 05.2: the identity is the token's verified `sub` claim.
Day 05.5: the principal also carries the token's verified `scope`, the authority
the issuer approved for THIS token. Nothing here knows about roles or SQLite.
"""

import logging
import os
from dataclasses import dataclass
from pathlib import Path

import jwt
from dotenv import load_dotenv

from inventory_service.tokens import load_delegation_trust, load_trusted_keys, verify_delegation, verify_token

# Service-side configuration only. Real environment variables take precedence.
load_dotenv(Path(__file__).resolve().parent / ".env")

logger = logging.getLogger("uvicorn.error")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = Path(
    os.getenv("INVENTORY_SERVICE_CONFIG", PROJECT_ROOT / "config" / "inventory_service.json")
).expanduser()

# Day 05.8: {kid: public key}, loaded once at startup. Trusting a new key or
# retiring an old one is a config change plus a restart. A bad config stops startup.
_TRUSTED_KEYS = load_trusted_keys(CONFIG_PATH, PROJECT_ROOT)

# Day 06.09B: the Delegation Authority's public keys (None = delegation not configured).
_DELEGATION_TRUST = load_delegation_trust(CONFIG_PATH, PROJECT_ROOT)


@dataclass(frozen=True)
class Principal:
    """Who is calling (from `sub`) and what this token permits (from `scope`)."""
    identity: str
    scopes: frozenset[str]


def extract_bearer_token(authorization: str | None) -> str | None:
    """Return the token from 'Bearer <token>', or None if the header is unusable."""
    if not authorization:
        return None                                  # header missing or empty
    scheme, _, token = authorization.strip().partition(" ")
    if scheme.lower() != "bearer":                   # auth schemes are case-insensitive
        return None                                  # e.g. "Basic ...", or a bare token
    token = token.strip()
    if not token or " " in token:
        return None                                  # "Bearer" alone, or extra junk
    return token


def authenticate(authorization: str | None) -> Principal | None:
    """Return the verified principal, or None. Never raises for a bad token."""
    token = extract_bearer_token(authorization)
    if token is None:
        logger.warning("AUTHN FAILED reason=no bearer token")
        return None
    try:
        claims = verify_token(token, _TRUSTED_KEYS)
    except jwt.InvalidTokenError as exc:
        # Log the reason class only, never the token itself.
        logger.warning("AUTHN FAILED reason=%s", type(exc).__name__)
        return None

    sub = claims.get("sub")
    if not isinstance(sub, str) or not sub.strip():
        logger.warning("AUTHN FAILED reason=empty sub")
        return None
    scope = claims.get("scope")
    if not isinstance(scope, str):
        # A malformed scope claim means a malformed token: reject it outright.
        logger.warning("AUTHN FAILED reason=scope claim is not a string")
        return None
    return Principal(identity=sub, scopes=frozenset(scope.split()))


@dataclass(frozen=True)
class Delegation:
    """A verified grant: `human` authorized `actor` for `scopes`, at this service, until exp."""
    human: str
    actor: str
    scopes: frozenset[str]


def authenticate_delegation(token: str, machine_identity: str) -> Delegation | None:
    """Verify a delegation JWT AND bind it to the authenticated machine. None on any failure."""
    if _DELEGATION_TRUST is None:
        logger.warning("DELEGATION FAILED reason=delegation not configured")
        return None
    issuer, keys = _DELEGATION_TRUST
    try:
        claims = verify_delegation(token, issuer, keys)
    except jwt.InvalidTokenError as exc:
        logger.warning("DELEGATION FAILED reason=%s", type(exc).__name__)
        return None
    if claims["act"]["sub"] != machine_identity:
        # A valid grant for SOME agent, presented by a different one: not yours to use.
        logger.warning("DELEGATION FAILED reason=actor mismatch act.sub=%s machine=%s",
                       claims["act"]["sub"], machine_identity)
        return None
    return Delegation(human=claims["sub"], actor=claims["act"]["sub"], scopes=frozenset(claims["scope"].split()))
