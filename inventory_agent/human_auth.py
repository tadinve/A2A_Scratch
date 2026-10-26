"""Verify HUMAN JWTs at the Inventory Agent's HTTP boundary (Day 06.07).

The agent trusts the human Identity Service's PUBLIC keys, by kid, from
config/inventory_agent.json (override with INVENTORY_AGENT_CONFIG). It never
holds a private key, never sees a password, and never mints identity.
"""

import json
import logging
import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import jwt
from fastapi import HTTPException
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = Path(os.getenv("INVENTORY_AGENT_CONFIG", PROJECT_ROOT / "config" / "inventory_agent.json")).expanduser()

ALLOWED_ALGORITHMS = ["RS256"]                      # pinned: the token's alg header is not trusted
REQUIRED_CLAIMS = ["iss", "sub", "aud", "iat", "exp"]


@dataclass(frozen=True)
class HumanTrust:
    issuer: str
    audience: str
    keys: dict[str, RSAPublicKey]


@dataclass(frozen=True)
class Human:
    sub: str


def load_trust(path: Path = CONFIG_PATH) -> HumanTrust:
    """Fail closed on a missing or invalid config, or a key that isn't an RSA public key."""
    try:
        raw = json.loads(Path(path).read_text())
        issuer, audience, entries = raw["human_issuer"], raw["audience"], raw["trusted_human_keys"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise RuntimeError(f"agent config not usable at {path}: {exc}") from None
    if not (isinstance(issuer, str) and issuer and isinstance(audience, str) and audience
            and isinstance(entries, dict) and entries):
        raise RuntimeError(f"{path}: human_issuer, audience and trusted_human_keys are required")
    keys = {}
    for kid, raw_path in entries.items():
        key_path = Path(raw_path).expanduser()
        key_path = key_path if key_path.is_absolute() else PROJECT_ROOT / key_path
        try:
            key = load_pem_public_key(key_path.read_bytes())
        except (OSError, ValueError) as exc:
            raise RuntimeError(f"trusted key {kid!r} not loadable from {key_path}: {exc}") from None
        if not isinstance(key, RSAPublicKey):
            raise RuntimeError(f"trusted key {kid!r} is not an RSA public key")
        keys[kid] = key
    return HumanTrust(issuer, audience, keys)


def extract_bearer(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, _, token = authorization.strip().partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token or " " in token:
        return None
    return token


def verify_human(token: str, trust: HumanTrust) -> Human:
    """Return the verified human, or raise jwt.InvalidTokenError."""
    kid = jwt.get_unverified_header(token).get("kid")
    key = trust.keys.get(kid) if isinstance(kid, str) else None
    if key is None:
        raise jwt.InvalidTokenError("token kid is not a trusted human identity key")
    claims = jwt.decode(token, key, algorithms=ALLOWED_ALGORITHMS, issuer=trust.issuer,
                        audience=trust.audience, options={"require": REQUIRED_CLAIMS})
    sub = claims.get("sub")
    if not isinstance(sub, str) or not sub.strip():
        raise jwt.InvalidTokenError("empty sub")
    return Human(sub=sub)


# --------------------------------------------------------------------------- #
# The HTTP-boundary entry point (Day 06.07, step 4)
# --------------------------------------------------------------------------- #
_logger = logging.getLogger("uvicorn.error")
GENERIC_401 = "Human authentication required."


@lru_cache(maxsize=1)
def get_trust() -> HumanTrust:
    """Trusted keys from LOCAL config, loaded once. Never from a URL or the token itself."""
    return load_trust()


def authenticate_human(authorization: str | None) -> dict:
    """Return {"sub": ...} for a valid human JWT; otherwise raise HTTP 401.

    The 401 is deliberately generic: callers never learn whether the signature,
    the kid, the issuer, the audience or the expiry was wrong. The reason is
    logged server-side as an exception class name only, never the token.
    """
    token = extract_bearer(authorization)
    try:
        if token is None:
            raise jwt.InvalidTokenError("no bearer token")
        human = verify_human(token, get_trust())
    except jwt.InvalidTokenError as exc:
        _logger.warning("AGENT HUMAN AUTHN FAILED reason=%s",
                        type(exc).__name__ if token else "no bearer token")
        raise HTTPException(status_code=401, detail=GENERIC_401,
                            headers={"WWW-Authenticate": "Bearer"}) from None
    return {"sub": human.sub}
