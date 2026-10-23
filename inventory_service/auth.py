"""Authentication: turn an API key into a trusted identity.

Day 04, increment 1. The service owns the key -> identity mapping. Each caller
gets only its own key. Nothing here knows about roles, permissions, or SQLite.
"""

import os
import secrets
from pathlib import Path

from dotenv import load_dotenv

# Service-side configuration only. Real environment variables take precedence.
load_dotenv(Path(__file__).resolve().parent / ".env")

# Identity -> name of the environment variable holding that identity's key.
# The identity names live in code; the key values never do.
IDENTITY_KEY_ENV_VARS = {
    "inventory-agent": "INVENTORY_AGENT_API_KEY",
    "restricted-agent": "RESTRICTED_AGENT_API_KEY",
}


def _load_key_to_identity() -> dict[bytes, str]:
    """Build {key: identity}. Fail closed if any key is missing or reused."""
    key_to_identity: dict[bytes, str] = {}
    for identity, env_var in IDENTITY_KEY_ENV_VARS.items():
        key = os.getenv(env_var)
        if not key:
            raise RuntimeError(f"{env_var} must be set (key for identity '{identity}')")
        if key.encode() in key_to_identity:
            # Two identities sharing a key would make "who is calling" ambiguous.
            raise RuntimeError(f"{env_var} reuses another identity's key; keys must be unique")
        key_to_identity[key.encode()] = identity
    return key_to_identity


# Loaded once at import, so a misconfigured service refuses to start.
_KEY_TO_IDENTITY = _load_key_to_identity()


def authenticate(api_key: str | None) -> str | None:
    """Return the identity that owns this key, or None if it matches no one."""
    if not api_key:
        return None
    supplied = api_key.encode()
    identity = None
    # Compare against every key in constant time; don't stop at the first match.
    for known_key, known_identity in _KEY_TO_IDENTITY.items():
        if secrets.compare_digest(supplied, known_key):
            identity = known_identity
    return identity
