"""Client authentication and entitlements for the token issuer.

"Who are you?"            -> authenticate_client() returns the registered client
"What may you ask for?"   -> that client's allowed_scopes (its ENTITLEMENT)

The caller never chooses its identity. It may REQUEST scopes, but only ones
inside its entitlement; it cannot grant authority to itself.
"""

import os
import secrets
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

# Issuer-side configuration only. Real environment variables take precedence.
load_dotenv(Path(__file__).resolve().parent / ".env")

READ_CLASS_A = "inventory.read.class_a"
READ_CLASS_B = "inventory.read.class_b"
READ_CLASS_C = "inventory.read.class_c"
KNOWN_SCOPES = frozenset({READ_CLASS_A, READ_CLASS_B, READ_CLASS_C})

REGISTERED_CLIENTS = {
    "inventory-agent": {
        "secret_env": "CLIENT_SECRET_INVENTORY_AGENT",
        "identity": "inventory-agent",
        "allowed_scopes": {READ_CLASS_A, READ_CLASS_B, READ_CLASS_C},
    },
    "restricted-agent": {
        "secret_env": "CLIENT_SECRET_RESTRICTED_AGENT",
        "identity": "restricted-agent",
        "allowed_scopes": {READ_CLASS_B, READ_CLASS_C},
    },
}


@dataclass(frozen=True)
class Client:
    secret: bytes
    identity: str
    allowed_scopes: frozenset[str]


def load_clients() -> dict[str, Client]:
    """Build {client_id: Client}. Fail closed on missing/reused secrets or unknown scopes."""
    clients: dict[str, Client] = {}
    seen: set[bytes] = set()
    for client_id, cfg in REGISTERED_CLIENTS.items():
        secret = os.getenv(cfg["secret_env"])
        if not secret:
            raise RuntimeError(f"{cfg['secret_env']} must be set (secret for client '{client_id}')")
        if secret.encode() in seen:
            raise RuntimeError(f"{cfg['secret_env']} reuses another client's secret; secrets must be unique")
        unknown = set(cfg["allowed_scopes"]) - KNOWN_SCOPES
        if unknown:
            raise RuntimeError(f"client '{client_id}' is entitled to unknown scopes: {sorted(unknown)}")
        seen.add(secret.encode())
        clients[client_id] = Client(secret.encode(), cfg["identity"], frozenset(cfg["allowed_scopes"]))
    return clients


_CLIENTS = load_clients()

# Compared against when the client ID is unknown, so an unknown ID takes the
# same code path (and roughly the same time) as a wrong secret.
_DUMMY_SECRET = secrets.token_bytes(32)


def authenticate_client(client_id: str | None, client_secret: str | None) -> Client | None:
    """Return the registered client if its credentials are correct, else None."""
    if not client_id or not client_secret:
        return None
    client = _CLIENTS.get(client_id)
    expected = client.secret if client else _DUMMY_SECRET
    if not secrets.compare_digest(client_secret.encode(), expected):
        return None
    return client


def parse_scope(raw: str | None) -> frozenset[str] | None:
    """Parse a space-delimited scope string (OAuth style). None if empty or missing."""
    if not raw:
        return None
    scopes = frozenset(raw.split())
    return scopes or None
