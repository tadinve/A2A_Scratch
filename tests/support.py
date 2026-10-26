"""Shared test setup, imported ONCE as tests.support (Day 05.2: JWT bearer tokens).

Why not conftest.py? pytest imports conftest as `conftest`; importing it again as
`tests.conftest` runs it a second time, generating a second key pair the service
never loaded. A normal module is imported once, so there is one key pair.

Throwaway RSA key pairs and config files are created here, and both services are
pointed at them BEFORE they are imported, so tests never touch ~/secrets.
"""

import json
import os
import tempfile
import time
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def _keypair() -> tuple[bytes, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem


PRIVATE_PEM, PUBLIC_PEM = _keypair()            # the trusted issuer
ATTACKER_PRIVATE_PEM, _ = _keypair()            # someone else's key

_key_dir = Path(tempfile.mkdtemp(prefix="jwt-test-"))
PUBLIC_KEY_FILE = _key_dir / "key-1-public.pem"
PUBLIC_KEY_FILE.write_bytes(PUBLIC_PEM)
PRIVATE_KEY_FILE = _key_dir / "key-1-private.pem"
PRIVATE_KEY_FILE.write_bytes(PRIVATE_PEM)
PRIVATE_KEY_FILE.chmod(0o600)

# Day 05.8: a second key pair for rotation tests. Not trusted at startup.
KEY2_PRIVATE_PEM, KEY2_PUBLIC_PEM = _keypair()
KEY2_PUBLIC_FILE = _key_dir / "key-2-public.pem"
KEY2_PUBLIC_FILE.write_bytes(KEY2_PUBLIC_PEM)
KEY2_PRIVATE_FILE = _key_dir / "key-2-private.pem"
KEY2_PRIVATE_FILE.write_bytes(KEY2_PRIVATE_PEM)
KEY2_PRIVATE_FILE.chmod(0o600)

# Configs mirror the real starting state: issuer signs with key-1, service trusts key-1.
ISSUER_CONFIG_FILE = _key_dir / "issuer.json"
ISSUER_CONFIG_FILE.write_text(json.dumps({"active_kid": "key-1", "private_key_path": str(PRIVATE_KEY_FILE)}))
SERVICE_CONFIG_FILE = _key_dir / "inventory_service.json"
SERVICE_CONFIG_FILE.write_text(json.dumps({"trusted_keys": {"key-1": str(PUBLIC_KEY_FILE)}}))
os.environ["ISSUER_CONFIG"] = str(ISSUER_CONFIG_FILE)
os.environ["INVENTORY_SERVICE_CONFIG"] = str(SERVICE_CONFIG_FILE)

# Day 06.02: the Identity Service gets its OWN throwaway key and a temp user store.
IDENTITY_PRIVATE_PEM, IDENTITY_PUBLIC_PEM = _keypair()
IDENTITY_PRIVATE_FILE = _key_dir / "identity-key-1-private.pem"
IDENTITY_PRIVATE_FILE.write_bytes(IDENTITY_PRIVATE_PEM)
IDENTITY_PRIVATE_FILE.chmod(0o600)
IDENTITY_USERS_DB = _key_dir / "identity.db"
IDENTITY_CONFIG_FILE = _key_dir / "identity_service.json"
IDENTITY_CONFIG_FILE.write_text(json.dumps({
    "issuer": "a2a-human-identity-service", "audience": "inventory-agent", "token_lifetime_seconds": 300,
    "active_kid": "identity-key-1", "private_key_path": str(IDENTITY_PRIVATE_FILE),
    "users_db": str(IDENTITY_USERS_DB),
}))
os.environ["IDENTITY_SERVICE_CONFIG"] = str(IDENTITY_CONFIG_FILE)

# Day 06.07: the Inventory Agent trusts the identity PUBLIC key for human tokens.
IDENTITY_PUBLIC_FILE = _key_dir / "identity-key-1-public.pem"
IDENTITY_PUBLIC_FILE.write_bytes(IDENTITY_PUBLIC_PEM)
AGENT_CONFIG_FILE = _key_dir / "inventory_agent.json"
AGENT_CONFIG_FILE.write_text(json.dumps({
    "human_issuer": "a2a-human-identity-service", "audience": "inventory-agent",
    "trusted_human_keys": {"identity-key-1": str(IDENTITY_PUBLIC_FILE)},
}))
os.environ["INVENTORY_AGENT_CONFIG"] = str(AGENT_CONFIG_FILE)

READER_CLIENT = ("inventory-agent", "test-reader-client-secret")
RESTRICTED_CLIENT = ("restricted-agent", "test-restricted-client-secret")
os.environ["CLIENT_SECRET_INVENTORY_AGENT"] = READER_CLIENT[1]
os.environ["CLIENT_SECRET_RESTRICTED_AGENT"] = RESTRICTED_CLIENT[1]


ALL_READ_SCOPES = "inventory.read.class_a inventory.read.class_b inventory.read.class_c"


_DEFAULT = object()


def make_token(sub="inventory-agent", *, key=PRIVATE_PEM, algorithm="RS256", drop=(),
               scope=ALL_READ_SCOPES, kid=_DEFAULT, **overrides) -> str:
    """A token like the issuer's, with any claim overridden or dropped.

    Defaults to all three read scopes (so pre-05.5 tests exercise roles alone)
    and kid="key-1" (05.8). Pass kid=None for a token with no kid header.
    """
    now = int(time.time())
    claims = {"iss": "a2a-local-issuer", "sub": sub, "aud": "inventory-service",
              "scope": scope, "iat": now, "exp": now + 300}
    claims.update(overrides)
    for name in drop:
        claims.pop(name, None)
    headers = {} if kid is None else {"kid": "key-1" if kid is _DEFAULT else kid}
    return jwt.encode(claims, key, algorithm=algorithm, headers=headers)


READER_TOKEN = make_token("inventory-agent")
RESTRICTED_TOKEN = make_token("restricted-agent")

# Import the services only after their config paths are set.
from fastapi.testclient import TestClient  # noqa: E402

from inventory_service import app as service  # noqa: E402

CLASSES = {"WIDGET-A": "A", "WIDGET-B": "B", "WIDGET-C": "C"}
DETAILS = {
    "WIDGET-A": {"status": "found", "sku": "WIDGET-A", "name": "Standard Widget", "quantity": 30},
    "WIDGET-B": {"status": "found", "sku": "WIDGET-B", "name": "Heavy-duty Widget", "quantity": 12},
    "WIDGET-C": {"status": "found", "sku": "WIDGET-C", "name": "Mini Widget", "quantity": 0},
}


class RepoSpy:
    """Stands in for the repository and records every call."""

    def __init__(self):
        self.class_calls: list[str] = []
        self.detail_calls: list[str] = []
        self.classes = dict(CLASSES)
        self.class_error = False

    def get_classification(self, sku: str) -> dict:
        self.class_calls.append(sku)
        if self.class_error:
            return {"status": "error", "message": "Inventory is temporarily unavailable."}
        s = sku.strip().upper()
        if s not in self.classes:
            return {"status": "not_found", "sku": s}
        return {"status": "found", "sku": s, "inventory_class": self.classes[s]}

    def lookup_sku(self, sku: str) -> dict:
        self.detail_calls.append(sku)
        s = sku.strip().upper()
        return DETAILS.get(s, {"status": "not_found", "sku": s})

    @property
    def class_lookup(self) -> bool:
        return bool(self.class_calls)

    @property
    def detail_lookup(self) -> bool:
        return bool(self.detail_calls)

    @property
    def sqlite_touched(self) -> bool:
        return self.class_lookup or self.detail_lookup


def get(client, sku="WIDGET-A", token=None, *, headers=None):
    """GET /stock/{sku}, sending `Authorization: Bearer <token>` when a token is given.

    Extra headers must be passed explicitly as headers={...}; an unknown keyword
    raises TypeError instead of silently becoming a header.
    """
    all_headers = dict(headers or {})
    if token is not None:
        all_headers["Authorization"] = f"Bearer {token}"
    return client.get(f"/stock/{sku}", headers=all_headers)
