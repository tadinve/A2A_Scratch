"""Token creation and signing. The private key lives here and nowhere else.

Day 05.8: which key signs is CONFIGURATION, not code. config/issuer.json says

    {"active_kid": "key-2", "private_key_path": "~/secrets/keys/key-2-private.pem"}

and every token's header carries that `kid`, so verifiers can pick the matching
public key. Rotating keys = new key pair + config change + restart. No code change.
"""

import json
import os
import time
from pathlib import Path

import jwt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent / ".env")

ISSUER = "a2a-local-issuer"
AUDIENCE = "inventory-service"
LIFETIME_SECONDS = 300
ALGORITHM = "RS256"


def load_private_key(path: Path) -> RSAPrivateKey:
    """Load the signing key. Fail closed if it's missing, not private, or not RSA."""
    try:
        pem = Path(path).expanduser().read_bytes()
    except OSError as exc:
        raise RuntimeError(f"JWT private key not readable at {path}: {exc.strerror}") from None
    try:
        key = load_pem_private_key(pem, password=None)
    except (ValueError, TypeError):
        # Includes pointing at the PUBLIC key by mistake.
        raise RuntimeError(f"{path} is not an unencrypted PEM private key") from None
    if not isinstance(key, RSAPrivateKey):
        raise RuntimeError(f"{path} is not an RSA private key (RS256 needs RSA)")
    return key


PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = Path(os.getenv("ISSUER_CONFIG", PROJECT_ROOT / "config" / "issuer.json")).expanduser()


def resolve_path(raw: str) -> Path:
    """'~' expands to home; relative paths are relative to the project root."""
    path = Path(raw).expanduser()
    return path if path.is_absolute() else PROJECT_ROOT / path


def load_signing_config(config_path: Path) -> tuple[str, RSAPrivateKey]:
    """Read config/issuer.json -> (active_kid, private key). Fail closed on any problem."""
    try:
        config = json.loads(Path(config_path).read_text())
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"issuer config not readable at {config_path}: {exc}") from None
    kid = config.get("active_kid") if isinstance(config, dict) else None
    key_path = config.get("private_key_path") if isinstance(config, dict) else None
    if not isinstance(kid, str) or not kid.strip():
        raise RuntimeError(f"{config_path}: active_kid must be a non-empty string")
    if not isinstance(key_path, str) or not key_path.strip():
        raise RuntimeError(f"{config_path}: private_key_path must be a non-empty string")
    return kid, load_private_key(resolve_path(key_path))


ACTIVE_KID, _PRIVATE_KEY = load_signing_config(CONFIG_PATH)


def format_scope(scopes) -> str:
    """Canonical space-delimited scope string, e.g. 'inventory.read.class_b inventory.read.class_c'."""
    return " ".join(sorted(scopes))


def issue_access_token(identity: str, scopes, *, now: int | None = None, audience: str = AUDIENCE) -> str:
    """Sign a token for an identity and scopes the issuer has ALREADY approved.

    `identity` must come from authenticate_client(), and `scopes` must already be
    checked against that client's entitlement. Neither comes straight from the request.
    `now` exists only so tests can create expired tokens.
    """
    issued_at = int(time.time()) if now is None else now
    claims = {
        "iss": ISSUER,
        "sub": identity,
        "aud": audience,
        "scope": format_scope(scopes),
        "iat": issued_at,
        "exp": issued_at + LIFETIME_SECONDS,
    }
    # `kid` tells verifiers WHICH public key to try. It selects a key; it proves nothing.
    return jwt.encode(claims, _PRIVATE_KEY, algorithm=ALGORITHM, headers={"kid": ACTIVE_KID})
