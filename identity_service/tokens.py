"""Sign human identity tokens. Only the Identity Service holds this private key."""

import time
from pathlib import Path

import jwt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from identity_service.config import IdentityConfig


def load_private_key(path: Path) -> RSAPrivateKey:
    try:
        pem = Path(path).read_bytes()
    except OSError as exc:
        raise RuntimeError(f"identity private key not readable at {path}: {exc.strerror}") from None
    try:
        key = load_pem_private_key(pem, password=None)
    except (ValueError, TypeError):
        raise RuntimeError(f"{path} is not an unencrypted PEM private key") from None
    if not isinstance(key, RSAPrivateKey):
        raise RuntimeError(f"{path} is not an RSA private key")
    return key


def issue_user_token(cfg: IdentityConfig, key: RSAPrivateKey, user_id: str, *, now: int | None = None) -> str:
    """Claims for an ALREADY authenticated user. No password, no email in the token."""
    issued_at = int(time.time()) if now is None else now
    claims = {
        "iss": cfg.issuer,
        "sub": user_id,
        "aud": cfg.audience,
        "iat": issued_at,
        "exp": issued_at + cfg.token_lifetime_seconds,
    }
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": cfg.active_kid})
