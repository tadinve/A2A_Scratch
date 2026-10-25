"""JWT verification for the inventory service (Days 05.2-05.8).

The service holds only PUBLIC keys: it can verify tokens but never mint them.

Day 05.8: the service trusts a SET of keys, {kid: public key}, loaded from
config/inventory_service.json. A token's `kid` header selects which trusted key
to try. The kid is unverified input: it only picks a candidate, and the
signature check with that key is what actually authenticates the token.
"""

import json
from pathlib import Path

import jwt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

# The service's own trust decisions. The caller can't influence any of these.
EXPECTED_ISSUER = "a2a-local-issuer"
EXPECTED_AUDIENCE = "inventory-service"
ALLOWED_ALGORITHMS = ["RS256"]  # pinned: the token's "alg" header is not trusted
REQUIRED_CLAIMS = ["iss", "sub", "aud", "iat", "exp", "scope"]  # Day 05.5: scope required


def load_public_key(path: Path) -> RSAPublicKey:
    """Load and sanity-check the issuer's public key. Fail closed on any problem."""
    try:
        pem = Path(path).expanduser().read_bytes()
    except OSError as exc:
        raise RuntimeError(f"JWT public key not readable at {path}: {exc.strerror}") from None
    try:
        key = load_pem_public_key(pem)
    except ValueError:
        # Includes the mistake of pointing at the PRIVATE key file.
        raise RuntimeError(f"{path} is not a PEM public key") from None
    if not isinstance(key, RSAPublicKey):
        raise RuntimeError(f"{path} is not an RSA public key (RS256 needs RSA)")
    return key


class MissingKeyIdError(jwt.InvalidTokenError):
    """The token header has no usable `kid`."""


class UnknownKeyIdError(jwt.InvalidTokenError):
    """The token names a key this service does not (or no longer) trusts."""


def load_trusted_keys(config_path: Path, project_root: Path) -> dict[str, RSAPublicKey]:
    """Read {"trusted_keys": {kid: path}} -> {kid: public key}. Fail closed on any problem."""
    try:
        config = json.loads(Path(config_path).read_text())
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"service config not readable at {config_path}: {exc}") from None
    entries = config.get("trusted_keys") if isinstance(config, dict) else None
    if not isinstance(entries, dict) or not entries:
        raise RuntimeError(f"{config_path}: trusted_keys must be a non-empty object")
    trusted = {}
    for kid, raw_path in entries.items():
        if not isinstance(kid, str) or not kid.strip() or not isinstance(raw_path, str):
            raise RuntimeError(f"{config_path}: each trusted key needs a string kid and path")
        path = Path(raw_path).expanduser()
        trusted[kid] = load_public_key(path if path.is_absolute() else project_root / path)
    return trusted


def verify_token(token: str, trusted_keys: dict[str, RSAPublicKey]) -> dict:
    """Return verified claims, or raise a jwt.InvalidTokenError subclass."""
    # Reading the header is safe: nothing in it is trusted yet.
    kid = jwt.get_unverified_header(token).get("kid")
    if not isinstance(kid, str) or not kid:
        raise MissingKeyIdError("token header has no kid")
    public_key = trusted_keys.get(kid)
    if public_key is None:
        raise UnknownKeyIdError("token kid is not a trusted key")
    # Now verify EVERYTHING with the selected key. A forged kid just picks the
    # wrong key, and the signature check fails.
    return jwt.decode(
        token,
        public_key,
        algorithms=ALLOWED_ALGORITHMS,
        issuer=EXPECTED_ISSUER,
        audience=EXPECTED_AUDIENCE,
        options={"require": REQUIRED_CLAIMS},
    )
