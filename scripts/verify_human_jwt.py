"""Day 06.04: verify a HUMAN JWT the way the Inventory Agent will: public key only.

    uv run python scripts/verify_human_jwt.py <token>
    ... | uv run python scripts/verify_human_jwt.py          (token on stdin)

Trusted key: ~/secrets/keys/identity-key-1-public.pem (override with IDENTITY_PUBLIC_KEY_PATH).
Never needs, and never reads, the Identity Service's private key.
"""

import os
import sys
from pathlib import Path

import jwt
from cryptography.hazmat.primitives.serialization import load_pem_public_key

EXPECTED_ISSUER = "a2a-human-identity-service"
EXPECTED_AUDIENCE = "inventory-agent"          # this verifier IS the agent
ALLOWED_ALGORITHMS = ["RS256"]
REQUIRED_CLAIMS = ["iss", "sub", "aud", "iat", "exp"]
TRUSTED_KID = "identity-key-1"


def verify_human_token(token: str, public_key) -> dict:
    """Return verified claims or raise jwt.InvalidTokenError."""
    if jwt.get_unverified_header(token).get("kid") != TRUSTED_KID:
        raise jwt.InvalidTokenError("token kid is not the trusted identity key")
    return jwt.decode(token, public_key, algorithms=ALLOWED_ALGORITHMS, issuer=EXPECTED_ISSUER,
                      audience=EXPECTED_AUDIENCE, options={"require": REQUIRED_CLAIMS})


def main() -> int:
    token = sys.argv[1] if len(sys.argv) > 1 else sys.stdin.read().strip()
    if not token:
        print(__doc__, file=sys.stderr)
        return 2
    key_path = Path(os.environ.get("IDENTITY_PUBLIC_KEY_PATH", "~/secrets/keys/identity-key-1-public.pem")).expanduser()
    try:
        claims = verify_human_token(token, load_pem_public_key(key_path.read_bytes()))
    except jwt.InvalidTokenError as exc:
        print(f"REJECTED: {type(exc).__name__}: {exc}")
        return 1
    print(f"VERIFIED human: sub={claims['sub']}  iss={claims['iss']}  aud={claims['aud']}  "
          f"lifetime={claims['exp'] - claims['iat']}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
