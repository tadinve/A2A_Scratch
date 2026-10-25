"""Day 05.1: issue a signed JWT (RS256) with the private key.

    uv run python scripts/issue_jwt.py                    # sub = inventory-agent
    uv run python scripts/issue_jwt.py --sub restricted-agent

The private key path comes from JWT_PRIVATE_KEY_PATH (default ~/secrets/jwt-private.pem).
Only the issuer ever reads this file.
"""

import argparse
import os
import time
from pathlib import Path

import jwt

ISSUER = "a2a-local-issuer"
AUDIENCE = "inventory-service"
LIFETIME_SECONDS = 300  # five minutes
ALGORITHM = "RS256"

DEFAULT_PRIVATE_KEY = Path.home() / "secrets" / "jwt-private.pem"


def issue_token(
    private_key_pem: bytes,
    sub: str,
    *,
    iss: str = ISSUER,
    aud: str = AUDIENCE,
    lifetime: int = LIFETIME_SECONDS,
    now: int | None = None,
) -> str:
    """Build the five claims and sign them. `now` lets tests make expired tokens."""
    issued_at = int(time.time()) if now is None else now
    claims = {
        "iss": iss,                       # who issued it
        "sub": sub,                       # who it represents
        "aud": aud,                       # which service may accept it
        "iat": issued_at,                 # when it was issued
        "exp": issued_at + lifetime,      # when it stops being valid
    }
    jwt_encode = jwt.encode(claims, private_key_pem, algorithm=ALGORITHM)
    return jwt_encode


def main() -> None:
    parser = argparse.ArgumentParser(description="Issue an RS256-signed JWT.")
    parser.add_argument("--sub", default="inventory-agent", help="identity the token represents")
    args = parser.parse_args()

    key_path = Path(os.environ.get("JWT_PRIVATE_KEY_PATH", DEFAULT_PRIVATE_KEY)).expanduser()
    print(issue_token(key_path.read_bytes(), args.sub))


if __name__ == "__main__":
    main()
