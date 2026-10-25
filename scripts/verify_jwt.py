"""Day 05.1: verify a JWT with the issuer's PUBLIC key.

    uv run python scripts/verify_jwt.py <token>
    uv run python scripts/issue_jwt.py | uv run python scripts/verify_jwt.py

The public key path comes from JWT_PUBLIC_KEY_PATH (default ~/secrets/jwt-public.pem).
The verifier never needs the private key.
"""

import os
import sys
from pathlib import Path

import jwt

# The verifier's own expectations. Deliberately NOT imported from the issuer:
# a service decides for itself which issuer and audience it trusts.
EXPECTED_ISSUER = "a2a-local-issuer"
EXPECTED_AUDIENCE = "inventory-service"
ALLOWED_ALGORITHMS = ["RS256"]  # pinned: the token's own "alg" header is not trusted
REQUIRED_CLAIMS = ["iss", "sub", "aud", "iat", "exp"]

DEFAULT_PUBLIC_KEY = Path.home() / "secrets" / "jwt-public.pem"


def verify_token(token: str, public_key_pem: bytes) -> dict:
    """Return the verified claims, or raise a jwt.InvalidTokenError subclass.

    PyJWT checks, in effect:
      - the algorithm is in ALLOWED_ALGORITHMS        -> InvalidAlgorithmError
      - the signature matches the public key           -> InvalidSignatureError
      - all REQUIRED_CLAIMS are present                -> MissingRequiredClaimError
      - exp is in the future                           -> ExpiredSignatureError
      - iss == EXPECTED_ISSUER                         -> InvalidIssuerError
      - aud contains EXPECTED_AUDIENCE                 -> InvalidAudienceError
    """
    jwt_decode = jwt.decode(
        token,
        public_key_pem,
        algorithms=ALLOWED_ALGORITHMS,
        issuer=EXPECTED_ISSUER,
        audience=EXPECTED_AUDIENCE,
        options={"require": REQUIRED_CLAIMS},
    )
    print(f"DEBUG: verified claims = {jwt_decode}")
    return jwt_decode


def main() -> int:
    token = sys.argv[1] if len(sys.argv) > 1 else sys.stdin.read().strip()
    if not token:
        print("usage: verify_jwt.py <token>   (or pipe a token on stdin)", file=sys.stderr)
        return 2
    print(f"DEBUG: verifying token = {token}")

    header, payload, signature = token.split(".")
    print(f"====> DEBUG: header = {header}  payload = {payload}  signature = {signature}")

    key_path = Path(os.environ.get("JWT_PUBLIC_KEY_PATH", DEFAULT_PUBLIC_KEY)).expanduser()
    try:
        claims = verify_token(token, key_path.read_bytes())
        print(f"DEBUG: verified claims = {claims}")
    except jwt.InvalidTokenError as exc:
        print(f"REJECTED: {type(exc).__name__}: {exc}")
        return 1

    print(f"VERIFIED: authenticated identity (sub) = {claims['sub']}")
    print(f"  iss={claims['iss']}  aud={claims['aud']}  iat={claims['iat']}  exp={claims['exp']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
