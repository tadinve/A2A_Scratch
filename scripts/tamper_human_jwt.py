"""Day 06.05: payload-tampering experiment against a real human JWT.

    uv run python scripts/tamper_human_jwt.py "$TOKEN"          # sub -> user-002
    uv run python scripts/tamper_human_jwt.py "$TOKEN" admin    # sub -> admin

Plays an attacker who has Alice's token and the Identity Service's PUBLIC key
(public keys are meant to be shared). Every forgery must be rejected by the same
verifier the Inventory Agent uses. The private key is never read.
"""

import base64
import hashlib
import hmac
import json
import os
import sys
from pathlib import Path

import jwt
from cryptography.hazmat.primitives.serialization import load_pem_public_key

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.verify_human_jwt import verify_human_token  # noqa: E402


def b64url_decode(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def verdict(token: str, public_key) -> tuple[bool, str]:
    """(accepted?, description) from the agent's verifier."""
    try:
        claims = verify_human_token(token, public_key)
        return True, f"ACCEPTED sub={claims['sub']}"
    except jwt.InvalidTokenError as exc:
        return False, f"REJECTED {type(exc).__name__}"


def run_experiments(token: str, public_pem: bytes, target_sub: str = "user-002", verbose: bool = True) -> list[tuple[str, bool]]:
    """Return [(attack, rejected?)]. The original token must be accepted; every forgery rejected."""
    public_key = load_pem_public_key(public_pem)
    header_b64, payload_b64, signature_b64 = token.split(".")
    claims = json.loads(b64url_decode(payload_b64))
    results: list[tuple[str, bool]] = []

    def show(label, forged, expect_accept=False):
        accepted, text = verdict(forged, public_key)
        ok = accepted if expect_accept else not accepted
        results.append((label, ok))
        if verbose:
            print(f"[{'PASS' if ok else 'FAIL'}] {label:<52} -> {text}")

    if verbose:
        print("Original payload:", json.dumps(claims))
    show("0. original token, untouched", token, expect_accept=True)

    # 1. The experiment: change ONLY the payload segment, keep header + signature.
    forged_claims = dict(claims, sub=target_sub)
    forged_payload_b64 = b64url_encode(json.dumps(forged_claims, separators=(",", ":")).encode())
    forged = ".".join([header_b64, forged_payload_b64, signature_b64])
    if verbose:
        print(f"\nForged payload:  {json.dumps(forged_claims)}")
        print(f"header    segment unchanged: {forged.split('.')[0] == header_b64}")
        print(f"payload   segment changed:   {forged.split('.')[1] != payload_b64}")
        print(f"signature segment unchanged: {forged.split('.')[2] == signature_b64}\n")
    show(f"1. sub -> {target_sub}, original signature kept", forged)

    # 2. Same idea for other claims an attacker would want.
    for label, change in [("2. exp pushed out 1 hour", {"exp": claims["exp"] + 3600}),
                          ("3. aud -> inventory-service", {"aud": "inventory-service"})]:
        p = b64url_encode(json.dumps(dict(claims, **change), separators=(",", ":")).encode())
        show(label + ", original signature kept", ".".join([header_b64, p, signature_b64]))

    # 4. "I have the public key, so I'll just re-sign it." RSA can't sign with a public key.
    try:
        jwt.encode(forged_claims, public_pem, algorithm="RS256", headers={"kid": "identity-key-1"})
        resigned = True
    except Exception as exc:                                    # noqa: BLE001
        resigned = False
        reason = type(exc).__name__
    results.append(("4. re-sign with the PUBLIC key", not resigned))
    if verbose:
        print(f"[{'PASS' if not resigned else 'FAIL'}] {'4. re-sign with the PUBLIC key':<52} -> "
              f"{'impossible: ' + reason if not resigned else 'SIGNED (bad!)'}")

    # 5. Algorithm confusion: HMAC-SHA256 keyed with the public key's bytes, header says HS256.
    hs_header = b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT", "kid": "identity-key-1"},
                                         separators=(",", ":")).encode())
    signing_input = f"{hs_header}.{forged_payload_b64}".encode()
    mac = b64url_encode(hmac.new(public_pem, signing_input, hashlib.sha256).digest())
    show("5. alg confusion: HS256 keyed with public key", f"{hs_header}.{forged_payload_b64}.{mac}")

    # 6. Strip the signature entirely.
    none_header = b64url_encode(json.dumps({"alg": "none", "typ": "JWT", "kid": "identity-key-1"},
                                           separators=(",", ":")).encode())
    show("6. alg=none, no signature", f"{none_header}.{forged_payload_b64}.")
    return results


def main() -> int:
    token = sys.argv[1] if len(sys.argv) > 1 else sys.stdin.read().strip()
    if token.count(".") != 2:
        print(__doc__, file=sys.stderr)
        return 2
    target = sys.argv[2] if len(sys.argv) > 2 else "user-002"
    key_path = Path(os.environ.get("IDENTITY_PUBLIC_KEY_PATH", "~/secrets/keys/identity-key-1-public.pem")).expanduser()
    results = run_experiments(token, key_path.read_bytes(), target)
    ok = all(passed for _, passed in results)
    print(f"\n{sum(p for _, p in results)}/{len(results)} as expected")
    print("ALL PASS: the public key verifies but cannot forge" if ok else "SOME CHECKS FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
