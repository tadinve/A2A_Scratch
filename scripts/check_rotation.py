"""Day 05.8: live key-rotation checks against the running issuer and service.

    uv run python scripts/check_rotation.py save              # keep a token from the CURRENT key
    uv run python scripts/check_rotation.py check single      # only key-1 everywhere
    uv run python scripts/check_rotation.py check overlap     # service trusts key-1 + key-2, issuer signs key-2
    uv run python scripts/check_rotation.py check retired     # service trusts key-2 only

`save` stores one token in ~/secrets/rotation-old-token.jwt (mode 600). Tokens
live 300 s, so finish the rotation steps within five minutes of saving.
Uses the agent's client credentials. Never reads any private key.
"""

import base64
import json
import os
import sys
from pathlib import Path

import httpx
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / "inventory_agent" / ".env")

ISSUER = os.environ.get("INVENTORY_ISSUER_URL", "http://127.0.0.1:8001").rstrip("/")
SERVICE = os.environ.get("INVENTORY_SERVICE_URL", "http://127.0.0.1:8000").rstrip("/")
SAVED = Path.home() / "secrets" / "rotation-old-token.jwt"
SCOPE = "inventory.read.class_b"

# phase -> (expected status for the SAVED key-1 token, expected kid + status for a FRESH token)
EXPECT = {
    "single":  {"saved": 200, "fresh_kid": "key-1", "fresh": 200},
    "overlap": {"saved": 200, "fresh_kid": "key-2", "fresh": 200},
    "retired": {"saved": 401, "fresh_kid": "key-2", "fresh": 200},
}


def kid_of(token: str) -> str:
    """The token's kid, or '(none)'. No kid means the issuer predates 05.8: restart it."""
    header = token.split(".")[0]
    kid = json.loads(base64.urlsafe_b64decode(header + "=" * (-len(header) % 4))).get("kid")
    return kid if isinstance(kid, str) and kid else "(none)"


def fresh_token() -> str:
    r = httpx.post(f"{ISSUER}/token", timeout=5, headers={
        "X-Client-ID": os.environ.get("INVENTORY_CLIENT_ID", "inventory-agent"),
        "X-Client-Secret": os.environ.get("INVENTORY_CLIENT_SECRET", ""),
        "X-Scope": SCOPE,
    })
    if r.status_code != 200:
        sys.exit(f"issuer returned HTTP {r.status_code}: {r.text}")
    return r.json()["access_token"]


def stock_status(token: str) -> int:
    return httpx.get(f"{SERVICE}/stock/WIDGET-B", timeout=5,
                     headers={"Authorization": f"Bearer {token}"}).status_code


def main() -> int:
    if len(sys.argv) >= 2 and sys.argv[1] == "save":
        token = fresh_token()
        SAVED.parent.mkdir(parents=True, exist_ok=True)
        SAVED.write_text(token)
        SAVED.chmod(0o600)
        print(f"saved a token with kid={kid_of(token)} to {SAVED} (valid 300 s)")
        return 0

    if len(sys.argv) < 3 or sys.argv[1] != "check" or sys.argv[2] not in EXPECT:
        print(__doc__)
        return 2
    want = EXPECT[sys.argv[2]]
    ok = True

    if SAVED.exists():
        saved = SAVED.read_text().strip()
        got = stock_status(saved)
        passed = kid_of(saved) == "key-1" and got == want["saved"]
        ok &= passed
        print(f"[{'PASS' if passed else 'FAIL'}] saved token  kid={kid_of(saved):<6} -> HTTP {got} "
              f"(want kid=key-1, {want['saved']})")
    elif sys.argv[2] == "single":
        print("[SKIP] no saved token yet (expected before `save`)")
    else:
        ok = False
        print("[FAIL] no saved token: run `check_rotation.py save` during the single-key phase")

    token = fresh_token()
    kid, got = kid_of(token), stock_status(token)
    passed = kid == want["fresh_kid"] and got == want["fresh"]
    ok &= passed
    print(f"[{'PASS' if passed else 'FAIL'}] fresh token  kid={kid:<6} -> HTTP {got} "
          f"(want kid={want['fresh_kid']}, {want['fresh']})")

    if "(none)" in (kid, kid_of(SAVED.read_text().strip()) if SAVED.exists() else ""):
        print("hint: a token with no kid came from an issuer running pre-05.8 code. Restart the issuer.")
    print("ALL PASS" if ok else "SOME CHECKS FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
