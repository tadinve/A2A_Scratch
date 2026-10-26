"""Day 06.09A live evidence: X-Human-User never changes an access decision.

Needs the inventory service (:8000) and the token issuer (:8001) running.

    uv run python scripts/check_identity_forwarding.py

Gets REAL machine tokens from the issuer (reader with all classes, restricted
with B and C), then calls the inventory service with no claim, user-001 and
admin. Prints the decision matrix. Every row must be identical across claims.
The service log shows each claim as `unverified_human_claim=...`.
"""

import os
import sys
from pathlib import Path

import httpx
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / "inventory_agent" / ".env")

ISSUER = os.environ.get("INVENTORY_ISSUER_URL", "http://127.0.0.1:8001").rstrip("/")
SERVICE = os.environ.get("INVENTORY_SERVICE_URL", "http://127.0.0.1:8000").rstrip("/")
ALL = "inventory.read.class_a inventory.read.class_b inventory.read.class_c"
MACHINES = {
    "reader (inventory-agent)": (os.environ.get("INVENTORY_CLIENT_ID", "inventory-agent"),
                                 os.environ.get("INVENTORY_CLIENT_SECRET", ""), ALL),
    "restricted-agent": ("restricted-agent",
                         os.environ.get("CHECK_RESTRICTED_CLIENT_SECRET", "demo-restricted-secret"),
                         "inventory.read.class_b inventory.read.class_c"),
}
CLAIMS = [None, "user-001", "admin"]
SKUS = ["WIDGET-A", "WIDGET-B"]


def machine_token(client_id, secret, scope):
    r = httpx.post(f"{ISSUER}/token", timeout=5,
                   headers={"X-Client-ID": client_id, "X-Client-Secret": secret, "X-Scope": scope})
    if r.status_code != 200:
        sys.exit(f"issuer refused {client_id}: HTTP {r.status_code} {r.text}")
    return r.json()["access_token"]


def main() -> int:
    try:
        tokens = {name: machine_token(*cfg) for name, cfg in MACHINES.items()}
    except httpx.RequestError:
        sys.exit("Could not reach the token issuer on :8001. Is it running?")

    ok = True
    print(f"{'machine':<26}{'sku':<10}" + "".join(f"{str(c):>12}" for c in CLAIMS) + "   same?")
    for name, token in tokens.items():
        for sku in SKUS:
            codes = []
            for claim in CLAIMS:
                headers = {"Authorization": f"Bearer {token}"}
                if claim is not None:
                    headers["X-Human-User"] = claim
                try:
                    codes.append(httpx.get(f"{SERVICE}/stock/{sku}", headers=headers, timeout=5).status_code)
                except httpx.RequestError:
                    sys.exit("Could not reach the inventory service on :8000. Is it running?")
            same = len(set(codes)) == 1
            ok &= same
            print(f"{name:<26}{sku:<10}" + "".join(f"{c:>12}" for c in codes) + f"   {'yes' if same else 'NO'}")

    restricted_a = tokens["restricted-agent"]
    r = httpx.get(f"{SERVICE}/stock/WIDGET-A", timeout=5,
                  headers={"Authorization": f"Bearer {restricted_a}", "X-Human-User": "admin"})
    key = r.status_code == 403
    ok &= key
    print(f"\n[{'PASS' if key else 'FAIL'}] restricted machine + X-Human-User: admin on class A -> {r.status_code} (want 403)")
    print("ALL PASS: the claim never changed a decision" if ok else "FAILED: a claim changed a decision")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
