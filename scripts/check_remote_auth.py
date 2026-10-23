"""Live checks against the running inventory service (Days 03-04).

Terminal 1:
    uv run uvicorn inventory_service.app:app --host 127.0.0.1 --port 8000
Terminal 2:
    uv run python scripts/check_remote_auth.py            # service running
    uv run python scripts/check_remote_auth.py --stopped  # after stopping it

Part 1 drives the agent's real get_stock tool (reader key from inventory_agent/.env).
Part 2 acts as a test harness holding both demo keys and sends raw HTTP, to show
the class-based policy. The restricted key comes from CHECK_RESTRICTED_KEY, or the
documented demo value; the agent itself never holds it.
"""

import os
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from inventory_agent import tools  # noqa: E402  (loads inventory_agent/.env)

BASE_URL = os.environ.get("INVENTORY_SERVICE_URL", "http://127.0.0.1:8000").rstrip("/")
PROTECTED_DETAILS = ("name", "quantity", "Standard Widget", "Heavy-duty Widget", "Mini Widget")

results: list[bool] = []


def record(passed: bool, label: str, detail: str = "") -> None:
    results.append(passed)
    print(f"[{'PASS' if passed else 'FAIL'}] {label:<44} {detail}")


def section(title: str) -> None:
    print(f"\n== {title} ==")


# --------------------------------------------------------------------------- #
section("Agent process isolation")
for module in ("sqlite3", "inventory_service", "inventory_service.repository"):
    record(module not in sys.modules, f"agent did not import {module}")

if "--stopped" in sys.argv:
    section("Service stopped")
    got = tools.get_stock("WIDGET-A")
    record(got.get("status") == "error", "agent tool, service stopped", f"-> {got}")
    print("\nALL PASS" if all(results) else "\nSOME CHECKS FAILED")
    sys.exit(0 if all(results) else 1)

# --------------------------------------------------------------------------- #
section("Part 1: agent tool (reader key) over HTTP")
reader_key = os.environ.get("INVENTORY_CLIENT_SECRET")
cases = [
    ("WIDGET-A, class A", "WIDGET-A", "found"),
    ("WIDGET-B, class B", "WIDGET-B", "found"),
    ("WIDGET-C, zero stock, class C", " widget-c ", "found"),
    ("WIDGET-X, unknown", "WIDGET-X", "not_found"),
]
for label, sku, want in cases:
    got = tools.get_stock(sku)
    record(got.get("status") == want, label, f"-> {got}")

os.environ["INVENTORY_CLIENT_SECRET"] = "wrong-client-key"
got = tools.get_stock("WIDGET-A")
record(got.get("status") == "unauthenticated", "wrong client key", f"-> {got}")
os.environ.pop("INVENTORY_CLIENT_SECRET")
got = tools.get_stock("WIDGET-A")
record(got.get("status") == "unauthenticated", "no client key configured", f"-> {got}")
if reader_key:
    os.environ["INVENTORY_CLIENT_SECRET"] = reader_key

# --------------------------------------------------------------------------- #
section("Part 2: class-based policy grid (raw HTTP)")
restricted_key = os.environ.get("CHECK_RESTRICTED_KEY", "demo-restricted-secret")
keys = {
    "privileged": reader_key,
    "restricted": restricted_key,
    "invalid": "not-a-real-key",
    "missing": None,
}
policy = {
    #             class A  class B  class C
    "privileged": (200,    200,     200),
    "restricted": (403,    200,     200),
    "invalid":    (401,    401,     401),
    "missing":    (401,    401,     401),
}
skus = ("WIDGET-A", "WIDGET-B", "WIDGET-C")


def fetch(sku: str, key: str | None, extra_headers: dict | None = None, params: dict | None = None):
    headers = dict(extra_headers or {})
    if key is not None:
        headers["X-API-Key"] = key
    try:
        return httpx.get(f"{BASE_URL}/stock/{sku}", headers=headers, params=params, timeout=5)
    except httpx.RequestError:
        sys.exit(f"\nCould not reach {BASE_URL}. Is the service running?")


print(f"{'':<12}{'class A':>9}{'class B':>9}{'class C':>9}")
for who, expected in policy.items():
    row = []
    for sku, want in zip(skus, expected):
        r = fetch(sku, keys[who])
        ok = r.status_code == want
        results.append(ok)
        row.append(f"{r.status_code}{'' if ok else '!'}")
    print(f"{who:<12}" + "".join(f"{c:>9}" for c in row))
print("(a '!' marks an unexpected status)")

# --------------------------------------------------------------------------- #
section("Denied responses leak nothing")
for who, sku in (("restricted", "WIDGET-A"), ("invalid", "WIDGET-A"), ("missing", "WIDGET-B")):
    r = fetch(sku, keys[who])
    body = r.json()
    clean = set(body) == {"status", "message"} and not any(word in r.text for word in PROTECTED_DETAILS)
    no_secret = not any(k and k in r.text for k in keys.values())
    record(clean and no_secret, f"{who} {sku}: body is only status+message", f"-> HTTP {r.status_code} {body}")

# --------------------------------------------------------------------------- #
section("Class comes from server records, not the caller")
spoofs = [
    ("header X-Inventory-Class: C", {"X-Inventory-Class": "C"}, None),
    ("header X-Role: inventory_reader", {"X-Role": "inventory_reader"}, None),
    ("header X-Permissions: ...class_a", {"X-Permissions": "inventory.read.class_a"}, None),
    ("query ?inventory_class=C", None, {"inventory_class": "C"}),
]
for label, headers, params in spoofs:
    r = fetch("WIDGET-A", restricted_key, headers, params)
    record(r.status_code == 403, f"restricted WIDGET-A + {label}", f"-> HTTP {r.status_code}")

print(f"\n{sum(results)}/{len(results)} checks passed")
print("ALL PASS" if all(results) else "SOME CHECKS FAILED")
sys.exit(0 if all(results) else 1)
