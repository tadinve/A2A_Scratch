"""Day 02 check: exercise protected_get_stock with three credentials.

Run from the project root:  uv run python scripts/check_auth.py
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from inventory_agent import tools  # noqa: E402  (loads inventory_agent/.env)

# Count SQLite lookups so we can prove the failing cases never reach the DB.
lookups = {"count": 0}
_real_lookup = tools._lookup_sku


def _counting_lookup(sku: str) -> dict:
    lookups["count"] += 1
    return _real_lookup(sku)


tools._lookup_sku = _counting_lookup

correct = os.environ.get("INVENTORY_SHARED_SECRET")
if not correct:
    sys.exit("INVENTORY_SHARED_SECRET is not set; add it to inventory_agent/.env")

cases = [
    ("correct secret", correct, "found", True),
    ("None", None, "unauthenticated", False),
    ("incorrect secret", "not-the-secret", "unauthenticated", False),
]

ok = True
for label, credential, want_status, want_lookup in cases:
    before = lookups["count"]
    result = tools.protected_get_stock("WIDGET-A", credential)
    did_lookup = lookups["count"] > before
    passed = result["status"] == want_status and did_lookup == want_lookup
    ok &= passed
    print(f"[{'PASS' if passed else 'FAIL'}] {label:<17} -> {result}  sqlite_lookup={did_lookup}")

print("\nALL PASS" if ok else "\nSOME CHECKS FAILED")
sys.exit(0 if ok else 1)
