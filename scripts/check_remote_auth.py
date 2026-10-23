"""Day 03D: live checks of the agent's get_stock tool against the HTTP service.

Terminal 1:
    INVENTORY_SERVICE_SECRET=demo-local-secret \\
        uv run uvicorn inventory_service.app:app --host 127.0.0.1 --port 8000
Terminal 2:
    uv run python scripts/check_remote_auth.py            # service running
    uv run python scripts/check_remote_auth.py --stopped  # after stopping it
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from inventory_agent import tools  # noqa: E402  (loads inventory_agent/.env)

results = []


def check(label: str, got: dict, want_status: str) -> None:
    passed = got.get("status") == want_status
    results.append(passed)
    print(f"[{'PASS' if passed else 'FAIL'}] {label:<28} -> {got}")


# The agent side must not touch the database layer at all.
for module in ("sqlite3", "inventory_service", "inventory_service.repository"):
    loaded = module in sys.modules
    results.append(not loaded)
    print(f"[{'PASS' if not loaded else 'FAIL'}] {'agent did not import ' + module:<28}")

if "--stopped" in sys.argv:
    check("service stopped", tools.get_stock("WIDGET-A"), "error")
else:
    real_secret = os.environ.get("INVENTORY_CLIENT_SECRET")
    check("WIDGET-A, correct key", tools.get_stock("WIDGET-A"), "found")
    check("WIDGET-C, zero stock", tools.get_stock(" widget-c "), "found")
    check("WIDGET-X, unknown", tools.get_stock("WIDGET-X"), "not_found")

    os.environ["INVENTORY_CLIENT_SECRET"] = "wrong-client-key"
    check("wrong client key", tools.get_stock("WIDGET-A"), "unauthenticated")

    os.environ.pop("INVENTORY_CLIENT_SECRET")
    check("no client key configured", tools.get_stock("WIDGET-A"), "unauthenticated")

    if real_secret:
        os.environ["INVENTORY_CLIENT_SECRET"] = real_secret

print("\nALL PASS" if all(results) else "\nSOME CHECKS FAILED")
sys.exit(0 if all(results) else 1)
