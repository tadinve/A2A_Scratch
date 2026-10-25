"""Days 05.4-05.5: watch the Inventory Agent perform the whole security flow itself.

Needs both services running:
    uv run uvicorn inventory_service.app:app --host 127.0.0.1 --port 8000
    uv run uvicorn token_issuer.app:app      --host 127.0.0.1 --port 8001
Then:
    uv run python scripts/agent_flow_demo.py

Each scenario calls the agent's real get_stock tool. The flow logs show the
issuer call, then the service call. No secrets or tokens are printed.
The restricted client secret comes from CHECK_RESTRICTED_CLIENT_SECRET, or the demo value.
"""

import logging
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from inventory_agent import tools  # noqa: E402  (loads inventory_agent/.env)

logging.basicConfig(level=logging.INFO, format="      %(message)s")
logging.getLogger("httpx").setLevel(logging.WARNING)  # hide httpx's own request lines

agent_id = os.environ.get("INVENTORY_CLIENT_ID", "inventory-agent")
agent_secret = os.environ.get("INVENTORY_CLIENT_SECRET", "")
restricted_secret = os.environ.get("CHECK_RESTRICTED_CLIENT_SECRET", "demo-restricted-secret")

A, B, C = "inventory.read.class_a", "inventory.read.class_b", "inventory.read.class_c"

#  title, client_id, secret, requested scope, sku, expected tool status
scenarios = [
    ("1. inventory-agent, WRONG secret", agent_id, "wrong-secret", B, "WIDGET-A", "unauthenticated"),
    ("2. inventory-agent asks class_b, reads WIDGET-A", agent_id, agent_secret, B, "WIDGET-A", "forbidden"),
    ("3. inventory-agent asks class_b, reads WIDGET-B", agent_id, agent_secret, B, "WIDGET-B", "found"),
    ("4. inventory-agent asks class_a, reads WIDGET-A", agent_id, agent_secret, A, "WIDGET-A", "found"),
    ("5. restricted-agent asks class_a (issuer refuses)", "restricted-agent", restricted_secret, A, "WIDGET-A", "forbidden"),
    ("6. restricted-agent asks class_b, reads WIDGET-B", "restricted-agent", restricted_secret, B, "WIDGET-B", "found"),
]

all_ok = True
for title, client_id, secret, scope, sku, want in scenarios:
    print(f"\n{title}")
    os.environ["INVENTORY_CLIENT_ID"] = client_id
    os.environ["INVENTORY_CLIENT_SECRET"] = secret
    os.environ["INVENTORY_REQUESTED_SCOPE"] = scope
    result = tools.get_stock(sku)
    ok = result.get("status") == want
    all_ok &= ok
    print(f"   [{'PASS' if ok else 'FAIL'}] tool returned {result}")

print("\nALL PASS" if all_ok else "\nSOME SCENARIOS FAILED")
sys.exit(0 if all_ok else 1)
