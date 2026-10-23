"""SQLite access for the inventory service.

Moved unchanged from the Day 02 agent tool. Only this module imports sqlite3.
It loads no configuration and contains no authentication logic.
"""

import sqlite3
from pathlib import Path

# Resolve relative to this file, not the terminal's working directory.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = PROJECT_ROOT / "data" / "inventory.db"

_LOOKUP_SQL = """
SELECT sku, name, quantity
FROM inventory
WHERE sku = ?;
"""

_UNAVAILABLE = {"status": "error", "message": "Inventory is temporarily unavailable."}


def lookup_sku(sku: str) -> dict:
    """Run the fixed, parameterized SQLite query for one SKU."""
    normalized_sku = sku.strip().upper()

    try:
        # Read-only URI: a missing database is reported, not silently recreated.
        conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
    except sqlite3.Error:
        return dict(_UNAVAILABLE)

    try:
        row = conn.execute(_LOOKUP_SQL, (normalized_sku,)).fetchone()
    except sqlite3.Error:
        return dict(_UNAVAILABLE)
    finally:
        conn.close()

    if row is None:
        return {"status": "not_found", "sku": normalized_sku}

    found_sku, name, quantity = row
    return {
        "status": "found",
        "sku": found_sku,
        "name": name,
        "quantity": quantity,
    }
