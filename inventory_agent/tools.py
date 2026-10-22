"""SQLite lookup tool for the inventory agent.

The model supplies the SKU. This module owns the SQL.
"""

import sqlite3
from pathlib import Path

# Resolve the database relative to this file, not the terminal's working directory.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = PROJECT_ROOT / "data" / "inventory.db"

_LOOKUP_SQL = """
SELECT sku, name, quantity
FROM inventory
WHERE sku = ?;
"""

_UNAVAILABLE = {"status": "error", "message": "Inventory is temporarily unavailable."}


def get_stock(sku: str) -> dict:
    """Return the inventory record for a SKU.

    Args:
        sku: The stock-keeping unit to look up, for example "WIDGET-A".
             Surrounding whitespace is ignored and the value is upper-cased.

    Returns:
        A dict whose "status" is one of:
        - "found": includes "sku", "name", and "quantity". A quantity of 0
          means the item exists but is out of stock.
        - "not_found": the SKU is not in the inventory table.
        - "error": the database could not be read; includes "message".
    """
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
