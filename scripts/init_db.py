"""Create, migrate, and seed data/inventory.db. Safe to run repeatedly.

Day 04 adds `inventory_class` (A, B, or C): an independent property of each
record, used for authorization. It is stored, never inferred from the SKU.
"""

import sqlite3
import sys
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "inventory.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS inventory (
    sku TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    quantity INTEGER NOT NULL CHECK (quantity >= 0),
    inventory_class TEXT NOT NULL DEFAULT 'A' CHECK (inventory_class IN ('A', 'B', 'C'))
);
"""

# Day 04 migration for databases created before the column existed.
# Default 'A' = most restrictive: anything not explicitly classified fails closed.
ADD_CLASS_COLUMN = """
ALTER TABLE inventory
ADD COLUMN inventory_class TEXT NOT NULL DEFAULT 'A'
CHECK (inventory_class IN ('A', 'B', 'C'));
"""

SEED = [
    ("WIDGET-A", "Standard Widget", 30, "A"),
    ("WIDGET-B", "Heavy-duty Widget", 12, "B"),
    ("WIDGET-C", "Mini Widget", 0, "C"),
]


def initialize(db_path: Path) -> list[tuple]:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(SCHEMA)

        columns = {row[1] for row in conn.execute("PRAGMA table_info(inventory);")}
        if "inventory_class" not in columns:
            conn.execute(ADD_CLASS_COLUMN)
            # Classify the seed records once, at migration time only.
            # Later runs never overwrite a class someone has changed.
            conn.executemany(
                "UPDATE inventory SET inventory_class = ? WHERE sku = ?;",
                [(cls, sku) for sku, _, _, cls in SEED],
            )
            print("Migrated: added inventory_class column")

        # INSERT OR IGNORE: existing SKUs keep their current quantity and class.
        conn.executemany(
            "INSERT OR IGNORE INTO inventory (sku, name, quantity, inventory_class) VALUES (?, ?, ?, ?);",
            SEED,
        )
        conn.commit()
        return conn.execute(
            "SELECT sku, name, quantity, inventory_class FROM inventory ORDER BY sku;"
        ).fetchall()
    finally:
        conn.close()


def main() -> None:
    db_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DB_PATH
    rows = initialize(db_path)
    print(f"Database ready at {db_path}")
    for sku, name, quantity, cls in rows:
        print(f"  {sku:<10} {name:<20} {quantity:>4}  class {cls}")


if __name__ == "__main__":
    main()
