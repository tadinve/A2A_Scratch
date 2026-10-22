"""Create and seed data/inventory.db. Safe to run repeatedly."""

import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "inventory.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS inventory (
    sku TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    quantity INTEGER NOT NULL CHECK (quantity >= 0)
);
"""

SEED = [
    ("WIDGET-A", "Standard Widget", 30),
    ("WIDGET-B", "Heavy-duty Widget", 12),
    ("WIDGET-C", "Mini Widget", 0),
]


def main() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(SCHEMA)
        # INSERT OR IGNORE: existing SKUs keep their current quantity.
        conn.executemany(
            "INSERT OR IGNORE INTO inventory (sku, name, quantity) VALUES (?, ?, ?);",
            SEED,
        )
        conn.commit()
        rows = conn.execute("SELECT sku, name, quantity FROM inventory ORDER BY sku;").fetchall()
    finally:
        conn.close()

    print(f"Database ready at {DB_PATH}")
    for sku, name, quantity in rows:
        print(f"  {sku:<10} {name:<20} {quantity:>4}")


if __name__ == "__main__":
    main()
