"""Day 04: the inventory_class column, against a real throwaway SQLite file."""

import sqlite3

import pytest

from inventory_service import repository
from scripts.init_db import initialize

OLD_SCHEMA = """
CREATE TABLE inventory (
    sku TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    quantity INTEGER NOT NULL CHECK (quantity >= 0)
);
"""


@pytest.fixture
def old_db(tmp_path):
    """A database exactly as Day 01-03 left it: no inventory_class column."""
    path = tmp_path / "inventory.db"
    conn = sqlite3.connect(path)
    conn.execute(OLD_SCHEMA)
    conn.executemany(
        "INSERT INTO inventory VALUES (?, ?, ?);",
        [("WIDGET-A", "Standard Widget", 30), ("WIDGET-B", "Heavy-duty Widget", 12),
         ("WIDGET-C", "Mini Widget", 0), ("GADGET-Z", "Unlisted Gadget", 5)],
    )
    conn.commit()
    conn.close()
    return path


def classes(path):
    conn = sqlite3.connect(path)
    try:
        return dict(conn.execute("SELECT sku, inventory_class FROM inventory;").fetchall())
    finally:
        conn.close()


def test_migration_adds_classes_and_keeps_quantities(old_db):
    rows = initialize(old_db)
    assert {r[0]: r[2] for r in rows}["WIDGET-B"] == 12  # quantity untouched
    assert classes(old_db) == {"WIDGET-A": "A", "WIDGET-B": "B", "WIDGET-C": "C", "GADGET-Z": "A"}


def test_unclassified_existing_rows_default_to_most_restrictive(old_db):
    initialize(old_db)
    assert classes(old_db)["GADGET-Z"] == "A"


def test_rerun_does_not_overwrite_a_changed_class(old_db):
    initialize(old_db)
    conn = sqlite3.connect(old_db)
    conn.execute("UPDATE inventory SET inventory_class = 'C' WHERE sku = 'WIDGET-A';")
    conn.commit()
    conn.close()
    initialize(old_db)
    assert classes(old_db)["WIDGET-A"] == "C"


def test_database_rejects_invalid_class(old_db):
    initialize(old_db)
    conn = sqlite3.connect(old_db)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE inventory SET inventory_class = 'D' WHERE sku = 'WIDGET-A';")
    conn.close()


def test_get_classification_returns_metadata_only(old_db, monkeypatch):
    initialize(old_db)
    monkeypatch.setattr(repository, "DB_PATH", old_db)
    assert repository.get_classification(" widget-b ") == {
        "status": "found", "sku": "WIDGET-B", "inventory_class": "B",
    }
    assert repository.get_classification("WIDGET-X") == {"status": "not_found", "sku": "WIDGET-X"}


def test_missing_database_is_error_not_recreated(tmp_path, monkeypatch):
    missing = tmp_path / "nope.db"
    monkeypatch.setattr(repository, "DB_PATH", missing)
    assert repository.get_classification("WIDGET-A")["status"] == "error"
    assert not missing.exists()
