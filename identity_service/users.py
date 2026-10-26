"""User store: SQLite rows of (user_id, username, password_hash). No passwords.

The user_id ("user-001") is the stable identity that goes into tokens as `sub`.
The username (an email) is only a login handle and can change later.
"""

import os
import sqlite3
from pathlib import Path

from identity_service.passwords import hash_password

MIN_PASSWORD_LENGTH = 12  # account policy, enforced when a user is created

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    user_id       TEXT PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL CHECK (password_hash LIKE '$argon2id$%'),
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


def normalize_username(username: str) -> str:
    return username.strip().lower()


def _connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute(SCHEMA)
    os.chmod(db_path, 0o600)   # password verifiers: readable by the owner only
    return conn


def create_user(db_path: Path, username: str, password: str) -> str:
    """Store a new user with a hashed password. Returns the new user_id."""
    name = normalize_username(username)
    if not name:
        raise ValueError("username is required")
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    password_hash = hash_password(password)   # the plaintext stops here
    conn = _connect(db_path)
    try:
        if conn.execute("SELECT 1 FROM users WHERE username = ?", (name,)).fetchone():
            raise ValueError(f"user {name!r} already exists")
        count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        user_id = f"user-{count + 1:03d}"
        conn.execute("INSERT INTO users (user_id, username, password_hash) VALUES (?, ?, ?)",
                     (user_id, name, password_hash))
        conn.commit()
        return user_id
    finally:
        conn.close()


def find_user(db_path: Path, username: str) -> tuple[str, str, str] | None:
    """Return (user_id, username, password_hash) or None."""
    conn = _connect(db_path)
    try:
        row = conn.execute("SELECT user_id, username, password_hash FROM users WHERE username = ?",
                           (normalize_username(username),)).fetchone()
        return tuple(row) if row else None
    finally:
        conn.close()


def update_hash(db_path: Path, user_id: str, password_hash: str) -> None:
    conn = _connect(db_path)
    try:
        conn.execute("UPDATE users SET password_hash = ? WHERE user_id = ?", (password_hash, user_id))
        conn.commit()
    finally:
        conn.close()
