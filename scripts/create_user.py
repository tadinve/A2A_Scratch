"""Day 06.02: add a human user to the Identity Service's user store.

    uv run python scripts/create_user.py alice@example.com

Prompts for the password without echoing it (it never appears in shell history),
stores ONLY its Argon2id hash, and prints the new user_id.
"""

import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from identity_service.config import load_config  # noqa: E402
from identity_service.users import create_user  # noqa: E402


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: create_user.py <username>", file=sys.stderr)
        return 2
    password = getpass.getpass("Password (12+ characters): ")
    if password != getpass.getpass("Repeat password: "):
        print("passwords do not match", file=sys.stderr)
        return 1
    cfg = load_config()
    try:
        user_id = create_user(cfg.users_db, sys.argv[1], password)
    except ValueError as exc:
        print(f"not created: {exc}", file=sys.stderr)
        return 1
    print(f"created {user_id} for {sys.argv[1].strip().lower()} in {cfg.users_db}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
