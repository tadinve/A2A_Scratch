"""Day 08: manage the Identity Service's internal users in Firestore. No passwords.

    uv run python scripts/identity_users.py add user-001 --name Alice
    uv run python scripts/identity_users.py disable user-001
    uv run python scripts/identity_users.py enable user-001
    uv run python scripts/identity_users.py list

Uses the same store settings as the service (identity_service/.env:
IDENTITY_FIRESTORE_PROJECT, optional IDENTITY_FIRESTORE_DATABASE) and your
Application Default Credentials. A user can sign in only once enabled AND
linked to a Google account (scripts/google_enroll.py --link USER_ID).
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(Path(__file__).resolve().parent.parent / "identity_service" / ".env")

from identity_service.datastore import StoreUnavailable, build_stores  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    add = sub.add_parser("add", help="create or re-enable a user")
    add.add_argument("user_id")
    add.add_argument("--name", default="", help="display name, for operators only; never put in tokens")
    for name in ("enable", "disable"):
        sub.add_parser(name).add_argument("user_id")
    sub.add_parser("list")
    args = parser.parse_args()

    try:
        stores = build_stores()
        if stores.backend != "firestore":
            print("refusing to manage users in the memory store: nothing would persist", file=sys.stderr)
            return 2
        if args.command == "list":
            for user in stores.users.list():
                print(f"{user['user_id']}  enabled={user.get('enabled')}  name={user.get('display_name', '')}")
            return 0
        enabled = args.command in ("add", "enable")
        stores.users.put(args.user_id, enabled=enabled, display_name=getattr(args, "name", ""))
    except (RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except StoreUnavailable as exc:
        print(f"Firestore unavailable ({exc.operation}): check the project, database and your ADC login",
              file=sys.stderr)
        return 1
    print(f"{args.user_id} enabled={enabled} in {stores.description}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
