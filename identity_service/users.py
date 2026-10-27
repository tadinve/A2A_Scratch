"""Internal user directory (Day 08): who exists and whether they may sign in. No passwords.

The user_id ("user-001") is the stable identity that goes into tokens as `sub`.
How someone proves they ARE that user lives elsewhere (external_identities.py).

    Firestore  identity_users/{user_id} = {"enabled": true, "display_name": "Alice", "updated_at": ...}

Managed with scripts/identity_users.py. A missing user and a disabled one are
treated the same: they cannot sign in.
"""

import re
import threading

from identity_service.datastore import TIMEOUT_SECONDS, USERS, guarded

USER_ID = re.compile(r"user-\d{3,}")


def check_user_id(user_id: str) -> str:
    if not isinstance(user_id, str) or not USER_ID.fullmatch(user_id):
        raise ValueError(f"malformed user id {user_id!r}; expected user-NNN")
    return user_id


class MemoryUserDirectory:
    """For tests. Same behaviour as Firestore, nothing persists."""

    def __init__(self, users: dict[str, bool] | None = None):
        self._users = {check_user_id(u): bool(e) for u, e in (users or {}).items()}
        self._lock = threading.Lock()

    def is_enabled(self, user_id: str) -> bool:
        with self._lock:
            return self._users.get(user_id) is True

    def put(self, user_id: str, *, enabled: bool, display_name: str = "") -> None:
        with self._lock:
            self._users[check_user_id(user_id)] = bool(enabled)

    def list(self) -> list[dict]:
        with self._lock:
            return [{"user_id": u, "enabled": e} for u, e in sorted(self._users.items())]


class FirestoreUserDirectory:
    def __init__(self, client, collection: str = USERS):
        self._client, self._col = client, client.collection(collection)

    def is_enabled(self, user_id: str) -> bool:
        if not USER_ID.fullmatch(user_id or ""):
            return False
        with guarded("users.get"):
            snap = self._col.document(user_id).get(timeout=TIMEOUT_SECONDS)
        return snap.exists and (snap.to_dict() or {}).get("enabled") is True

    def put(self, user_id: str, *, enabled: bool, display_name: str = "") -> None:
        from google.cloud import firestore
        fields = {"enabled": bool(enabled), "updated_at": firestore.SERVER_TIMESTAMP}
        if display_name:
            fields["display_name"] = display_name
        with guarded("users.put"):
            self._col.document(check_user_id(user_id)).set(fields, merge=True, timeout=TIMEOUT_SECONDS)

    def list(self) -> list[dict]:
        with guarded("users.list"):
            return [{"user_id": s.id, **(s.to_dict() or {})} for s in self._col.stream(timeout=TIMEOUT_SECONDS)]
