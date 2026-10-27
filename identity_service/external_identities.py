"""Explicit links from an external identity to an internal user (Days 07-08).

The key is (canonical issuer, Google `sub`): stable and never reassigned by Google.
It is NEVER the email, display name, login_hint, or anything the browser sends.
There is no automatic linking by matching email and no public link endpoint:
an operator runs scripts/google_enroll.py --link user-001, sees the verified
account, confirms, and the link is written.

    Firestore  identity_external_identities/{sha256(issuer \\n sub)} =
               {"issuer": ..., "subject": ..., "user_id": "user-001", "linked_by": ..., "linked_at": ...}

One link per (issuer, sub) AND one per (issuer, user): a second of either is
refused when written, and a malformed stored link resolves to nobody.
"""

import hashlib
import re
import threading

from identity_service.datastore import LINKS, TIMEOUT_SECONDS, guarded
from identity_service.google_oidc import CANONICAL_ISSUER, GoogleIdentity
from identity_service.users import USER_ID, check_user_id

_SUBJECT = re.compile(r"[\x21-\x7e]{1,255}")      # Google: up to 255 printable ASCII, case-sensitive
TRUSTED_ISSUERS = {CANONICAL_ISSUER}


class LinkConflict(Exception):
    pass


def check_link(issuer: str, subject: str, user_id: str) -> None:
    if issuer not in TRUSTED_ISSUERS:
        raise ValueError(f"untrusted issuer {issuer!r}")
    if not isinstance(subject, str) or not _SUBJECT.fullmatch(subject):
        raise ValueError("not a valid Google subject identifier")
    check_user_id(user_id)


def link_id(issuer: str, subject: str) -> str:
    """Firestore document ids can't contain '/', and issuers are URLs: hash the pair."""
    return hashlib.sha256(f"{issuer}\n{subject}".encode()).hexdigest()


def _valid_target(data: dict | None, issuer: str, subject: str) -> str | None:
    if not data or data.get("issuer") != issuer or data.get("subject") != subject:
        return None
    user_id = data.get("user_id")
    return user_id if isinstance(user_id, str) and USER_ID.fullmatch(user_id) else None


class MemoryLinkStore:
    """For tests. Same rules as Firestore, nothing persists."""

    def __init__(self):
        self._links: dict[tuple[str, str], str] = {}
        self._lock = threading.Lock()

    def resolve(self, identity: GoogleIdentity) -> str | None:
        with self._lock:
            return self._links.get((identity.issuer, identity.subject))

    def link(self, issuer: str, subject: str, user_id: str, *, linked_by: str = "") -> None:
        check_link(issuer, subject, user_id)
        with self._lock:
            if (issuer, subject) in self._links:
                raise LinkConflict("this external identity is already linked")
            if any(i == issuer and u == user_id for (i, _), u in self._links.items()):
                raise LinkConflict(f"{user_id} already has a link from this issuer")
            self._links[(issuer, subject)] = user_id


class FirestoreLinkStore:
    def __init__(self, client, collection: str = LINKS):
        self._client, self._col = client, client.collection(collection)

    def resolve(self, identity: GoogleIdentity) -> str | None:
        with guarded("links.get"):
            snap = self._col.document(link_id(identity.issuer, identity.subject)).get(timeout=TIMEOUT_SECONDS)
        return _valid_target(snap.to_dict() if snap.exists else None, identity.issuer, identity.subject)

    def link(self, issuer: str, subject: str, user_id: str, *, linked_by: str = "") -> None:
        from google.cloud import firestore
        from google.cloud.firestore_v1 import FieldFilter

        check_link(issuer, subject, user_id)
        ref = self._col.document(link_id(issuer, subject))
        same_user = (self._col.where(filter=FieldFilter("issuer", "==", issuer))
                     .where(filter=FieldFilter("user_id", "==", user_id)).limit(1))

        @firestore.transactional
        def write(transaction):
            if ref.get(transaction=transaction).exists:
                raise LinkConflict("this external identity is already linked")
            if any(True for _ in transaction.get(same_user)):
                raise LinkConflict(f"{user_id} already has a link from this issuer")
            transaction.create(ref, {"issuer": issuer, "subject": subject, "user_id": user_id,
                                     "linked_by": linked_by, "linked_at": firestore.SERVER_TIMESTAMP})

        with guarded("links.link"):
            write(self._client.transaction())
