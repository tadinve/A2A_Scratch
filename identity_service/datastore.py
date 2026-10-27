"""Where the Identity Service keeps its state (Day 08): Google Cloud Firestore.

Three collections, all owned by this service:

    identity_users/{user_id}                  who exists, and whether they may sign in
    identity_external_identities/{link_id}    (Google issuer, Google sub) -> user_id
    identity_oauth_transactions/{id}          pending logins: state, nonce, PKCE verifier

Access is by IAM: the service's own identity needs roles/datastore.user, and
there is no database password. Locally that identity is your ADC login
(`gcloud auth application-default login`), or the Firestore emulator when
FIRESTORE_EMULATOR_HOST is set.

    IDENTITY_FIRESTORE_PROJECT   required for the firestore backend
    IDENTITY_FIRESTORE_DATABASE  optional, default "(default)"
    IDENTITY_STORE               "firestore" (default) | "memory" (tests only: nothing persists)
"""

import contextlib
import os
from dataclasses import dataclass

from google.api_core import exceptions as api_exceptions
from google.auth import exceptions as auth_exceptions

USERS = "identity_users"
LINKS = "identity_external_identities"
TRANSACTIONS = "identity_oauth_transactions"
TIMEOUT_SECONDS = 5.0


class StoreUnavailable(Exception):
    """Firestore could not be reached or refused the call. `operation` is for logs only."""

    def __init__(self, operation: str):
        super().__init__(operation)
        self.operation = operation


@contextlib.contextmanager
def guarded(operation: str):
    """Turn any Firestore/auth failure into StoreUnavailable, so callers fail closed."""
    try:
        yield
    except (api_exceptions.GoogleAPIError, auth_exceptions.GoogleAuthError):
        raise StoreUnavailable(operation) from None


@dataclass(frozen=True)
class Stores:
    backend: str
    users: object           # identity_service.users.UserDirectory
    links: object           # identity_service.external_identities.LinkStore
    transactions: object    # identity_service.oauth_transactions.TransactionStore
    description: str


def build_stores(env=os.environ) -> Stores:
    # Imported here: those modules import StoreUnavailable from this one.
    from identity_service import external_identities, oauth_transactions, users

    backend = (env.get("IDENTITY_STORE") or "firestore").strip()
    if backend == "memory":
        return Stores("memory", users.MemoryUserDirectory(), external_identities.MemoryLinkStore(),
                      oauth_transactions.MemoryTransactionStore(), "memory (tests only; nothing persists)")
    if backend != "firestore":
        raise RuntimeError(f"IDENTITY_STORE must be 'firestore' or 'memory', not {backend!r}")

    project = (env.get("IDENTITY_FIRESTORE_PROJECT") or "").strip()
    if not project:
        raise RuntimeError("IDENTITY_FIRESTORE_PROJECT is required for the firestore store")
    database = (env.get("IDENTITY_FIRESTORE_DATABASE") or "").strip() or "(default)"
    from google.cloud import firestore
    try:
        client = firestore.Client(project=project, database=database)
    except auth_exceptions.GoogleAuthError as exc:
        raise RuntimeError(f"no Google credentials for Firestore: {type(exc).__name__}") from None
    where = env.get("FIRESTORE_EMULATOR_HOST")
    return Stores("firestore", users.FirestoreUserDirectory(client), external_identities.FirestoreLinkStore(client),
                  oauth_transactions.FirestoreTransactionStore(client),
                  f"firestore project={project} database={database}" + (f" emulator={where}" if where else ""))
