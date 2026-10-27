"""Single-use, server-side login transactions for the Google flow (Days 07-08).

/auth/google creates one: a random state, nonce and PKCE verifier, kept HERE,
plus a separate browser-binding id that goes in an HttpOnly cookie. The callback
claims it exactly once, so a replayed or concurrent duplicate callback finds nothing.

FirestoreTransactionStore (Day 08) shares pending logins across instances:
    identity_oauth_transactions/{sha256(binding_id)} = {state, nonce, code_verifier,
                                                        correlation_id, expires_at, expire_at}
The claim is a Firestore transaction that reads and deletes the document together:
of two concurrent callbacks, one wins and the other's retry finds it gone. Only a
HASH of the cookie value is stored, so reading the database doesn't give anyone a
usable cookie. `expire_at` is a timestamp for a Firestore TTL policy, which deletes
abandoned logins; expiry is still enforced on every claim.

MemoryTransactionStore is for tests: bounded, per-process, gone on restart.
"""

import datetime
import hashlib
import hmac
import secrets
import threading
import time
from dataclasses import asdict, dataclass

from identity_service.datastore import TIMEOUT_SECONDS, TRANSACTIONS, guarded

TRANSACTION_TTL_SECONDS = 300
MAX_PENDING = 1000


@dataclass(frozen=True)
class LoginTransaction:
    state: str
    nonce: str
    code_verifier: str
    expires_at: float       # wall-clock epoch seconds: instances must agree on it
    correlation_id: str     # one id for the start AND callback log lines of this login


class TransactionStoreFull(Exception):
    pass


def _new(correlation_id: str, now: float, ttl: int) -> tuple[str, LoginTransaction]:
    tx = LoginTransaction(
        state=secrets.token_urlsafe(32),
        nonce=secrets.token_urlsafe(32),
        code_verifier=secrets.token_urlsafe(64),      # 86 chars: within PKCE's 43-128
        expires_at=now + ttl,
        correlation_id=correlation_id,
    )
    return secrets.token_urlsafe(32), tx


def _accept(tx: LoginTransaction | None, state: str, now: float) -> LoginTransaction | None:
    if tx is None or now >= tx.expires_at:
        return None
    if not hmac.compare_digest(tx.state.encode(), state.encode()):
        return None
    return tx


class MemoryTransactionStore:
    def __init__(self, ttl: int = TRANSACTION_TTL_SECONDS, max_pending: int = MAX_PENDING, clock=time.time):
        self._ttl, self._max, self._clock = ttl, max_pending, clock
        self._pending: dict[str, LoginTransaction] = {}
        self._lock = threading.Lock()

    def begin(self, correlation_id: str) -> tuple[str, LoginTransaction]:
        """Return (binding_id for the cookie, the transaction). Raise TransactionStoreFull."""
        binding_id, tx = _new(correlation_id, self._clock(), self._ttl)
        with self._lock:
            if len(self._pending) >= self._max:
                self._purge_expired()
            if len(self._pending) >= self._max:
                raise TransactionStoreFull()
            self._pending[binding_id] = tx
        return binding_id, tx

    def claim(self, binding_id: str | None, state: str | None) -> LoginTransaction | None:
        """Remove and return the transaction if it exists, is unexpired and the state
        matches. A mismatch still removes it: one bad attempt ends that login."""
        if not binding_id or not state:
            return None
        with self._lock:
            tx = self._pending.pop(binding_id, None)
        return _accept(tx, state, self._clock())

    def discard(self, binding_id: str) -> None:
        with self._lock:
            self._pending.pop(binding_id, None)

    def __len__(self) -> int:
        return len(self._pending)

    def _purge_expired(self) -> None:
        now = self._clock()
        for key in [k for k, tx in self._pending.items() if now >= tx.expires_at]:
            del self._pending[key]


def _doc_id(binding_id: str) -> str:
    return hashlib.sha256(binding_id.encode()).hexdigest()


class FirestoreTransactionStore:
    def __init__(self, client, collection: str = TRANSACTIONS, ttl: int = TRANSACTION_TTL_SECONDS, clock=time.time):
        self._client, self._col, self._ttl, self._clock = client, client.collection(collection), ttl, clock

    def begin(self, correlation_id: str) -> tuple[str, LoginTransaction]:
        binding_id, tx = _new(correlation_id, self._clock(), self._ttl)
        doc = {**asdict(tx), "expire_at": datetime.datetime.fromtimestamp(tx.expires_at, datetime.timezone.utc)}
        with guarded("transactions.begin"):
            self._col.document(_doc_id(binding_id)).create(doc, timeout=TIMEOUT_SECONDS)
        return binding_id, tx

    def claim(self, binding_id: str | None, state: str | None) -> LoginTransaction | None:
        if not binding_id or not state:
            return None
        from google.cloud import firestore

        ref = self._col.document(_doc_id(binding_id))

        @firestore.transactional
        def take(transaction):
            snap = ref.get(transaction=transaction)
            if not snap.exists:
                return None
            transaction.delete(ref)
            return snap.to_dict()

        with guarded("transactions.claim"):
            data = take(self._client.transaction())
        if data is None:
            return None
        try:
            tx = LoginTransaction(**{f: data[f] for f in LoginTransaction.__dataclass_fields__})
        except (KeyError, TypeError):
            return None
        return _accept(tx, state, self._clock())

    def discard(self, binding_id: str) -> None:
        with guarded("transactions.discard"):
            self._col.document(_doc_id(binding_id)).delete(timeout=TIMEOUT_SECONDS)
