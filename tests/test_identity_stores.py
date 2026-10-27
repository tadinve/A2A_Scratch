"""Day 08: one contract for the Identity Service's three stores, run against every backend.

"memory" always runs. "firestore" runs only against the EMULATOR (FIRESTORE_EMULATOR_HOST
set), under a demo- project id, which the emulator guarantees never reaches real Google
Cloud. Each test uses fresh, uniquely named collections.

    gcloud emulators firestore start --host-port=localhost:8085
    FIRESTORE_EMULATOR_HOST=localhost:8085 uv run pytest tests/test_identity_stores.py -v
"""

import os
import threading
import time
import uuid

import pytest

from identity_service import external_identities as ext
from identity_service import oauth_transactions as otx
from identity_service import users
from identity_service.google_oidc import CANONICAL_ISSUER, GoogleIdentity

ALICE_SUB, BOB_SUB = "110248495921238986420", "220000000000000000002"
EMULATOR = os.environ.get("FIRESTORE_EMULATOR_HOST")

BACKENDS = ["memory", pytest.param("firestore", marks=pytest.mark.skipif(
    not EMULATOR, reason="set FIRESTORE_EMULATOR_HOST to run against the Firestore emulator"))]


class Clock:
    def __init__(self):
        self.now = time.time()

    def __call__(self):
        return self.now


@pytest.fixture(params=BACKENDS)
def backend(request):
    return request.param


@pytest.fixture
def fs():
    from google.cloud import firestore
    assert EMULATOR, "firestore tests must only ever run against the emulator"
    return firestore.Client(project="demo-a2a-identity")


def _name(kind):
    return f"test_{kind}_{uuid.uuid4().hex[:12]}"


@pytest.fixture
def directory(backend, request):
    if backend == "memory":
        return users.MemoryUserDirectory()
    return users.FirestoreUserDirectory(request.getfixturevalue("fs"), _name("users"))


@pytest.fixture
def link_store(backend, request):
    if backend == "memory":
        return ext.MemoryLinkStore()
    return ext.FirestoreLinkStore(request.getfixturevalue("fs"), _name("links"))


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def tx_store(backend, request, clock):
    if backend == "memory":
        return otx.MemoryTransactionStore(clock=clock)
    return otx.FirestoreTransactionStore(request.getfixturevalue("fs"), _name("tx"), clock=clock)


def google(sub=ALICE_SUB, issuer=CANONICAL_ISSUER):
    return GoogleIdentity(issuer=issuer, subject=sub, email="anyone@example.com")


# --------------------------------------------------------------------------- #
# Users
# --------------------------------------------------------------------------- #
def test_unknown_user_is_not_enabled(directory):
    assert directory.is_enabled("user-001") is False


def test_added_user_is_enabled_and_can_be_disabled(directory):
    directory.put("user-001", enabled=True, display_name="Alice")
    assert directory.is_enabled("user-001") is True
    directory.put("user-001", enabled=False)
    assert directory.is_enabled("user-001") is False
    assert [u["user_id"] for u in directory.list()] == ["user-001"]


@pytest.mark.parametrize("bad", ["alice", "user-1", "user-001/x", "", "../user-001"])
def test_malformed_user_ids_are_refused(directory, bad):
    with pytest.raises(ValueError):
        directory.put(bad, enabled=True)
    assert directory.is_enabled(bad) is False


# --------------------------------------------------------------------------- #
# External identity links
# --------------------------------------------------------------------------- #
def test_linked_subject_resolves_and_others_do_not(link_store):
    link_store.link(CANONICAL_ISSUER, ALICE_SUB, "user-001", linked_by="operator")
    assert link_store.resolve(google(ALICE_SUB)) == "user-001"
    assert link_store.resolve(google(BOB_SUB)) is None


def test_same_subject_from_another_issuer_does_not_resolve(link_store):
    link_store.link(CANONICAL_ISSUER, ALICE_SUB, "user-001")
    assert link_store.resolve(google(ALICE_SUB, issuer="https://evil.example")) is None


def test_a_subject_cannot_be_linked_twice(link_store):
    link_store.link(CANONICAL_ISSUER, ALICE_SUB, "user-001")
    with pytest.raises(ext.LinkConflict, match="already linked"):
        link_store.link(CANONICAL_ISSUER, ALICE_SUB, "user-002")
    assert link_store.resolve(google(ALICE_SUB)) == "user-001"          # never silently replaced


def test_a_user_cannot_get_a_second_google_link(link_store):
    link_store.link(CANONICAL_ISSUER, ALICE_SUB, "user-001")
    with pytest.raises(ext.LinkConflict, match="already has"):
        link_store.link(CANONICAL_ISSUER, BOB_SUB, "user-001")
    assert link_store.resolve(google(BOB_SUB)) is None


@pytest.mark.parametrize("issuer,subject,user_id", [
    ("https://evil.example", ALICE_SUB, "user-001"),
    ("accounts.google.com", ALICE_SUB, "user-001"),                     # only the canonical form is stored
    (CANONICAL_ISSUER, " 1102 ", "user-001"),
    (CANONICAL_ISSUER, "x" * 256, "user-001"),
    (CANONICAL_ISSUER, ALICE_SUB, "alice"),
])
def test_malformed_links_are_refused(link_store, issuer, subject, user_id):
    with pytest.raises(ValueError):
        link_store.link(issuer, subject, user_id)


@pytest.mark.skipif(not EMULATOR, reason="needs the Firestore emulator")
@pytest.mark.parametrize("tamper", [{"subject": BOB_SUB}, {"user_id": "admin"}, {"issuer": "https://evil.example"}])
def test_a_tampered_stored_link_resolves_to_nobody(fs, tamper):
    store = ext.FirestoreLinkStore(fs, _name("links"))
    store.link(CANONICAL_ISSUER, ALICE_SUB, "user-001")
    store._col.document(ext.link_id(CANONICAL_ISSUER, ALICE_SUB)).update(tamper)
    assert store.resolve(google(ALICE_SUB)) is None


# --------------------------------------------------------------------------- #
# Login transactions
# --------------------------------------------------------------------------- #
def test_a_transaction_is_claimed_exactly_once(tx_store):
    binding, tx = tx_store.begin("cid-1")
    claimed = tx_store.claim(binding, tx.state)
    assert claimed == tx and claimed.correlation_id == "cid-1"
    assert tx_store.claim(binding, tx.state) is None


def test_wrong_state_fails_and_consumes_the_transaction(tx_store):
    binding, tx = tx_store.begin("cid")
    assert tx_store.claim(binding, "forged") is None
    assert tx_store.claim(binding, tx.state) is None


def test_expired_transaction_is_refused(tx_store, clock):
    binding, tx = tx_store.begin("cid")
    clock.now += otx.TRANSACTION_TTL_SECONDS
    assert tx_store.claim(binding, tx.state) is None


@pytest.mark.parametrize("binding,state", [(None, "s"), ("b", None), ("", "s"), ("unknown", "s")])
def test_missing_or_unknown_inputs_claim_nothing(tx_store, binding, state):
    assert tx_store.claim(binding, state) is None


def test_discarded_transaction_cannot_be_claimed(tx_store):
    binding, tx = tx_store.begin("cid")
    tx_store.discard(binding)
    assert tx_store.claim(binding, tx.state) is None


def test_concurrent_claims_have_exactly_one_winner(tx_store):
    binding, tx = tx_store.begin("cid")
    barrier, won = threading.Barrier(6), []

    def claim():
        barrier.wait()
        if tx_store.claim(binding, tx.state):
            won.append(1)

    threads = [threading.Thread(target=claim) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert won == [1]


@pytest.mark.skipif(not EMULATOR, reason="needs the Firestore emulator")
def test_firestore_stores_only_a_hash_of_the_cookie_and_a_ttl_timestamp(fs):
    store = otx.FirestoreTransactionStore(fs, _name("tx"))
    binding, tx = store.begin("cid")
    (doc,) = list(store._col.stream())
    assert doc.id != binding and binding not in str(doc.to_dict())
    assert doc.to_dict()["expire_at"].timestamp() == pytest.approx(tx.expires_at, abs=1)
