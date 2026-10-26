"""Days 06.02-06.04: password storage, human login, and the signed human JWT."""

import logging
import sqlite3
import stat

import jwt
import pytest
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from fastapi.testclient import TestClient

from tests.support import IDENTITY_PRIVATE_FILE, IDENTITY_PUBLIC_PEM, IDENTITY_USERS_DB, PUBLIC_PEM

from identity_service import app as identity_app  # noqa: E402  (after support sets the config)
from identity_service import passwords, tokens, users
from identity_service.config import load_config

ALICE = ("alice", "correct horse battery staple")
BOB = ("bob", "another long passphrase")


@pytest.fixture
def db():
    if IDENTITY_USERS_DB.exists():
        IDENTITY_USERS_DB.unlink()
    users.create_user(IDENTITY_USERS_DB, *ALICE)    # user-001
    users.create_user(IDENTITY_USERS_DB, *BOB)      # user-002
    yield IDENTITY_USERS_DB
    IDENTITY_USERS_DB.unlink()


@pytest.fixture
def idp():
    return TestClient(identity_app.app)


def login(idp, username, password):
    return idp.post("/login", json={"username": username, "password": password})


def stored_hash(db_path, username):
    return users.find_user(db_path, username)[2]


UNAUTHENTICATED = {"status": "unauthenticated", "message": "Invalid username or password"}


# --------------------------------------------------------------------------- #
# Day 06.03 required tests
# --------------------------------------------------------------------------- #
def test_alice_correct_password_is_200(idp, db):
    r = login(idp, *ALICE)
    assert r.status_code == 200
    body = r.json()
    assert {k: body[k] for k in ("status", "user_id", "username")} == \
        {"status": "authenticated", "user_id": "user-001", "username": "alice"}
    assert body["token_type"] == "Bearer" and body["expires_in"] == 300 and body["access_token"]


def test_alice_wrong_password_is_401(idp, db):
    r = login(idp, ALICE[0], "wrong password entirely")
    assert r.status_code == 401
    assert r.json() == UNAUTHENTICATED


def test_unknown_username_is_401(idp, db):
    r = login(idp, "mallory", "wrong password entirely")
    assert r.status_code == 401
    assert r.json() == UNAUTHENTICATED


def test_unknown_user_and_wrong_password_are_indistinguishable(idp, db):
    a = login(idp, ALICE[0], "wrong password entirely")
    b = login(idp, "mallory", "wrong password entirely")
    assert (a.status_code, a.json(), a.headers.get("content-type")) == \
           (b.status_code, b.json(), b.headers.get("content-type"))


def test_missing_password_is_422(idp, db):
    r = idp.post("/login", json={"username": "alice"})
    assert r.status_code == 422


def test_missing_username_is_422(idp, db):
    r = idp.post("/login", json={"password": ALICE[1]})
    assert r.status_code == 422
    assert ALICE[1] not in r.text                    # the 422 body never echoes input


def test_login_response_contains_no_password_or_hash(idp, db):
    ok = login(idp, *ALICE)
    bad = login(idp, ALICE[0], "wrong password entirely")
    for r in (ok, bad):
        assert ALICE[1] not in r.text and "wrong password entirely" not in r.text
        assert "argon2" not in r.text and "$" not in r.text
    assert "access_token" not in bad.text            # failures never get a token
    assert ok.headers["cache-control"] == "no-store"


def test_existing_inventory_jwt_security_unchanged(idp, db, client, spy):
    # A successful human login gives the caller nothing usable at the inventory service.
    login(idp, *ALICE)
    assert client.get("/stock/WIDGET-C").status_code == 401
    assert client.get("/stock/WIDGET-C", headers={"X-User": "user-001"}).status_code == 401
    assert spy.sqlite_touched is False


# --------------------------------------------------------------------------- #
# Login behaviour details
# --------------------------------------------------------------------------- #
def test_username_is_case_and_space_insensitive(idp, db):
    r = login(idp, "  ALICE ", ALICE[1])
    assert r.status_code == 200 and r.json()["username"] == "alice"


def test_another_users_password_is_401(idp, db):
    assert login(idp, ALICE[0], BOB[1]).status_code == 401


def test_unknown_user_still_costs_a_hash_check(idp, db, monkeypatch):
    calls = []
    real = passwords.verify_password
    monkeypatch.setattr(identity_app, "verify_password", lambda p, h: calls.append(h) or real(p, h))
    login(idp, "mallory", "some long password")
    assert calls == [passwords.DUMMY_HASH]           # timing doesn't reveal unknown accounts


@pytest.mark.parametrize("body", [{}, {"username": "", "password": "x"}, {"username": "a", "password": "x" * 2000}])
def test_malformed_requests_are_422_and_never_echo_input(idp, db, body):
    r = idp.post("/login", json=body)
    assert r.status_code == 422
    assert r.json()["status"] == "invalid_request"
    assert "x" * 50 not in r.text


def test_get_is_not_allowed(idp):
    assert idp.get("/login").status_code == 405


def test_weak_hash_is_upgraded_on_next_successful_login(idp, db):
    weak = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1).hash(ALICE[1])
    users.update_hash(db, "user-001", weak)
    assert login(idp, *ALICE).status_code == 200
    upgraded = stored_hash(db, ALICE[0])
    assert upgraded != weak and not passwords.needs_rehash(upgraded)
    assert login(idp, *ALICE).status_code == 200


def test_failed_login_does_not_upgrade(idp, db):
    weak = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1).hash(ALICE[1])
    users.update_hash(db, "user-001", weak)
    login(idp, ALICE[0], "wrong password entirely")
    assert stored_hash(db, ALICE[0]) == weak


def test_logs_contain_no_credentials(idp, db, caplog):
    with caplog.at_level(logging.INFO):
        login(idp, ALICE[0], "wrong password entirely")
        login(idp, *ALICE)
    assert "wrong password entirely" not in caplog.text and ALICE[1] not in caplog.text
    assert "LOGIN OK user_id=user-001" in caplog.text and "LOGIN FAILED" in caplog.text


# --------------------------------------------------------------------------- #
# Storage (06.02)
# --------------------------------------------------------------------------- #
def test_password_is_never_stored(db):
    raw = db.read_bytes()
    for _, password in (ALICE, BOB):
        assert password.encode() not in raw


def test_stored_value_is_a_salted_argon2id_hash(db):
    assert stored_hash(db, ALICE[0]).startswith("$argon2id$v=19$m=65536,t=3,p=4$")


def test_users_db_is_owner_only(db):
    assert stat.S_IMODE(db.stat().st_mode) == 0o600


def test_database_refuses_a_non_argon2_value(db):
    conn = sqlite3.connect(db)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO users (user_id, username, password_hash) VALUES ('user-999', 'x', 'plaintext')")
    conn.close()


@pytest.mark.parametrize("bad", ["short", "", "x" * 1025])
def test_weak_or_absurd_passwords_are_refused_at_creation(tmp_path, bad):
    with pytest.raises(ValueError):
        users.create_user(tmp_path / "u.db", "carol", bad)


def test_duplicate_username_is_refused(db):
    with pytest.raises(ValueError, match="already exists"):
        users.create_user(db, " ALICE ", "a different long password")


# --------------------------------------------------------------------------- #
# Token signing module
# --------------------------------------------------------------------------- #
def test_token_module_signs_with_identity_key_for_the_agent():
    cfg = load_config()
    token = tokens.issue_user_token(cfg, tokens.load_private_key(IDENTITY_PRIVATE_FILE), "user-001")
    claims = jwt.decode(token, load_pem_public_key(IDENTITY_PUBLIC_PEM), algorithms=["RS256"],
                        audience="inventory-agent", issuer="a2a-human-identity-service")
    assert claims["sub"] == "user-001" and set(claims) == {"iss", "sub", "aud", "iat", "exp"}
    assert jwt.get_unverified_header(token)["kid"] == "identity-key-1"


def test_human_token_is_rejected_by_the_inventory_service(client, spy):
    token = tokens.issue_user_token(load_config(), tokens.load_private_key(IDENTITY_PRIVATE_FILE), "user-001")
    assert client.get("/stock/WIDGET-C", headers={"Authorization": f"Bearer {token}"}).status_code == 401
    assert spy.sqlite_touched is False


def test_identity_key_differs_from_agent_issuer_key():
    assert IDENTITY_PUBLIC_PEM != PUBLIC_PEM
