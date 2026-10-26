"""Day 06.04: /login issues a signed human JWT that the agent can verify with the PUBLIC key."""

import base64
import json
import time
from dataclasses import replace
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from fastapi.testclient import TestClient

from tests.support import (
    ATTACKER_PRIVATE_PEM, IDENTITY_PRIVATE_FILE, IDENTITY_PUBLIC_PEM, IDENTITY_USERS_DB, PUBLIC_PEM, make_token,
)

from identity_service import app as identity_app  # noqa: E402
from identity_service import tokens, users
from identity_service.config import load_config
from scripts.verify_human_jwt import verify_human_token

ALICE = ("alice", "correct horse battery staple")
PUBLIC_KEY = load_pem_public_key(IDENTITY_PUBLIC_PEM)


@pytest.fixture
def db():
    if IDENTITY_USERS_DB.exists():
        IDENTITY_USERS_DB.unlink()
    users.create_user(IDENTITY_USERS_DB, *ALICE)
    yield IDENTITY_USERS_DB
    IDENTITY_USERS_DB.unlink()


@pytest.fixture
def idp():
    return TestClient(identity_app.app)


def alice_token(idp):
    r = idp.post("/login", json={"username": ALICE[0], "password": ALICE[1]})
    assert r.status_code == 200
    return r.json()["access_token"]


def edit_claim(token, **changes):
    header, payload, signature = token.split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    claims.update(changes)
    forged = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    return ".".join([header, forged, signature])


# --------------------------------------------------------------------------- #
# The token the agent receives
# --------------------------------------------------------------------------- #
def test_login_token_verifies_with_the_public_key(idp, db):
    claims = verify_human_token(alice_token(idp), PUBLIC_KEY)
    assert claims["sub"] == "user-001"
    assert claims["iss"] == "a2a-human-identity-service"
    assert claims["aud"] == "inventory-agent"


def test_claims_are_exactly_the_five_and_nothing_personal(idp, db):
    claims = jwt.decode(alice_token(idp), options={"verify_signature": False})
    assert set(claims) == {"iss", "sub", "aud", "iat", "exp"}
    assert ALICE[0] not in json.dumps(claims) and ALICE[1] not in json.dumps(claims)


def test_lifetime_is_five_minutes_from_now(idp, db):
    before = int(time.time())
    claims = verify_human_token(alice_token(idp), PUBLIC_KEY)
    assert before - 1 <= claims["iat"] <= int(time.time()) + 1      # real current time
    assert claims["exp"] - claims["iat"] == 300


def test_header_names_the_identity_key_and_rs256(idp, db):
    header = jwt.get_unverified_header(alice_token(idp))
    assert header == {"alg": "RS256", "typ": "JWT", "kid": "identity-key-1"}


def test_each_login_gets_a_fresh_token(idp, db):
    a = alice_token(idp)
    time.sleep(1.1)
    assert alice_token(idp) != a


def test_failed_login_issues_no_token(idp, db):
    r = idp.post("/login", json={"username": ALICE[0], "password": "wrong password entirely"})
    assert r.status_code == 401 and "access_token" not in r.text and "eyJ" not in r.text


# --------------------------------------------------------------------------- #
# What the agent's verifier must reject
# --------------------------------------------------------------------------- #
def test_edited_sub_is_rejected(idp, db):
    with pytest.raises(jwt.InvalidSignatureError):
        verify_human_token(edit_claim(alice_token(idp), sub="user-002"), PUBLIC_KEY)


def test_token_signed_by_another_key_is_rejected():
    now = int(time.time())
    forged = jwt.encode({"iss": "a2a-human-identity-service", "sub": "user-001", "aud": "inventory-agent",
                         "iat": now, "exp": now + 300},
                        ATTACKER_PRIVATE_PEM, algorithm="RS256", headers={"kid": "identity-key-1"})
    with pytest.raises(jwt.InvalidSignatureError):
        verify_human_token(forged, PUBLIC_KEY)


def test_expired_token_is_rejected():
    old = tokens.issue_user_token(load_config(), tokens.load_private_key(IDENTITY_PRIVATE_FILE), "user-001",
                                  now=int(time.time()) - 600)
    with pytest.raises(jwt.ExpiredSignatureError):
        verify_human_token(old, PUBLIC_KEY)


def test_agent_token_is_not_a_human_token():
    # An AGENT token (Day 05 issuer, other key, aud=inventory-service) must not pass as a human.
    with pytest.raises(jwt.InvalidTokenError):
        verify_human_token(make_token("inventory-agent"), PUBLIC_KEY)


def test_wrong_audience_is_rejected():
    other = tokens.issue_user_token(replace(load_config(), audience="inventory-service"),
                                    tokens.load_private_key(IDENTITY_PRIVATE_FILE), "user-001")
    with pytest.raises(jwt.InvalidAudienceError):
        verify_human_token(other, PUBLIC_KEY)


# --------------------------------------------------------------------------- #
# Trust boundaries
# --------------------------------------------------------------------------- #
def test_inventory_service_still_rejects_human_tokens(idp, db, client, spy):
    r = client.get("/stock/WIDGET-C", headers={"Authorization": f"Bearer {alice_token(idp)}"})
    assert r.status_code == 401
    assert spy.sqlite_touched is False


def test_verifier_never_touches_a_private_key():
    source = (Path(__file__).resolve().parent.parent / "scripts" / "verify_human_jwt.py").read_text()
    for marker in ("load_pem_private_key", "RSAPrivateKey", "private_key_path", "private.pem"):
        assert marker not in source


def test_identity_and_agent_keys_differ():
    assert IDENTITY_PUBLIC_PEM != PUBLIC_PEM
