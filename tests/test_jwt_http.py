"""Day 05.2 acceptance: JWT bearer authentication over the full HTTP path.

Non-negotiable: on every 401 path, SQLite is never touched
(neither the classification lookup nor the detail lookup).
"""

import base64
import json

import jwt
import pytest

from inventory_service import auth
from inventory_service.tokens import load_public_key
from tests.support import (
    ATTACKER_PRIVATE_PEM, PRIVATE_PEM, PUBLIC_KEY_FILE, READER_TOKEN, RESTRICTED_TOKEN, get, make_token,
)


def _tamper_sub(token: str, new_sub: str) -> str:
    header, payload, signature = token.split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    claims["sub"] = new_sub
    forged = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    return ".".join([header, forged, signature])


# --------------------------------------------------------------------------- #
# The seven acceptance cases
# --------------------------------------------------------------------------- #
ACCEPTANCE = [
    # label,                                  token,                                          sku,        status
    ("no Authorization header",               None,                                           "WIDGET-A", 401),
    ("garbage bearer token",                  "not-a-jwt",                                    "WIDGET-A", 401),
    ("signed by wrong private key",           make_token(key=ATTACKER_PRIVATE_PEM),           "WIDGET-A", 401),
    ("expired",                               make_token(iat=1_000_000, exp=1_000_300),       "WIDGET-A", 401),
    ("wrong aud",                             make_token(aud="billing-service"),              "WIDGET-A", 401),
    ("valid JWT, unauthorized identity",      RESTRICTED_TOKEN,                               "WIDGET-A", 403),
    ("valid JWT, authorized identity",        READER_TOKEN,                                   "WIDGET-A", 200),
]


@pytest.mark.parametrize("label, token, sku, want", ACCEPTANCE, ids=[c[0] for c in ACCEPTANCE])
def test_acceptance(client, spy, label, token, sku, want):
    r = get(client, sku, token)
    print(f"{label:<36} HTTP {r.status_code}  sqlite_touched={spy.sqlite_touched}")
    assert r.status_code == want
    if want == 401:
        assert spy.sqlite_touched is False          # the boundary sits in front of SQLite
        assert r.headers["www-authenticate"] == "Bearer"
        assert r.json()["status"] == "unauthenticated"
    if want == 403:
        assert spy.detail_lookup is False           # class read, details never read
        assert r.json()["status"] == "forbidden"
    if want == 200:
        assert r.json()["sku"] == sku


# --------------------------------------------------------------------------- #
# More ways a token can be bad: all 401, all before SQLite
# --------------------------------------------------------------------------- #
BAD_TOKENS = [
    ("payload edited: sub -> admin-agent",  _tamper_sub(RESTRICTED_TOKEN, "inventory-agent")),
    ("wrong iss",                           make_token(iss="some-other-issuer")),
    ("missing exp",                         make_token(drop=("exp",))),
    ("missing sub",                         make_token(drop=("sub",))),
    ("alg none",                            jwt.encode({"sub": "inventory-agent"}, None, algorithm="none")),
    ("HS256",                               make_token(key="a-shared-secret-of-at-least-32-bytes!!", algorithm="HS256")),
    ("RS512 with the real key",             make_token(algorithm="RS512")),
    ("exp in 1970",                         make_token(exp=1)),
]


@pytest.mark.parametrize("label, token", BAD_TOKENS, ids=[c[0] for c in BAD_TOKENS])
def test_bad_tokens_are_401_without_sqlite(client, spy, label, token):
    r = get(client, "WIDGET-C", token)   # class C: readable by everyone, so only authn can stop it
    assert r.status_code == 401
    assert spy.sqlite_touched is False


# --------------------------------------------------------------------------- #
# Malformed Authorization headers
# --------------------------------------------------------------------------- #
MALFORMED = [
    ("empty header",               ""),
    ("scheme only",                "Bearer"),
    ("scheme and space",           "Bearer "),
    ("wrong scheme",               f"Basic {READER_TOKEN}"),
    ("token without scheme",       READER_TOKEN),
    ("extra part after token",     f"Bearer {READER_TOKEN} extra"),
]


@pytest.mark.parametrize("label, header", MALFORMED, ids=[c[0] for c in MALFORMED])
def test_malformed_authorization_header_is_401(client, spy, label, header):
    r = client.get("/stock/WIDGET-C", headers={"Authorization": header})
    assert r.status_code == 401
    assert spy.sqlite_touched is False


def test_scheme_is_case_insensitive(client, spy):
    r = client.get("/stock/WIDGET-C", headers={"Authorization": f"bearer {READER_TOKEN}"})
    assert r.status_code == 200


def test_old_api_key_header_no_longer_works(client, spy):
    r = client.get("/stock/WIDGET-C", headers={"X-API-Key": "demo-local-secret"})
    assert r.status_code == 401
    assert spy.sqlite_touched is False


# --------------------------------------------------------------------------- #
# Identity comes from the verified `sub`, authorization unchanged
# --------------------------------------------------------------------------- #
def test_identity_is_the_verified_sub(client, spy):
    # Same request, two tokens: the only difference is `sub`.
    assert get(client, "WIDGET-A", make_token("inventory-agent")).status_code == 200
    assert get(client, "WIDGET-A", make_token("restricted-agent")).status_code == 403


def test_validly_signed_unknown_identity_is_403_not_401(client, spy):
    # Authenticated (the issuer really signed it), but no role -> deny by default.
    r = get(client, "WIDGET-C", make_token("admin-agent"))
    assert r.status_code == 403
    assert spy.detail_lookup is False


def test_token_is_never_echoed(client, spy):
    for token in (READER_TOKEN, RESTRICTED_TOKEN, "not-a-jwt"):
        r = get(client, "WIDGET-A", token)
        assert token not in r.text


def test_extract_bearer_token_unit():
    assert auth.extract_bearer_token("Bearer abc.def.ghi") == "abc.def.ghi"
    assert auth.extract_bearer_token("BEARER  abc") == "abc"
    for bad in (None, "", "Bearer", "Bearer   ", "Basic abc", "abc", "Bearer a b"):
        assert auth.extract_bearer_token(bad) is None


# --------------------------------------------------------------------------- #
# The service owns its trust configuration and fails closed at startup
# --------------------------------------------------------------------------- #
def test_missing_public_key_fails_startup(tmp_path):
    with pytest.raises(RuntimeError, match="not readable"):
        load_public_key(tmp_path / "nope.pem")


def test_private_key_file_is_rejected_as_public_key(tmp_path):
    wrong = tmp_path / "jwt-private.pem"
    wrong.write_bytes(PRIVATE_PEM)
    with pytest.raises(RuntimeError, match="not a PEM public key"):
        load_public_key(wrong)


def test_garbage_key_file_is_rejected(tmp_path):
    junk = tmp_path / "junk.pem"
    junk.write_text("hello")
    with pytest.raises(RuntimeError):
        load_public_key(junk)


def test_test_key_file_loads():
    assert load_public_key(PUBLIC_KEY_FILE) is not None
