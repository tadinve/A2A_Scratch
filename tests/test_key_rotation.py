"""Day 05.8: signing-key rotation with overlap and retirement.

Every phase is a CONFIG change loaded through the same loaders the services use
at startup. No JWT logic changes between phases.

    issuer config:   "Which PRIVATE key do I sign with now?"
    service config:  "Which PUBLIC keys do I currently trust?"
"""

import json

import jwt
import pytest
from fastapi.testclient import TestClient

from tests.support import (
    KEY2_PRIVATE_FILE, KEY2_PRIVATE_PEM, KEY2_PUBLIC_FILE, PRIVATE_KEY_FILE, PRIVATE_PEM,
    PUBLIC_KEY_FILE, READER_CLIENT, get, make_token,
)

from inventory_service import auth as service_auth  # noqa: E402
from inventory_service.tokens import load_trusted_keys
from token_issuer import app as issuer_app
from token_issuer import issuer

B = "inventory.read.class_b"


# --------------------------------------------------------------------------- #
# Helpers: "edit the config file and restart"
# --------------------------------------------------------------------------- #
def trust(monkeypatch, tmp_path, **kids):
    """Service now trusts exactly these {kid: public key file}."""
    cfg = tmp_path / "inventory_service.json"
    cfg.write_text(json.dumps({"trusted_keys": {k: str(v) for k, v in kids.items()}}))
    monkeypatch.setattr(service_auth, "_TRUSTED_KEYS", load_trusted_keys(cfg, tmp_path))


def sign_with(monkeypatch, tmp_path, kid, private_file):
    """Issuer now signs with this key."""
    cfg = tmp_path / "issuer.json"
    cfg.write_text(json.dumps({"active_kid": kid, "private_key_path": str(private_file)}))
    active_kid, key = issuer.load_signing_config(cfg)
    monkeypatch.setattr(issuer, "ACTIVE_KID", active_kid)
    monkeypatch.setattr(issuer, "_PRIVATE_KEY", key)


@pytest.fixture
def issuer_client():
    return TestClient(issuer_app.app)


def issue(issuer_client):
    r = issuer_client.post("/token", headers={"X-Client-ID": READER_CLIENT[0],
                                              "X-Client-Secret": READER_CLIENT[1], "X-Scope": B})
    assert r.status_code == 200
    return r.json()["access_token"]


def kid_of(token):
    return jwt.get_unverified_header(token).get("kid")


# --------------------------------------------------------------------------- #
# Acceptance evidence
# --------------------------------------------------------------------------- #
def test_issuer_token_contains_active_kid(issuer_client, monkeypatch, tmp_path):
    assert kid_of(issue(issuer_client)) == "key-1"
    sign_with(monkeypatch, tmp_path, "key-2", KEY2_PRIVATE_FILE)
    assert kid_of(issue(issuer_client)) == "key-2"


def test_key1_token_accepted_when_key1_trusted(issuer_client, client, spy):
    # Startup state: issuer signs with key-1, service trusts key-1 only.
    assert get(client, "WIDGET-B", issue(issuer_client)).status_code == 200


def test_key2_token_accepted_when_key2_trusted(issuer_client, client, spy, monkeypatch, tmp_path):
    trust(monkeypatch, tmp_path, **{"key-2": KEY2_PUBLIC_FILE})
    sign_with(monkeypatch, tmp_path, "key-2", KEY2_PRIVATE_FILE)
    assert get(client, "WIDGET-B", issue(issuer_client)).status_code == 200


def test_full_rotation_overlap_then_retirement(issuer_client, client, spy, monkeypatch, tmp_path):
    # Step 5: only key-1.
    old_token = issue(issuer_client)
    assert kid_of(old_token) == "key-1"
    assert get(client, "WIDGET-B", old_token).status_code == 200

    # Step 7: introduce key-2 to the SERVICE first. Issuer unchanged.
    trust(monkeypatch, tmp_path, **{"key-1": PUBLIC_KEY_FILE, "key-2": KEY2_PUBLIC_FILE})
    assert kid_of(issue(issuer_client)) == "key-1"
    assert get(client, "WIDGET-B", old_token).status_code == 200

    # Step 8: switch the ISSUER to key-2.
    sign_with(monkeypatch, tmp_path, "key-2", KEY2_PRIVATE_FILE)
    new_token = issue(issuer_client)
    assert kid_of(new_token) == "key-2"

    # Step 9: overlap. Both generations work.
    assert get(client, "WIDGET-B", old_token).status_code == 200
    assert get(client, "WIDGET-B", new_token).status_code == 200

    # Step 11: retire key-1.
    trust(monkeypatch, tmp_path, **{"key-2": KEY2_PUBLIC_FILE})
    spy.class_calls.clear(); spy.detail_calls.clear()
    r = get(client, "WIDGET-B", old_token)
    assert r.status_code == 401
    assert spy.sqlite_touched is False              # retired-key tokens never reach SQLite
    assert get(client, "WIDGET-B", new_token).status_code == 200


def test_wrong_order_breaks_new_tokens(issuer_client, client, spy, monkeypatch, tmp_path):
    # Why the service must learn key-2 BEFORE the issuer uses it:
    sign_with(monkeypatch, tmp_path, "key-2", KEY2_PRIVATE_FILE)   # service still trusts key-1 only
    assert get(client, "WIDGET-B", issue(issuer_client)).status_code == 401


# --------------------------------------------------------------------------- #
# Bad kid behaviour: kid selects a key, it never authenticates
# --------------------------------------------------------------------------- #
def test_unknown_kid_is_401(client, spy):
    r = get(client, "WIDGET-B", make_token(kid="key-9"))
    assert r.status_code == 401
    assert spy.sqlite_touched is False


def with_raw_header(token: str, header: dict) -> str:
    """Swap in a hand-built header. PyJWT refuses to ENCODE a non-string kid,
    but an attacker can still send one, so the verifier must handle it."""
    import base64
    raw = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    return ".".join([raw, *token.split(".")[1:]])


@pytest.mark.parametrize("kid", [None, "", 7, ["key-1"]], ids=["missing", "empty", "number", "list"])
def test_missing_or_malformed_kid_is_401(client, spy, kid):
    if kid is None:
        token = make_token(kid=None)
    else:
        token = with_raw_header(make_token(), {"alg": "RS256", "typ": "JWT", "kid": kid})
    r = get(client, "WIDGET-B", token)
    assert r.status_code == 401
    assert spy.sqlite_touched is False


def test_kid_mismatched_with_signature_is_401(client, spy, monkeypatch, tmp_path):
    # Both keys trusted; token SIGNED with key-1 but CLAIMS kid=key-2.
    trust(monkeypatch, tmp_path, **{"key-1": PUBLIC_KEY_FILE, "key-2": KEY2_PUBLIC_FILE})
    forged = make_token(key=PRIVATE_PEM, kid="key-2")
    assert get(client, "WIDGET-B", forged).status_code == 401
    # And the reverse.
    assert get(client, "WIDGET-B", make_token(key=KEY2_PRIVATE_PEM, kid="key-1")).status_code == 401
    assert spy.sqlite_touched is False


def test_attacker_cannot_pick_a_trusted_kid(client, spy):
    from tests.support import ATTACKER_PRIVATE_PEM
    assert get(client, "WIDGET-B", make_token(key=ATTACKER_PRIVATE_PEM, kid="key-1")).status_code == 401


def test_kid_cannot_be_a_path_or_url(client, spy):
    # kid is only a dictionary lookup, never a file path or URL to fetch.
    for kid in ("../../keys/key-1-public.pem", str(PUBLIC_KEY_FILE), "https://evil.example/key.pem"):
        assert get(client, "WIDGET-B", make_token(kid=kid)).status_code == 401


# --------------------------------------------------------------------------- #
# Configuration fails closed
# --------------------------------------------------------------------------- #
def write(tmp_path, name, data):
    p = tmp_path / name
    p.write_text(data if isinstance(data, str) else json.dumps(data))
    return p


@pytest.mark.parametrize(
    "label, data",
    [
        ("not json", "{oops"),
        ("no trusted_keys", {}),
        ("empty trusted_keys", {"trusted_keys": {}}),
        ("missing key file", {"trusted_keys": {"key-1": "/nope/key.pem"}}),
        ("private key listed as trusted", {"trusted_keys": {"key-1": str(PRIVATE_KEY_FILE)}}),
        ("path not a string", {"trusted_keys": {"key-1": 5}}),
    ],
)
def test_bad_service_config_fails_startup(tmp_path, label, data):
    with pytest.raises(RuntimeError):
        load_trusted_keys(write(tmp_path, "svc.json", data), tmp_path)


def test_missing_service_config_fails_startup(tmp_path):
    with pytest.raises(RuntimeError, match="not readable"):
        load_trusted_keys(tmp_path / "absent.json", tmp_path)


@pytest.mark.parametrize(
    "label, data",
    [
        ("not json", "{oops"),
        ("no active_kid", {"private_key_path": str(PRIVATE_KEY_FILE)}),
        ("empty active_kid", {"active_kid": "", "private_key_path": str(PRIVATE_KEY_FILE)}),
        ("no key path", {"active_kid": "key-1"}),
        ("public key as signing key", {"active_kid": "key-1", "private_key_path": str(PUBLIC_KEY_FILE)}),
    ],
)
def test_bad_issuer_config_fails_startup(tmp_path, label, data):
    with pytest.raises(RuntimeError):
        issuer.load_signing_config(write(tmp_path, "issuer.json", data))


def test_relative_paths_resolve_from_project_root(tmp_path):
    (tmp_path / "keys").mkdir()
    (tmp_path / "keys" / "key-1-public.pem").write_bytes(PUBLIC_KEY_FILE.read_bytes())
    cfg = write(tmp_path, "svc.json", {"trusted_keys": {"key-1": "keys/key-1-public.pem"}})
    assert set(load_trusted_keys(cfg, tmp_path)) == {"key-1"}
