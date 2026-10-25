"""Days 05.3-05.5: the token issuer decides identity, approves scopes, and alone holds the private key."""

import base64
import inspect
import json
import time
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from fastapi.testclient import TestClient

from tests.support import PRIVATE_PEM, PUBLIC_PEM, READER_CLIENT, RESTRICTED_CLIENT, get

from token_issuer import app as issuer_app  # noqa: E402  (after support sets env)
from token_issuer import auth as issuer_auth
from token_issuer import issuer
from inventory_service.tokens import load_public_key, verify_token

ROOT = Path(__file__).resolve().parent.parent
A, B, C = "inventory.read.class_a", "inventory.read.class_b", "inventory.read.class_c"
PUBLIC_KEY = load_pem_public_key(PUBLIC_PEM)


@pytest.fixture
def issuer_client():
    return TestClient(issuer_app.app)


def request_token(issuer_client, client=None, scope=None, **kwargs):
    headers = dict(kwargs.pop("headers", {}) or {})
    if client is not None:
        headers["X-Client-ID"], headers["X-Client-Secret"] = client
    if scope is not None:
        headers["X-Scope"] = scope
    return issuer_client.post("/token", headers=headers, **kwargs)


def claims_of(token: str) -> dict:
    """Read claims WITHOUT verifying (what anyone holding the token can do)."""
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


# --------------------------------------------------------------------------- #
# Issuing
# --------------------------------------------------------------------------- #
def test_valid_request_gets_a_token(issuer_client):
    r = request_token(issuer_client, READER_CLIENT, B)
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"access_token", "token_type", "expires_in", "scope"}
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == 300
    assert body["scope"] == B
    assert r.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("client, sub", [(READER_CLIENT, "inventory-agent"), (RESTRICTED_CLIENT, "restricted-agent")])
def test_issued_claims_are_correct(issuer_client, client, sub):
    token = request_token(issuer_client, client, C).json()["access_token"]
    claims = verify_token(token, {"key-1": PUBLIC_KEY})  # verifies with the PUBLIC key only
    assert claims["sub"] == sub
    assert claims["iss"] == "a2a-local-issuer"
    assert claims["aud"] == "inventory-service"
    assert claims["scope"] == C
    assert claims["exp"] - claims["iat"] == 300


def test_issued_token_expires():
    old = issuer.issue_access_token("inventory-agent", {B}, now=int(time.time()) - 600)
    with pytest.raises(jwt.ExpiredSignatureError):
        verify_token(old, {"key-1": PUBLIC_KEY})


# --------------------------------------------------------------------------- #
# 05.5 acceptance at the issuer: request authority, never grant it to yourself
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "label, client, scope, want_status, want_scope",
    [
        ("inventory-agent asks class_b",   READER_CLIENT,     B, 200, B),
        ("inventory-agent asks class_a",   READER_CLIENT,     A, 200, A),
        ("restricted-agent asks class_a",  RESTRICTED_CLIENT, A, 403, None),   # the key test
        ("restricted-agent asks class_b",  RESTRICTED_CLIENT, B, 200, B),
    ],
    ids=lambda v: v if isinstance(v, str) and " asks " in v else None,
)
def test_scope_acceptance(issuer_client, label, client, scope, want_status, want_scope):
    r = request_token(issuer_client, client, scope)
    print(f"{label:<32} HTTP {r.status_code}  {r.json()}")
    assert r.status_code == want_status
    if want_scope:
        assert claims_of(r.json()["access_token"])["scope"] == want_scope
    else:
        assert r.json()["status"] == "scope_not_allowed"
        assert "access_token" not in r.text


def test_entitled_client_can_request_less_than_its_entitlement(issuer_client):
    # inventory-agent may have A/B/C but asks only for B: the token carries only B.
    token = request_token(issuer_client, READER_CLIENT, B).json()["access_token"]
    assert claims_of(token)["scope"] == B


def test_several_scopes_are_granted_together_and_canonicalised(issuer_client):
    r = request_token(issuer_client, RESTRICTED_CLIENT, f"{C} {B}  {C}")
    assert r.status_code == 200
    assert r.json()["scope"] == f"{B} {C}"


def test_one_disallowed_scope_refuses_the_whole_request(issuer_client):
    r = request_token(issuer_client, RESTRICTED_CLIENT, f"{B} {A}")
    assert r.status_code == 403
    assert "access_token" not in r.text


@pytest.mark.parametrize(
    "label, scope",
    [("missing", None), ("empty", ""), ("only spaces", "   "),
     ("unknown scope", "inventory.write"), ("admin", "admin"), ("known + unknown", f"{B} admin")],
)
def test_missing_or_unknown_scope_is_400(issuer_client, label, scope):
    r = request_token(issuer_client, READER_CLIENT, scope)
    assert r.status_code == 400
    assert r.json()["status"] == "invalid_scope"
    assert "access_token" not in r.text


def test_authentication_is_checked_before_scope(issuer_client):
    # Bad credentials asking for an unknown scope still get 401, not 400.
    r = request_token(issuer_client, ("inventory-agent", "wrong"), "admin")
    assert r.status_code == 401


@pytest.mark.parametrize(
    "label, extra",
    [
        ("JSON body scope", {"json": {"scope": A}}),
        ("query scope", {"params": {"scope": A}}),
    ],
)
def test_scope_from_body_or_query_is_ignored(issuer_client, label, extra):
    # restricted-agent asks for B in the header and smuggles A elsewhere: only B is granted.
    r = request_token(issuer_client, RESTRICTED_CLIENT, B, **extra)
    assert r.status_code == 200
    assert claims_of(r.json()["access_token"])["scope"] == B


# --------------------------------------------------------------------------- #
# Authentication failures: 401, no token
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "label, client",
    [
        ("wrong secret", ("inventory-agent", "not-the-secret")),
        ("unknown client", ("admin-agent", "anything")),
        ("another client's secret", ("restricted-agent", READER_CLIENT[1])),
        ("empty secret", ("inventory-agent", "")),
    ],
)
def test_bad_credentials_are_401(issuer_client, label, client):
    r = request_token(issuer_client, client, B)
    assert r.status_code == 401
    assert r.json() == {"status": "unauthenticated", "message": "Client could not be authenticated."}
    assert "access_token" not in r.text
    assert client[1] == "" or client[1] not in r.text  # secret never echoed


@pytest.mark.parametrize("headers", [{}, {"X-Client-ID": "inventory-agent"}, {"X-Client-Secret": READER_CLIENT[1]}])
def test_missing_credentials_are_401(issuer_client, headers):
    assert request_token(issuer_client, scope=B, headers=headers).status_code == 401


def test_get_is_not_allowed(issuer_client):
    assert issuer_client.get("/token").status_code == 405


# --------------------------------------------------------------------------- #
# The caller cannot choose `sub`
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "label, extra",
    [
        ("JSON body sub", {"json": {"sub": "inventory-agent"}}),
        ("form body sub", {"data": {"sub": "inventory-agent"}}),
        ("query sub", {"params": {"sub": "inventory-agent"}}),
        ("header X-Sub", {"headers": {"X-Sub": "inventory-agent"}}),
        ("header X-Identity", {"headers": {"X-Identity": "inventory-agent"}}),
    ],
)
def test_caller_cannot_choose_sub(issuer_client, label, extra):
    r = request_token(issuer_client, RESTRICTED_CLIENT, B, **extra)
    assert r.status_code == 200
    assert claims_of(r.json()["access_token"])["sub"] == "restricted-agent"


def test_identity_and_entitlement_come_from_issuer_registry(issuer_client, monkeypatch):
    # Change the registry entry: the same credentials now get a different sub and entitlement.
    old = issuer_auth._CLIENTS["restricted-agent"]
    monkeypatch.setitem(issuer_auth._CLIENTS, "restricted-agent",
                        issuer_auth.Client(old.secret, "renamed-agent", frozenset({A})))
    r = request_token(issuer_client, RESTRICTED_CLIENT, A)
    assert r.status_code == 200
    assert claims_of(r.json()["access_token"])["sub"] == "renamed-agent"


def test_token_endpoint_reads_only_these_headers():
    params = inspect.signature(issuer_app.token).parameters
    assert set(params) == {"client_id", "client_secret", "scope"}


# --------------------------------------------------------------------------- #
# End to end: issuer token -> inventory service (service does not enforce scope yet)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "client_creds, scope, sku, want",
    [
        (READER_CLIENT, A, "WIDGET-A", 200),
        (RESTRICTED_CLIENT, B, "WIDGET-A", 403),   # role still denies class A
        (RESTRICTED_CLIENT, C, "WIDGET-C", 200),
    ],
    ids=["reader-A", "restricted-A", "restricted-C"],
)
def test_inventory_service_accepts_issued_tokens(issuer_client, client, spy, client_creds, scope, sku, want):
    token = request_token(issuer_client, client_creds, scope).json()["access_token"]
    assert get(client, sku, token).status_code == want


# --------------------------------------------------------------------------- #
# Configuration fails closed
# --------------------------------------------------------------------------- #
def test_issuer_fails_closed_without_client_secrets(monkeypatch):
    monkeypatch.delenv("CLIENT_SECRET_RESTRICTED_AGENT")
    with pytest.raises(RuntimeError, match="must be set"):
        issuer_auth.load_clients()


def test_issuer_rejects_shared_client_secrets(monkeypatch):
    monkeypatch.setenv("CLIENT_SECRET_RESTRICTED_AGENT", READER_CLIENT[1])
    with pytest.raises(RuntimeError, match="must be unique"):
        issuer_auth.load_clients()


def test_issuer_rejects_entitlement_to_unknown_scope(monkeypatch):
    bad = dict(issuer_auth.REGISTERED_CLIENTS["restricted-agent"], allowed_scopes={"inventory.write"})
    monkeypatch.setitem(issuer_auth.REGISTERED_CLIENTS, "restricted-agent", bad)
    with pytest.raises(RuntimeError, match="unknown scopes"):
        issuer_auth.load_clients()


# --------------------------------------------------------------------------- #
# Private key ownership
# --------------------------------------------------------------------------- #
PRIVATE_KEY_MARKERS = ("JWT_PRIVATE_KEY_PATH", "private_key_path", "private.pem", "load_pem_private_key", "RSAPrivateKey")


@pytest.mark.parametrize("package", ["inventory_service", "inventory_agent"])
def test_private_key_is_not_referenced_outside_issuer(package):
    for path in (ROOT / package).glob("*.py"):
        source = path.read_text()
        for marker in PRIVATE_KEY_MARKERS:
            assert marker not in source, f"{path.name} references {marker}"


def test_inventory_service_refuses_a_private_key_file(tmp_path):
    wrong = tmp_path / "private.pem"
    wrong.write_bytes(PRIVATE_PEM)
    with pytest.raises(RuntimeError):
        load_public_key(wrong)


def test_issuer_refuses_a_public_key_file(tmp_path):
    wrong = tmp_path / "public.pem"
    wrong.write_bytes(PUBLIC_PEM)
    with pytest.raises(RuntimeError, match="not an unencrypted PEM private key"):
        issuer.load_private_key(wrong)
