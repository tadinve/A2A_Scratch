"""Days 06-08: the Identity Service's signed human JWT, and that password login is gone.

How a human signs in (Google) is tested in tests/test_google_login.py.
"""

import jwt
import pytest
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from fastapi.testclient import TestClient

from tests.support import IDENTITY_PRIVATE_FILE, IDENTITY_PUBLIC_PEM, PUBLIC_PEM

from identity_service import app as identity_app  # noqa: E402  (after support sets the config)
from identity_service import tokens
from identity_service.config import load_config


@pytest.fixture
def idp():
    return TestClient(identity_app.app)


# --------------------------------------------------------------------------- #
# Day 08: Google is the only way in
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("method", ["post", "get"])
def test_password_login_route_is_gone(idp, method):
    r = getattr(idp, method)("/login", **({"json": {"username": "alice", "password": "x" * 20}}
                                          if method == "post" else {}))
    assert r.status_code == 404 and "access_token" not in r.text


def test_no_password_code_remains():
    import importlib.util
    assert importlib.util.find_spec("identity_service.passwords") is None
    assert importlib.util.find_spec("argon2") is None


def test_only_the_google_routes_are_exposed():
    # The OpenAPI schema lists every route, however include_router nests them in app.routes.
    paths = set(identity_app.app.openapi()["paths"])
    assert paths == {"/auth/google", "/auth/google/callback"}


def test_existing_inventory_jwt_security_unchanged(client, spy):
    assert client.get("/stock/WIDGET-C").status_code == 401
    assert client.get("/stock/WIDGET-C", headers={"X-User": "user-001"}).status_code == 401
    assert spy.sqlite_touched is False


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


def test_private_key_path_can_come_from_the_environment(monkeypatch, tmp_path):
    # Day 08: Cloud Run mounts the key from Secret Manager at a fixed path.
    monkeypatch.setenv("IDENTITY_PRIVATE_KEY_PATH", str(tmp_path / "signing-key.pem"))
    assert load_config().private_key_path == tmp_path / "signing-key.pem"
    monkeypatch.delenv("IDENTITY_PRIVATE_KEY_PATH")
    assert load_config().private_key_path == IDENTITY_PRIVATE_FILE
