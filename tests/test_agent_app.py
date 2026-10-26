"""Day 06.07: human authentication at the agent boundary. A failed human never triggers a machine call."""

import base64
import json
import time
from dataclasses import replace

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from tests.support import IDENTITY_PRIVATE_FILE, make_token

from identity_service import tokens as human_tokens  # noqa: E402
from identity_service.config import load_config
from inventory_agent import app as agent_app
from inventory_agent.human_auth import GENERIC_401, authenticate_human

GENERIC_BODY = {"status": "unauthenticated", "message": GENERIC_401}


def human_token(sub="user-001", now=None, **cfg_changes):
    cfg = replace(load_config(), **cfg_changes)
    return human_tokens.issue_user_token(cfg, human_tokens.load_private_key(IDENTITY_PRIVATE_FILE), sub, now=now)


def tamper(token, **changes):
    h, p, s = token.split(".")
    c = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    c.update(changes)
    return ".".join([h, base64.urlsafe_b64encode(json.dumps(c).encode()).rstrip(b"=").decode(), s])


@pytest.fixture
def downstream(monkeypatch):
    calls = []
    monkeypatch.setattr(agent_app.tools, "get_delegation", lambda subject_token: ("stub-delegation", None))
    monkeypatch.setattr(agent_app.tools, "fetch_stock",
                        lambda sku, **kw: calls.append(sku) or {"status": "found", "sku": sku, "name": "x", "quantity": 1})
    return calls


@pytest.fixture
def agent(downstream):
    return TestClient(agent_app.app)


def ask(agent, header):
    return agent.get("/agent/stock/WIDGET-A", headers={} if header is None else {"Authorization": header})


# --------------------------------------------------------------------------- #
# The step 6 table
# --------------------------------------------------------------------------- #
def test_valid_alice_jwt_is_200_with_human_sub(agent, downstream):
    r = ask(agent, f"Bearer {human_token()}")
    assert r.status_code == 200
    assert r.json()["authenticated_human"] == "user-001"
    assert downstream == ["WIDGET-A"]


FAILURES = {
    "no Authorization header": lambda: None,
    "Bearer fake-token": lambda: "Bearer fake-token",
    "tampered JWT": lambda: f"Bearer {tamper(human_token(), sub='user-002')}",
    "expired JWT": lambda: f"Bearer {human_token(now=int(time.time()) - 600)}",
    "valid JWT for wrong audience": lambda: f"Bearer {human_token(audience='inventory-service')}",
    "wrong issuer": lambda: f"Bearer {human_token(issuer='evil-issuer')}",
    "Day 05 machine token": lambda: f"Bearer {make_token('inventory-agent')}",
    "Basic scheme": lambda: "Basic YWxpY2U6cGFzcw==",
    "token without Bearer": lambda: human_token(),
}


@pytest.mark.parametrize("label", list(FAILURES))
def test_invalid_credentials_get_one_generic_401(agent, downstream, label):
    r = ask(agent, FAILURES[label]())
    assert r.status_code == 401
    assert downstream == []                             # no machine call for a failed human
    assert r.json() == GENERIC_BODY                     # identical for every failure
    assert r.headers["www-authenticate"] == "Bearer"
    for leak in ("signature", "kid", "expired", "audience", "issuer", "key"):
        assert leak not in r.text.lower()


def test_response_never_echoes_the_token(agent):
    token = human_token()
    assert token not in ask(agent, f"Bearer {token}").text


def test_reason_is_logged_server_side_without_the_token(agent, caplog):
    import logging
    bad = tamper(human_token(), sub="user-002")
    with caplog.at_level(logging.WARNING):
        ask(agent, f"Bearer {bad}")
    assert "AGENT HUMAN AUTHN FAILED reason=InvalidSignatureError" in caplog.text
    assert bad not in caplog.text


# --------------------------------------------------------------------------- #
# authenticate_human() as a unit
# --------------------------------------------------------------------------- #
def test_authenticate_human_returns_the_subject():
    assert authenticate_human(f"Bearer {human_token('user-042')}") == {"sub": "user-042"}


@pytest.mark.parametrize("header", [None, "", "Bearer", "Bearer   ", "bearer x y", "Token abc"])
def test_authenticate_human_rejects_malformed_headers(header):
    with pytest.raises(HTTPException) as exc:
        authenticate_human(header)
    assert exc.value.status_code == 401


def test_scheme_is_case_insensitive(agent):
    assert ask(agent, f"bearer {human_token()}").status_code == 200
