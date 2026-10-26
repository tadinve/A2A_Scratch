"""Day 06.08: human JWT in at the agent, machine JWT out to the Inventory Service."""

import base64
import json
import logging
import time
from dataclasses import replace
from urllib.parse import urlsplit

import httpx
import jwt
import pytest
from fastapi.testclient import TestClient

from tests.support import (
    ATTACKER_PRIVATE_PEM, IDENTITY_PRIVATE_FILE, READER_CLIENT, make_token, service,
)

from identity_service import tokens as human_tokens  # noqa: E402
from identity_service.config import load_config
from inventory_agent import app as agent_app
from inventory_agent import tools
from inventory_agent.human_auth import load_trust
from token_issuer import app as issuer_app

FOUND_A = {"status": "found", "sku": "WIDGET-A", "name": "Standard Widget", "quantity": 30}


def human_token(sub="user-001", **cfg_changes):
    cfg = replace(load_config(), **cfg_changes)
    return human_tokens.issue_user_token(cfg, human_tokens.load_private_key(IDENTITY_PRIVATE_FILE), sub)


def edit_claim(token, **changes):
    h, p, s = token.split(".")
    claims = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    claims.update(changes)
    return ".".join([h, base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode(), s])


@pytest.fixture
def agent():
    return TestClient(agent_app.app)


@pytest.fixture
def machine_calls(monkeypatch):
    """Replace the agent's machine call; record whether it happened."""
    calls = []

    def fake_fetch_stock(sku, forwarded_human=None):
        calls.append(sku)
        return dict(FOUND_A)
    monkeypatch.setattr(agent_app.tools, "fetch_stock", fake_fetch_stock)
    return calls


def ask(agent, token, sku="WIDGET-A", raw_header=None):
    headers = {}
    if raw_header is not None:
        headers["Authorization"] = raw_header
    elif token is not None:
        headers["Authorization"] = f"Bearer {token}"
    return agent.get(f"/agent/stock/{sku}", headers=headers)


# --------------------------------------------------------------------------- #
# Required tests
# --------------------------------------------------------------------------- #
def test_alices_valid_human_jwt_is_authenticated(agent, machine_calls):
    r = ask(agent, human_token())
    assert r.status_code == 200
    body = r.json()
    assert body["authenticated_human"] == "user-001"
    assert body["result"] == FOUND_A
    assert machine_calls == ["WIDGET-A"]


def test_missing_human_jwt_is_401(agent, machine_calls):
    r = ask(agent, None)
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == "Bearer"
    assert machine_calls == []                         # no machine call without a human


def test_tampered_human_jwt_is_401(agent, machine_calls):
    r = ask(agent, edit_claim(human_token(), sub="user-002"))
    assert r.status_code == 401 and machine_calls == []


def test_expired_human_jwt_is_401(agent, machine_calls):
    old = human_tokens.issue_user_token(load_config(), human_tokens.load_private_key(IDENTITY_PRIVATE_FILE),
                                        "user-001", now=int(time.time()) - 600)
    assert ask(agent, old).status_code == 401 and machine_calls == []


def test_wrong_audience_is_401(agent, machine_calls):
    assert ask(agent, human_token(audience="inventory-service")).status_code == 401 and machine_calls == []


def test_alice_jwt_sent_directly_to_inventory_service_is_401(client, spy):
    r = client.get("/stock/WIDGET-C", headers={"Authorization": f"Bearer {human_token()}"})
    assert r.status_code == 401
    assert spy.sqlite_touched is False


# --------------------------------------------------------------------------- #
# More ways a human token can be wrong
# --------------------------------------------------------------------------- #
def _bad_human_tokens():
    now = int(time.time())
    claims = {"iss": "a2a-human-identity-service", "sub": "user-001", "aud": "inventory-agent",
              "iat": now, "exp": now + 300}
    real_key = IDENTITY_PRIVATE_FILE.read_bytes()
    return {
        "wrong issuer": f"Bearer {human_token(issuer='evil-issuer')}",
        "signed by attacker": f"Bearer {jwt.encode(claims, ATTACKER_PRIVATE_PEM, algorithm='RS256', headers={'kid': 'identity-key-1'})}",
        "unknown kid": f"Bearer {jwt.encode(claims, real_key, algorithm='RS256', headers={'kid': 'key-9'})}",
        "Day 05 machine token": f"Bearer {make_token('inventory-agent')}",
        "garbage": "Bearer not-a-jwt",
        "basic scheme": "Basic abc",
        "token without scheme": human_token(),
    }


@pytest.mark.parametrize("label", list(_bad_human_tokens()))
def test_other_bad_tokens_are_401(agent, machine_calls, label):
    r = ask(agent, None, raw_header=_bad_human_tokens()[label])
    assert r.status_code == 401 and machine_calls == []


def test_response_never_contains_a_jwt(agent, machine_calls):
    token = human_token()
    r = ask(agent, token)
    assert token not in r.text and "eyJ" not in r.text


def test_logs_record_the_human_but_never_a_token(agent, machine_calls, caplog):
    token = human_token()
    with caplog.at_level(logging.INFO):
        ask(agent, token)
        ask(agent, "not-a-jwt")
    assert "AGENT REQUEST human=user-001 machine=" in caplog.text
    assert "AGENT HUMAN AUTHN FAILED" in caplog.text
    assert token not in caplog.text and "not-a-jwt" not in caplog.text


@pytest.mark.parametrize("status, http", [("not_found", 404), ("forbidden", 403), ("error", 503), ("unauthenticated", 502)])
def test_machine_side_outcomes_map_to_http(agent, monkeypatch, status, http):
    monkeypatch.setattr(agent_app.tools, "fetch_stock", lambda sku, forwarded_human=None: {"status": status, "message": "x"})
    assert ask(agent, human_token()).status_code == http


def test_bad_trust_config_fails_startup(tmp_path):
    bad = tmp_path / "agent.json"
    bad.write_text(json.dumps({"human_issuer": "x", "audience": "y",
                               "trusted_human_keys": {"k": str(IDENTITY_PRIVATE_FILE)}}))
    with pytest.raises(RuntimeError):
        load_trust(bad)                                 # a private key is not a trust anchor


# --------------------------------------------------------------------------- #
# End to end: human -> agent -> REAL issuer + REAL inventory service
# --------------------------------------------------------------------------- #
@pytest.fixture
def real_machine_path(monkeypatch, spy):
    issuer_http, service_http = TestClient(issuer_app.app), TestClient(service.app)
    monkeypatch.setattr(tools.httpx, "post", lambda url, headers=None, timeout=None: issuer_http.post("/token", headers=headers))
    monkeypatch.setattr(tools.httpx, "get", lambda url, headers=None, timeout=None: service_http.get(urlsplit(url).path, headers=headers))
    monkeypatch.setenv("INVENTORY_CLIENT_ID", READER_CLIENT[0])
    monkeypatch.setenv("INVENTORY_CLIENT_SECRET", READER_CLIENT[1])
    monkeypatch.setenv("INVENTORY_ISSUER_URL", "http://issuer")
    monkeypatch.setenv("INVENTORY_SERVICE_URL", "http://inventory")
    tools._clear_cache()
    yield spy
    tools._clear_cache()


@pytest.mark.parametrize("scope, sku, want_http, want_status", [
    ("inventory.read.class_a inventory.read.class_b inventory.read.class_c", "WIDGET-A", 200, "found"),
    ("inventory.read.class_b", "WIDGET-A", 403, "forbidden"),    # 05.5 scope rules preserved
    ("inventory.read.class_b", "WIDGET-B", 200, "found"),
    ("inventory.read.class_b", "WIDGET-X", 404, "not_found"),
])
def test_agent_uses_machine_credentials_and_existing_rules_hold(agent, real_machine_path, monkeypatch,
                                                                scope, sku, want_http, want_status):
    monkeypatch.setenv("INVENTORY_REQUESTED_SCOPE", scope)
    r = ask(agent, human_token(), sku)
    assert r.status_code == want_http
    assert r.json()["result"]["status"] == want_status
    assert r.json()["machine_identity"] == "inventory-agent"


def test_invalid_human_never_reaches_the_inventory_service(agent, real_machine_path, monkeypatch):
    monkeypatch.setenv("INVENTORY_REQUESTED_SCOPE", "inventory.read.class_c")
    ask(agent, "not-a-jwt", "WIDGET-C")
    assert real_machine_path.sqlite_touched is False


# --------------------------------------------------------------------------- #
# Day 06.08 acceptance: both credentials, each verified by its own party
# --------------------------------------------------------------------------- #
ALL_SCOPES = "inventory.read.class_a inventory.read.class_b inventory.read.class_c"


@pytest.fixture
def wire(monkeypatch, spy):
    """Route the agent's machine calls into the REAL issuer and service; record service statuses."""
    issuer_http, service_http = TestClient(issuer_app.app), TestClient(service.app)
    seen = {"service_status": [], "corrupt_machine_token": False}

    def get(url, headers=None, timeout=None):
        headers = dict(headers or {})
        if seen["corrupt_machine_token"]:
            headers["Authorization"] = "Bearer not-a-valid-machine-jwt"
        r = service_http.get(urlsplit(url).path, headers=headers)
        seen["service_status"].append(r.status_code)
        return r

    monkeypatch.setattr(tools.httpx, "post", lambda url, headers=None, timeout=None: issuer_http.post("/token", headers=headers))
    monkeypatch.setattr(tools.httpx, "get", get)
    for k, v in {"INVENTORY_CLIENT_ID": READER_CLIENT[0], "INVENTORY_CLIENT_SECRET": READER_CLIENT[1],
                 "INVENTORY_ISSUER_URL": "http://issuer", "INVENTORY_SERVICE_URL": "http://inventory",
                 "INVENTORY_REQUESTED_SCOPE": ALL_SCOPES}.items():
        monkeypatch.setenv(k, v)
    tools._clear_cache()
    seen["spy"] = spy
    yield seen
    tools._clear_cache()


def test_0608_valid_human_and_valid_machine_is_200_with_actual_stock(agent, wire):
    r = ask(agent, human_token(), "WIDGET-A")
    assert r.status_code == 200
    assert r.json()["result"] == FOUND_A                      # the spy repository's real record
    assert r.json()["authenticated_human"] == "user-001"
    assert wire["service_status"] == [200]


def test_0608_invalid_human_and_valid_machine_is_401_at_agent(agent, wire):
    r = ask(agent, "not-a-jwt", "WIDGET-A")
    assert r.status_code == 401
    assert wire["service_status"] == []                       # the service was never called
    assert wire["spy"].sqlite_touched is False


def test_0608_valid_human_and_invalid_machine_is_401_at_service(agent, wire):
    wire["corrupt_machine_token"] = True
    r = ask(agent, human_token(), "WIDGET-A")
    assert wire["service_status"] == [401]                    # the SERVICE rejected the machine token
    assert r.status_code == 502                               # Alice was fine; the agent's credential failed
    assert r.json()["result"]["status"] == "unauthenticated"
    assert wire["spy"].sqlite_touched is False


def test_0608_human_jwt_sent_directly_to_inventory_service_is_401(client, spy):
    r = client.get("/stock/WIDGET-A", headers={"Authorization": f"Bearer {human_token()}"})
    assert r.status_code == 401 and spy.sqlite_touched is False


def test_0608_machine_jwt_sent_to_agent_as_human_credential_is_401(agent, wire):
    machine_jwt = make_token("inventory-agent")               # a valid MACHINE token for the service
    r = ask(agent, machine_jwt, "WIDGET-A")
    assert r.status_code == 401
    assert wire["service_status"] == []


def test_0609_only_the_machine_token_and_a_plain_claim_go_downstream(agent, wire, monkeypatch):
    sent = []
    real_get = tools.httpx.get
    monkeypatch.setattr(tools.httpx, "get", lambda url, headers=None, timeout=None: sent.append(dict(headers or {})) or real_get(url, headers=headers, timeout=timeout))
    token = human_token()
    ask(agent, token, "WIDGET-A")
    (headers,) = sent
    assert set(headers) == {"Authorization", "Accept", "X-Human-User"}
    assert headers["X-Human-User"] == "user-001"              # 06.09 Experiment A: a plain assertion
    assert token not in str(headers)                          # the HUMAN token never goes downstream
