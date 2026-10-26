"""Day 06.09 Experiment A: forwarding a human identity as a plain header is NOT trust.

An authenticated machine can put any value in X-Human-User. The Inventory Service
logs it as an untrusted claim and never lets it change an authorization decision.
"""

import inspect
import logging
from dataclasses import replace
from urllib.parse import urlsplit

import pytest
from fastapi.testclient import TestClient

from tests.support import (
    IDENTITY_PRIVATE_FILE, READER_CLIENT, READER_TOKEN, RESTRICTED_TOKEN, get, service,
)

from identity_service import tokens as human_tokens  # noqa: E402
from identity_service.config import load_config
from inventory_agent import app as agent_app
from inventory_agent import tools
from token_issuer import app as issuer_app


def alice_token():
    return human_tokens.issue_user_token(load_config(), human_tokens.load_private_key(IDENTITY_PRIVATE_FILE), "user-001")


@pytest.fixture
def wired(monkeypatch, spy):
    """Agent -> REAL issuer + REAL service; capture what the agent sends downstream."""
    issuer_http, service_http = TestClient(issuer_app.app), TestClient(service.app)
    sent = []

    def get_(url, headers=None, timeout=None):
        sent.append(dict(headers or {}))
        return service_http.get(urlsplit(url).path, headers=headers)

    monkeypatch.setattr(tools.httpx, "post", lambda url, headers=None, timeout=None: issuer_http.post("/token", headers=headers))
    monkeypatch.setattr(tools.httpx, "get", get_)
    for k, v in {"INVENTORY_CLIENT_ID": READER_CLIENT[0], "INVENTORY_CLIENT_SECRET": READER_CLIENT[1],
                 "INVENTORY_ISSUER_URL": "http://issuer", "INVENTORY_SERVICE_URL": "http://inventory",
                 "INVENTORY_REQUESTED_SCOPE": "inventory.read.class_b"}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("EXPERIMENT_FORWARD_HUMAN_AS", raising=False)
    tools._clear_cache()
    yield sent
    tools._clear_cache()


def ask_agent(sku="WIDGET-B"):
    return TestClient(agent_app.app).get(f"/agent/stock/{sku}", headers={"Authorization": f"Bearer {alice_token()}"})


# --------------------------------------------------------------------------- #
# The experiment, end to end
# --------------------------------------------------------------------------- #
def test_agent_forwards_the_verified_human_as_a_header(wired, caplog):
    with caplog.at_level(logging.INFO):
        r = ask_agent()
    assert r.status_code == 200
    assert wired[-1]["X-Human-User"] == "user-001"
    assert "UNTRUSTED CLAIM X-Human-User='user-001' asserted by machine=inventory-agent" in caplog.text


def test_agent_can_be_made_to_forward_admin_and_the_service_cannot_tell(wired, monkeypatch, caplog):
    monkeypatch.setenv("EXPERIMENT_FORWARD_HUMAN_AS", "admin")
    with caplog.at_level(logging.INFO):
        r = ask_agent()
    assert r.status_code == 200                              # same outcome as for Alice
    assert wired[-1]["X-Human-User"] == "admin"              # Alice logged in; the agent claims "admin"
    assert r.json()["authenticated_human"] == "user-001"     # the agent KNOWS it was Alice...
    assert "EXPERIMENT forwarding X-Human-User='admin' instead of verified human=user-001" in caplog.text
    assert "UNTRUSTED CLAIM X-Human-User='admin'" in caplog.text   # ...the service just sees a string


# --------------------------------------------------------------------------- #
# The claim never changes an authorization decision
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("claim", [None, "user-001", "admin", "root", ""])
def test_claim_does_not_change_reader_outcomes(client, spy, claim):
    extra = {} if claim is None else {"X-Human-User": claim}
    outcomes = {sku: get(client, sku, READER_TOKEN, headers=extra).status_code for sku in ("WIDGET-A", "WIDGET-B", "WIDGET-X")}
    assert outcomes == {"WIDGET-A": 200, "WIDGET-B": 200, "WIDGET-X": 404}


@pytest.mark.parametrize("claim", [None, "user-001", "admin"])
def test_admin_claim_does_not_lift_a_restricted_machine(client, spy, claim):
    extra = {} if claim is None else {"X-Human-User": claim}
    r = get(client, "WIDGET-A", RESTRICTED_TOKEN, headers=extra)
    assert r.status_code == 403
    assert spy.detail_lookup is False


def test_claim_without_a_machine_token_is_still_401(client, spy):
    r = client.get("/stock/WIDGET-B", headers={"X-Human-User": "admin"})
    assert r.status_code == 401 and spy.sqlite_touched is False


def test_claim_is_never_echoed_in_the_response(client, spy):
    r = get(client, "WIDGET-B", READER_TOKEN, headers={"X-Human-User": "admin-marker-xyz"})
    assert "admin-marker-xyz" not in r.text


# --------------------------------------------------------------------------- #
# Logging hygiene for an attacker-controlled value
# --------------------------------------------------------------------------- #
def test_forged_header_cannot_inject_log_lines(client, spy, caplog):
    forged = "user-001\nINFO:     AUTHZ OK identity=admin"
    import httpx as _h
    with caplog.at_level(logging.INFO):
        try:
            get(client, "WIDGET-B", READER_TOKEN, headers={"X-Human-User": forged})
        except (_h.LocalProtocolError, ValueError):
            pytest.skip("HTTP client refuses newlines in headers, so injection can't even be sent")
    lines = [l for l in caplog.text.splitlines() if "UNTRUSTED CLAIM" in l]
    assert len(lines) == 1 and "\\n" in lines[0]


def test_long_claim_is_truncated_in_the_log(client, spy, caplog):
    with caplog.at_level(logging.INFO):
        get(client, "WIDGET-B", READER_TOKEN, headers={"X-Human-User": "A" * 500})
    assert "A" * 65 not in caplog.text and "A" * 64 in caplog.text


def test_authorization_code_never_reads_the_claim():
    # The claim parameter is used in exactly one place: the log statement.
    source = inspect.getsource(service.get_stock)
    assert source.count("x_human_user") == 3   # parameter, the None check, the log argument
