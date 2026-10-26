"""Day 06.09B: verifiable human delegation.

Three independently verifiable facts reach the Inventory Service:
    1. the human is user-001             (delegation sub, from HER verified token)
    2. the calling machine is inventory-agent  (machine JWT, and delegation act.sub)
    3. a trusted authority allowed that machine to do THIS for THAT human  (delegation scope)
"""

import base64
import json
import logging
import time
from dataclasses import replace
from urllib.parse import urlsplit

import jwt
import pytest
from fastapi.testclient import TestClient

from tests.support import (
    ATTACKER_PRIVATE_PEM, DELEGATION_PRIVATE_PEM, IDENTITY_PRIVATE_FILE, READER_CLIENT, get, make_token, service,
)

from delegation_authority import app as authority_app  # noqa: E402
from identity_service import tokens as human_tokens
from identity_service.config import load_config as identity_config
from inventory_agent import app as agent_app
from inventory_agent import tools
from token_issuer import app as issuer_app

A, B, C = "inventory.read.class_a", "inventory.read.class_b", "inventory.read.class_c"


# --------------------------------------------------------------------------- #
# Token builders
# --------------------------------------------------------------------------- #
def human(sub="user-001", **cfg):
    return human_tokens.issue_user_token(replace(identity_config(), **cfg),
                                         human_tokens.load_private_key(IDENTITY_PRIVATE_FILE), sub)


def actor(sub="inventory-agent", scope="delegation.request", aud="a2a-delegation-authority", **kw):
    """A machine JWT minted for the delegation authority (test issuer key-1)."""
    return make_token(sub, scope=scope, aud=aud, **kw)


def delegation(sub="user-001", act="inventory-agent", scope=B, aud="inventory-service",
               key=DELEGATION_PRIVATE_PEM, kid="delegation-key-1", iss="a2a-delegation-authority", ttl=300):
    now = int(time.time())
    return jwt.encode({"iss": iss, "sub": sub, "act": {"sub": act}, "aud": aud, "scope": scope,
                       "iat": now, "exp": now + ttl}, key, algorithm="RS256", headers={"kid": kid})


def edit(token, **changes):
    h, p, s = token.split(".")
    c = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    c.update(changes)
    return ".".join([h, base64.urlsafe_b64encode(json.dumps(c).encode()).rstrip(b"=").decode(), s])


@pytest.fixture
def authority():
    return TestClient(authority_app.app)


def delegate(authority, subject_token, scope=B, actor_token=None):
    headers = {} if actor_token is False else {"Authorization": f"Bearer {actor_token or actor()}"}
    return authority.post("/delegate", headers=headers, json={"subject_token": subject_token, "scope": scope})


# --------------------------------------------------------------------------- #
# Delegation Authority: the token it issues
# --------------------------------------------------------------------------- #
def test_authority_issues_the_proposed_delegation_jwt(authority):
    alice = human()
    r = delegate(authority, alice, B)
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    claims = jwt.decode(r.json()["delegation_token"], options={"verify_signature": False})
    assert claims["iss"] == "a2a-delegation-authority"
    assert claims["sub"] == "user-001"
    assert claims["act"] == {"sub": "inventory-agent"}
    assert claims["aud"] == "inventory-service"
    assert claims["scope"] == B
    assert 0 < claims["exp"] - claims["iat"] <= 300


def test_delegation_never_outlives_the_human_token(authority):
    cfg = identity_config()
    short = human_tokens.issue_user_token(cfg, human_tokens.load_private_key(IDENTITY_PRIVATE_FILE), "user-001",
                                          now=int(time.time()) - 240)          # 60 s left
    claims = jwt.decode(delegate(authority, short).json()["delegation_token"], options={"verify_signature": False})
    assert claims["exp"] == jwt.decode(short, options={"verify_signature": False})["exp"]


# --------------------------------------------------------------------------- #
# Delegation Authority: check 1, the actor
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("label, token, want", [
    ("no actor token", False, 401),
    ("garbage actor", "not-a-jwt", 401),
    ("actor token meant for inventory-service", "AUD", 401),
    ("actor token signed by attacker", "ATTACK", 401),
    ("actor lacks delegation.request", "NOSCOPE", 403),
])
def test_actor_must_prove_itself_for_this_authority(authority, label, token, want):
    built = {"AUD": actor(aud="inventory-service"), "ATTACK": actor(key=ATTACKER_PRIVATE_PEM),
             "NOSCOPE": actor(scope=B)}
    r = delegate(authority, human(), actor_token=built.get(token, token))
    assert r.status_code == want and "delegation_token" not in r.text


# --------------------------------------------------------------------------- #
# Delegation Authority: check 2, the subject (the human)
# --------------------------------------------------------------------------- #
def test_the_authority_will_not_sign_an_identity_the_agent_merely_names(authority):
    # Experiment A's lie, retried here: the agent asks for "admin" with no admin token.
    r = delegate(authority, "admin")
    assert r.status_code == 401
    r = delegate(authority, edit(human(), sub="admin"))       # Alice's token, edited
    assert r.status_code == 401


@pytest.mark.parametrize("label, maker", [
    ("expired human token", lambda: human_tokens.issue_user_token(identity_config(), human_tokens.load_private_key(IDENTITY_PRIVATE_FILE), "user-001", now=int(time.time()) - 600)),
    ("human token from another issuer", lambda: human(issuer="evil-issuer")),
    ("human token issued to a different agent", lambda: human(audience="some-other-agent")),
    ("a machine token posing as the human", lambda: make_token("inventory-agent")),
])
def test_subject_token_must_be_a_valid_human_token_for_this_actor(authority, label, maker):
    assert delegate(authority, maker()).status_code == 401


# --------------------------------------------------------------------------- #
# Delegation Authority: checks 3-4, policy and scope intersection
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("who, scope, want", [
    ("user-001", B, 200),                 # Alice may read B
    ("user-001", f"{A} {B}", 200),        # ...and A
    ("user-001", C, 403),                 # but NOT C: the agent could, Alice can't -> no
    ("user-002", B, 200),                 # Julie may read B
    ("user-002", A, 403),                 # but not A
    ("user-002", f"{B} {A}", 403),        # all or nothing
    ("user-999", B, 403),                 # no delegation relationship
])
def test_scope_is_the_intersection_of_human_and_actor(authority, who, scope, want):
    r = delegate(authority, human(who), scope)
    assert r.status_code == want


def test_an_actor_outside_policy_cannot_act_for_anyone(authority):
    r = delegate(authority, human(audience="restricted-agent"), B,
                 actor_token=actor("restricted-agent"))
    assert r.status_code == 403


# --------------------------------------------------------------------------- #
# Inventory Service: verifying the delegation
# --------------------------------------------------------------------------- #
MACHINE_B = make_token("inventory-agent", scope=f"{A} {B} {C}")


def test_service_accepts_machine_plus_valid_delegation(client, spy, caplog):
    with caplog.at_level(logging.INFO):
        r = get(client, "WIDGET-B", MACHINE_B, headers={"X-Delegation-Token": delegation()})
    assert r.status_code == 200
    assert "AUTHZ OK identity=inventory-agent on_behalf_of=user-001 (verified delegation)" in caplog.text


def test_delegated_scope_narrows_the_machine(client, spy):
    # The machine could read A, but Alice's grant is only B.
    r = get(client, "WIDGET-A", MACHINE_B, headers={"X-Delegation-Token": delegation(scope=B)})
    assert r.status_code == 403 and spy.detail_lookup is False


def test_delegation_cannot_widen_the_machine(client, spy):
    machine_b_only = make_token("inventory-agent", scope=B)
    r = get(client, "WIDGET-A", machine_b_only, headers={"X-Delegation-Token": delegation(scope=f"{A} {B}")})
    assert r.status_code == 403 and spy.detail_lookup is False


@pytest.mark.parametrize("label, token", [
    ("signed by attacker", lambda: delegation(key=ATTACKER_PRIVATE_PEM)),
    ("unknown kid", lambda: delegation(kid="delegation-key-9")),
    ("wrong issuer", lambda: delegation(iss="evil-authority")),
    ("wrong audience", lambda: delegation(aud="billing-service")),
    ("expired", lambda: delegation(ttl=-10)),
    ("edited sub", lambda: edit(delegation(), sub="admin")),
    ("edited scope", lambda: edit(delegation(scope=B), scope=f"{A} {B}")),
    ("garbage", lambda: "not-a-jwt"),
])
def test_bad_delegation_is_401_and_touches_nothing(client, spy, label, token):
    r = get(client, "WIDGET-B", MACHINE_B, headers={"X-Delegation-Token": token()})
    assert r.status_code == 401 and spy.sqlite_touched is False


def test_delegation_for_another_actor_is_401(client, spy):
    # A real grant for inventory-agent, presented by restricted-agent's machine token.
    restricted = make_token("restricted-agent", scope=f"{B} {C}")
    r = get(client, "WIDGET-B", restricted, headers={"X-Delegation-Token": delegation(act="inventory-agent")})
    assert r.status_code == 401 and spy.sqlite_touched is False


def test_delegation_alone_is_not_a_machine_credential(client, spy):
    r = client.get("/stock/WIDGET-B", headers={"Authorization": f"Bearer {delegation()}"})
    assert r.status_code == 401


def test_machine_only_requests_keep_their_day05_behaviour(client, spy):
    assert get(client, "WIDGET-A", MACHINE_B).status_code == 200


def test_bare_x_human_user_still_grants_nothing(client, spy):
    restricted = make_token("restricted-agent", scope=f"{B} {C}")
    assert get(client, "WIDGET-A", restricted, headers={"X-Human-User": "admin"}).status_code == 403


# --------------------------------------------------------------------------- #
# End to end: Alice -> agent -> issuer + authority -> service
# --------------------------------------------------------------------------- #
@pytest.fixture
def wired(monkeypatch, spy):
    issuer_http, authority_http, service_http = (TestClient(issuer_app.app), TestClient(authority_app.app),
                                                 TestClient(service.app))
    calls = {"delegate": 0, "service": []}

    def post(url, headers=None, timeout=None, json=None):
        if urlsplit(url).path == "/delegate":
            calls["delegate"] += 1
            return authority_http.post("/delegate", headers=headers, json=json)
        return issuer_http.post("/token", headers=headers)

    def get_(url, headers=None, timeout=None):
        calls["service"].append(dict(headers or {}))
        return service_http.get(urlsplit(url).path, headers=headers)

    monkeypatch.setattr(tools.httpx, "post", post)
    monkeypatch.setattr(tools.httpx, "get", get_)
    for k, v in {"INVENTORY_CLIENT_ID": READER_CLIENT[0], "INVENTORY_CLIENT_SECRET": READER_CLIENT[1],
                 "INVENTORY_ISSUER_URL": "http://issuer", "INVENTORY_SERVICE_URL": "http://inventory",
                 "INVENTORY_DELEGATION_URL": "http://authority", "INVENTORY_REQUESTED_SCOPE": B}.items():
        monkeypatch.setenv(k, v)
    tools._clear_cache()
    calls["spy"] = spy
    yield calls
    tools._clear_cache()


def ask(token, sku):
    return TestClient(agent_app.app).get(f"/agent/stock/{sku}", headers={"Authorization": f"Bearer {token}"})


def test_e2e_alice_reads_widget_b_on_her_own_verified_behalf(wired, caplog):
    with caplog.at_level(logging.INFO):
        r = ask(human("user-001"), "WIDGET-B")
    assert r.status_code == 200 and r.json()["result"]["sku"] == "WIDGET-B"
    (headers,) = wired["service"]
    assert set(headers) == {"Authorization", "Accept", "X-Delegation-Token"}
    claims = jwt.decode(headers["X-Delegation-Token"], options={"verify_signature": False})
    assert (claims["sub"], claims["act"]["sub"], claims["aud"]) == ("user-001", "inventory-agent", "inventory-service")
    assert "on_behalf_of=user-001 (verified delegation)" in caplog.text
    assert "DELEGATION ISSUED human=user-001 actor=inventory-agent" in caplog.text


def test_e2e_alice_with_class_b_grant_cannot_read_class_a(wired):
    r = ask(human("user-001"), "WIDGET-A")
    assert r.status_code == 403 and wired["spy"].detail_lookup is False


def test_e2e_julie_cannot_get_a_class_a_grant(wired, monkeypatch):
    monkeypatch.setenv("INVENTORY_REQUESTED_SCOPE", A)
    r = ask(human("user-002"), "WIDGET-A")
    assert r.status_code == 403
    assert wired["service"] == []                         # refused at the authority: no service call


def test_e2e_invalid_human_never_reaches_authority_or_service(wired):
    r = ask("not-a-jwt", "WIDGET-B")
    assert r.status_code == 401
    assert wired["delegate"] == 0 and wired["service"] == []
