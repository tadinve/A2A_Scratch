"""Day 05.5: scoped tokens. The issuer approves scope; the service enforces it.

Two independent checks must BOTH pass before inventory details are read:
    token scope  (what the issuer approved for this token)
    role         (what this identity may ever do)
"""

import pytest
from fastapi.testclient import TestClient

from tests.support import READER_CLIENT, RESTRICTED_CLIENT, get, make_token

from token_issuer import app as issuer_app  # noqa: E402

A, B, C = "inventory.read.class_a", "inventory.read.class_b", "inventory.read.class_c"


@pytest.fixture
def issuer_client():
    return TestClient(issuer_app.app)


def issue(issuer_client, creds, scope):
    return issuer_client.post("/token", headers={"X-Client-ID": creds[0], "X-Client-Secret": creds[1],
                                                 "X-Scope": scope})


# --------------------------------------------------------------------------- #
# The 05.5 acceptance cases, end to end: issuer -> token -> inventory service
# --------------------------------------------------------------------------- #
def test_reader_with_class_b_scope(issuer_client, client, spy):
    token = issue(issuer_client, READER_CLIENT, B).json()["access_token"]
    a = get(client, "WIDGET-A", token)
    assert a.status_code == 403                 # the role allows A, the TOKEN does not
    assert spy.detail_lookup is False
    assert get(client, "WIDGET-B", token).status_code == 200


def test_reader_with_class_a_scope(issuer_client, client, spy):
    token = issue(issuer_client, READER_CLIENT, A).json()["access_token"]
    assert get(client, "WIDGET-A", token).status_code == 200


def test_restricted_asking_for_class_a_is_refused_by_issuer(issuer_client):
    r = issue(issuer_client, RESTRICTED_CLIENT, A)
    assert r.status_code == 403
    assert "access_token" not in r.text         # no token exists to misuse


def test_restricted_with_class_b_scope(issuer_client, client, spy):
    r = issue(issuer_client, RESTRICTED_CLIENT, B)
    assert r.status_code == 200
    assert get(client, "WIDGET-B", r.json()["access_token"]).status_code == 200


# --------------------------------------------------------------------------- #
# The scope grid: one identity, three tokens, three resource classes
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "scope, want",
    [
        (A, {"WIDGET-A": 200, "WIDGET-B": 403, "WIDGET-C": 403}),
        (B, {"WIDGET-A": 403, "WIDGET-B": 200, "WIDGET-C": 403}),
        (C, {"WIDGET-A": 403, "WIDGET-B": 403, "WIDGET-C": 200}),
        (f"{A} {B} {C}", {"WIDGET-A": 200, "WIDGET-B": 200, "WIDGET-C": 200}),
    ],
    ids=["scope-A", "scope-B", "scope-C", "scope-ABC"],
)
def test_reader_scope_grid(client, spy, scope, want):
    token = make_token("inventory-agent", scope=scope)
    got = {sku: get(client, sku, token).status_code for sku in want}
    print(f"{scope:<70} {got}")
    assert got == want


# --------------------------------------------------------------------------- #
# Defence in depth: scope can only NARROW, never exceed the role
# --------------------------------------------------------------------------- #
def test_scope_cannot_exceed_role(client, spy):
    # A misconfigured issuer gives restricted-agent a class A scope: the role still says no.
    token = make_token("restricted-agent", scope=A)
    assert get(client, "WIDGET-A", token).status_code == 403
    assert spy.detail_lookup is False


def test_both_checks_must_pass(client, spy):
    assert get(client, "WIDGET-A", make_token("inventory-agent", scope=A)).status_code == 200   # scope yes, role yes
    assert get(client, "WIDGET-A", make_token("inventory-agent", scope=B)).status_code == 403   # scope no,  role yes
    assert get(client, "WIDGET-A", make_token("restricted-agent", scope=A)).status_code == 403  # scope yes, role no
    assert get(client, "WIDGET-A", make_token("restricted-agent", scope=B)).status_code == 403  # scope no,  role no


# --------------------------------------------------------------------------- #
# Malformed or missing scope
# --------------------------------------------------------------------------- #
def test_token_without_scope_claim_is_401(client, spy):
    r = get(client, "WIDGET-C", make_token(drop=("scope",)))
    assert r.status_code == 401
    assert spy.sqlite_touched is False


@pytest.mark.parametrize("bad", [["inventory.read.class_c"], 42, None], ids=["list", "number", "null"])
def test_non_string_scope_is_401(client, spy, bad):
    r = get(client, "WIDGET-C", make_token(scope=bad))
    assert r.status_code == 401
    assert spy.sqlite_touched is False


@pytest.mark.parametrize("scope", ["", "admin", "inventory.read", "inventory.read.class_*"],
                         ids=["empty", "admin", "prefix", "wildcard"])
def test_scope_that_grants_nothing_is_403(client, spy, scope):
    r = get(client, "WIDGET-C", make_token(scope=scope))
    assert r.status_code == 403
    assert spy.detail_lookup is False


def test_scope_match_is_exact_not_substring(client, spy):
    # "inventory.read.class_a_extra" contains "inventory.read.class_a" but is not it.
    r = get(client, "WIDGET-A", make_token(scope="inventory.read.class_a_extra"))
    assert r.status_code == 403


@pytest.mark.parametrize(
    "spoof",
    [{"X-Scope": A}, {"X-Permissions": A}],
    ids=["X-Scope", "X-Permissions"],
)
def test_caller_headers_cannot_add_scope(client, spy, spoof):
    token = make_token("inventory-agent", scope=B)
    r = get(client, "WIDGET-A", token, headers=spoof)
    assert r.status_code == 403
    assert spy.detail_lookup is False


def test_scope_check_happens_before_detail_lookup(client, spy):
    get(client, "WIDGET-A", make_token(scope=B))
    assert spy.class_lookup is True     # needed to know which scope is required
    assert spy.detail_lookup is False   # protected data never read
