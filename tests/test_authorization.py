"""Day 04: authentication (401) vs authorization (403), now resource-aware.

Flow under test:
    authenticate (401) -> classify SKU (404) -> authorize for class (403) -> details (200)

Both repository functions are replaced by spies, so each test asserts:
- class_lookup:   was the classification (metadata) read?
- detail_lookup:  were the protected stock details read?   (the old "sqlite_lookup")
"""

import inspect

import pytest
from fastapi.testclient import TestClient

from inventory_service import app as service
from inventory_service import authz
from inventory_service import repository
from tests.conftest import READER_KEY, RESTRICTED_KEY

CLASSES = {"WIDGET-A": "A", "WIDGET-B": "B", "WIDGET-C": "C"}
DETAILS = {
    "WIDGET-A": {"status": "found", "sku": "WIDGET-A", "name": "Standard Widget", "quantity": 30},
    "WIDGET-B": {"status": "found", "sku": "WIDGET-B", "name": "Heavy-duty Widget", "quantity": 12},
    "WIDGET-C": {"status": "found", "sku": "WIDGET-C", "name": "Mini Widget", "quantity": 0},
}


class RepoSpy:
    def __init__(self):
        self.class_calls: list[str] = []
        self.detail_calls: list[str] = []
        self.classes = dict(CLASSES)
        self.class_error = False

    def get_classification(self, sku: str) -> dict:
        self.class_calls.append(sku)
        if self.class_error:
            return {"status": "error", "message": "Inventory is temporarily unavailable."}
        s = sku.strip().upper()
        if s not in self.classes:
            return {"status": "not_found", "sku": s}
        return {"status": "found", "sku": s, "inventory_class": self.classes[s]}

    def lookup_sku(self, sku: str) -> dict:
        self.detail_calls.append(sku)
        s = sku.strip().upper()
        return DETAILS.get(s, {"status": "not_found", "sku": s})

    @property
    def class_lookup(self) -> bool:
        return bool(self.class_calls)

    @property
    def detail_lookup(self) -> bool:
        return bool(self.detail_calls)


@pytest.fixture
def spy(monkeypatch):
    s = RepoSpy()
    # app.py imported these names directly, so patch the names app uses.
    monkeypatch.setattr(service, "get_classification", s.get_classification)
    monkeypatch.setattr(service, "lookup_sku", s.lookup_sku)
    return s


@pytest.fixture
def client():
    return TestClient(service.app)


def get(client, sku="WIDGET-A", key=None, **extra_headers):
    headers = dict(extra_headers)
    if key is not None:
        headers["X-API-Key"] = key
    return client.get(f"/stock/{sku}", headers=headers)


# --------------------------------------------------------------------------- #
# The policy grid: same caller, different resource -> different answer
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "who, key, sku, want_status, want_body, want_class, want_detail",
    [
        ("privileged", READER_KEY,     "WIDGET-A", 200, "found",           True,  True),
        ("privileged", READER_KEY,     "WIDGET-B", 200, "found",           True,  True),
        ("privileged", READER_KEY,     "WIDGET-C", 200, "found",           True,  True),
        ("restricted", RESTRICTED_KEY, "WIDGET-A", 403, "forbidden",       True,  False),
        ("restricted", RESTRICTED_KEY, "WIDGET-B", 200, "found",           True,  True),
        ("restricted", RESTRICTED_KEY, "WIDGET-C", 200, "found",           True,  True),
        ("invalid",    "not-a-key",    "WIDGET-A", 401, "unauthenticated", False, False),
        ("invalid",    "not-a-key",    "WIDGET-B", 401, "unauthenticated", False, False),
        ("invalid",    "not-a-key",    "WIDGET-C", 401, "unauthenticated", False, False),
    ],
)
def test_policy_grid(client, spy, who, key, sku, want_status, want_body, want_class, want_detail):
    r = get(client, sku, key)
    print(f"{who:<10} {sku}  HTTP {r.status_code}  class_lookup={spy.class_lookup}  detail_lookup={spy.detail_lookup}")
    assert r.status_code == want_status
    assert r.json()["status"] == want_body
    assert spy.class_lookup is want_class
    assert spy.detail_lookup is want_detail
    if want_status == 200:
        assert r.json() == DETAILS[sku]


# --------------------------------------------------------------------------- #
# The original seven scenarios, updated for class-based authorization
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "case, sku, key, extra, want_status, want_body, want_detail",
    [
        ("1 reader, existing SKU",      "WIDGET-A", READER_KEY,     {},                             200, "found",           True),
        ("2 missing key",               "WIDGET-A", None,           {},                             401, "unauthenticated", False),
        ("3 invalid key",               "WIDGET-A", "not-a-key",    {},                             401, "unauthenticated", False),
        ("4 restricted, class A",       "WIDGET-A", RESTRICTED_KEY, {},                             403, "forbidden",       False),
        ("5 reader, unknown SKU",       "WIDGET-X", READER_KEY,     {},                             404, "not_found",       False),
        ("6 restricted, unknown SKU",   "WIDGET-X", RESTRICTED_KEY, {},                             404, "not_found",       False),
        ("7 restricted + X-Role spoof", "WIDGET-A", RESTRICTED_KEY, {"X-Role": "inventory_reader"}, 403, "forbidden",       False),
    ],
)
def test_original_matrix(client, spy, case, sku, key, extra, want_status, want_body, want_detail):
    r = get(client, sku, key, **extra)
    print(f"{case:<28} HTTP {r.status_code}  detail_lookup={spy.detail_lookup}")
    assert r.status_code == want_status
    assert r.json()["status"] == want_body
    assert spy.detail_lookup is want_detail


def test_denied_response_contains_no_protected_details(client, spy):
    r = get(client, "WIDGET-A", RESTRICTED_KEY)
    assert r.status_code == 403
    assert set(r.json()) == {"status", "message"}
    for leaked in ("Standard Widget", "30", "quantity", "inventory_class"):
        assert leaked not in r.text


# --------------------------------------------------------------------------- #
# Error shape and 401/403 distinction
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("key", [None, "not-a-key", RESTRICTED_KEY])
def test_error_body_shape_and_no_secret_leak(client, spy, key):
    r = get(client, "WIDGET-A", key)
    assert set(r.json()) == {"status", "message"}
    for secret in (READER_KEY, RESTRICTED_KEY, "not-a-key"):
        assert secret not in r.text


def test_401_and_403_are_distinct(client, spy):
    unauth = get(client, key="not-a-key")
    forbid = get(client, key=RESTRICTED_KEY)
    assert (unauth.status_code, forbid.status_code) == (401, 403)
    assert unauth.json()["status"] != forbid.json()["status"]
    assert unauth.headers.get("www-authenticate") == "ApiKey"
    assert "www-authenticate" not in forbid.headers


def test_framework_errors_use_same_shape(client, spy):
    r = client.post("/stock/WIDGET-A", headers={"X-API-Key": READER_KEY})
    assert r.status_code == 405
    assert r.json()["status"] == "method_not_allowed"
    assert spy.class_lookup is False and spy.detail_lookup is False


# --------------------------------------------------------------------------- #
# Deny by default and fail closed
# --------------------------------------------------------------------------- #
def test_unexpected_class_is_denied_even_for_privileged(client, spy):
    spy.classes["WIDGET-A"] = "D"  # a class no role grants
    r = get(client, "WIDGET-A", READER_KEY)
    assert r.status_code == 403
    assert spy.detail_lookup is False


def test_classification_failure_fails_closed(client, spy):
    spy.class_error = True
    r = get(client, "WIDGET-A", READER_KEY)
    assert r.status_code == 503
    assert spy.detail_lookup is False


def test_unknown_role_is_denied(client, spy, monkeypatch):
    monkeypatch.setitem(authz.IDENTITY_ROLES, "inventory-agent", "role-nobody-defined")
    r = get(client, "WIDGET-C", READER_KEY)
    assert r.status_code == 403
    assert spy.detail_lookup is False


def test_identity_without_role_is_denied(client, spy, monkeypatch):
    monkeypatch.delitem(authz.IDENTITY_ROLES, "inventory-agent")
    r = get(client, "WIDGET-C", READER_KEY)
    assert r.status_code == 403
    assert spy.detail_lookup is False


# --------------------------------------------------------------------------- #
# Separation of responsibilities
# --------------------------------------------------------------------------- #
def test_class_permission_comes_from_role_not_identity_name(client, spy, monkeypatch):
    # Grant class A to the 'restricted' role: the same restricted key now reads WIDGET-A.
    monkeypatch.setitem(
        authz.ROLE_PERMISSIONS, "restricted",
        authz.ROLE_PERMISSIONS["restricted"] | {"inventory.read.class_a"},
    )
    r = get(client, "WIDGET-A", RESTRICTED_KEY)
    assert r.status_code == 200
    assert len(spy.detail_calls) == 1


def test_class_comes_from_data_not_sku_name(client, spy):
    # Reclassify WIDGET-C as A in the "database": restricted is now denied.
    spy.classes["WIDGET-C"] = "A"
    assert get(client, "WIDGET-C", RESTRICTED_KEY).status_code == 403
    # And WIDGET-A reclassified as C becomes readable.
    spy.classes["WIDGET-A"] = "C"
    assert get(client, "WIDGET-A", RESTRICTED_KEY).status_code == 200


@pytest.mark.parametrize(
    "spoof",
    [
        {"X-Role": "inventory_reader"},
        {"X-Identity": "inventory-agent"},
        {"X-Permissions": "inventory.read.class_a"},
        {"X-Inventory-Class": "C"},
    ],
)
def test_caller_headers_cannot_change_identity_role_or_class(client, spy, spoof):
    r = get(client, "WIDGET-A", RESTRICTED_KEY, **spoof)
    assert r.status_code == 403
    assert spy.detail_lookup is False


def test_repository_knows_nothing_about_auth():
    for fn in (repository.lookup_sku, repository.get_classification):
        assert list(inspect.signature(fn).parameters) == ["sku"]
    source = inspect.getsource(repository)
    for word in ("api_key", "X-API-Key", "role", "permission", "authz", "authenticate"):
        assert word not in source
