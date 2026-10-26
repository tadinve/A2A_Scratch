"""Day 06.01: /whoami echoes a CLAIMED identity. Nothing proves it."""

import pytest

from tests.support import get


@pytest.mark.parametrize("user", ["alice", "bob", "admin"])
def test_whoami_echoes_any_claimed_user(client, spy, user):
    r = client.get("/whoami", params={"user": user})
    assert r.status_code == 200
    assert r.json() == {"claimed_user": user, "authenticated": False}
    assert spy.sqlite_touched is False          # never touches the inventory database


def test_whoami_needs_no_credentials_at_all(client, spy):
    r = client.get("/whoami", params={"user": "admin"})   # no Authorization header
    assert r.status_code == 200


def test_claiming_admin_grants_nothing_on_the_protected_endpoint(client, spy):
    # The claim on /whoami is just text; /stock still demands a verified JWT.
    r = get(client, "WIDGET-A", None, headers={"X-User": "admin"})
    assert r.status_code == 401
    assert spy.sqlite_touched is False


def test_missing_user_is_a_validation_error(client, spy):
    assert client.get("/whoami").status_code == 422
