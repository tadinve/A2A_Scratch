"""Days 05.3-05.6: the agent's token lifecycle (fake network, fake clock).

05.6 acceptance: reuse, proactive renewal, one bounded retry on 401, no retry
on 403, one cache entry per scope, and issuer outages vs. cached tokens.
"""

import inspect
import logging

import httpx
import pytest

from inventory_agent import tools

A, B, C = "inventory.read.class_a", "inventory.read.class_b", "inventory.read.class_c"


class FakeHTTP:
    """Plays the issuer (POST /token) and the inventory service (GET /stock)."""

    def __init__(self):
        self.posts, self.gets = [], []
        self.issuer_status = 200
        self.issuer_down = False
        self.expires_in = 300
        self.stock_statuses: list[int] = []   # queued statuses; empty -> 200
        self.issued = 0

    def post(self, url, headers=None, timeout=None):
        if self.issuer_down:
            raise httpx.ConnectError("issuer down")
        self.posts.append((url, dict(headers or {})))
        if self.issuer_status != 200:
            return httpx.Response(self.issuer_status, json={"status": "x", "message": "x"})
        self.issued += 1
        return httpx.Response(200, json={"access_token": f"jwt-{self.issued}", "token_type": "Bearer",
                                         "expires_in": self.expires_in})

    def get(self, url, headers=None, timeout=None):
        self.gets.append((url, dict(headers or {})))
        status = self.stock_statuses.pop(0) if self.stock_statuses else 200
        if status != 200:
            return httpx.Response(status, json={"status": "x", "message": "x"})
        return httpx.Response(200, json={"status": "found", "sku": "WIDGET-A", "name": "Standard Widget", "quantity": 30})

    @property
    def tokens_sent(self):
        return [h["Authorization"].removeprefix("Bearer ") for _, h in self.gets]


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


@pytest.fixture
def clock(monkeypatch):
    c = Clock()
    monkeypatch.setattr(tools, "_now", c)
    return c


@pytest.fixture
def fake(monkeypatch, clock):
    f = FakeHTTP()
    monkeypatch.setattr(tools.httpx, "post", f.post)
    monkeypatch.setattr(tools.httpx, "get", f.get)
    monkeypatch.setenv("INVENTORY_CLIENT_ID", "inventory-agent")
    monkeypatch.setenv("INVENTORY_CLIENT_SECRET", "agent-secret")
    monkeypatch.setenv("INVENTORY_ISSUER_URL", "http://issuer.test")
    monkeypatch.setenv("INVENTORY_SERVICE_URL", "http://inventory.test")
    monkeypatch.setenv("INVENTORY_REQUESTED_SCOPE", B)
    tools._clear_cache()
    yield f
    tools._clear_cache()


# --------------------------------------------------------------------------- #
# 05.6 acceptance tests
# --------------------------------------------------------------------------- #
def test_1_first_call_gets_a_token_then_calls_service(fake):
    assert tools.get_stock("WIDGET-A")["status"] == "found"
    assert len(fake.posts) == 1 and len(fake.gets) == 1


def test_2_second_call_before_expiry_reuses_token(fake, clock):
    tools.get_stock("WIDGET-A")
    clock.advance(60)
    tools.get_stock("WIDGET-A")
    assert len(fake.posts) == 1                       # issuer NOT called again
    assert fake.tokens_sent == ["jwt-1", "jwt-1"]     # same token reused


def test_10_calls_cost_1_issuer_call(fake, clock):
    for _ in range(10):
        tools.get_stock("WIDGET-A")
        clock.advance(10)
    assert len(fake.posts) == 1 and len(fake.gets) == 10


def test_3_token_near_expiry_is_renewed_proactively(fake, clock):
    tools.get_stock("WIDGET-A")
    clock.advance(300 - 30)                          # exactly at the 30 s margin
    tools.get_stock("WIDGET-A")
    assert len(fake.posts) == 2
    assert fake.tokens_sent == ["jwt-1", "jwt-2"]


def test_3b_just_outside_the_margin_still_reuses(fake, clock):
    tools.get_stock("WIDGET-A")
    clock.advance(300 - 31)
    tools.get_stock("WIDGET-A")
    assert len(fake.posts) == 1


def test_4_cached_token_rejected_with_401_renews_and_retries_once(fake, clock):
    tools.get_stock("WIDGET-A")                      # caches jwt-1
    fake.stock_statuses = [401]                      # service rejects jwt-1 next time
    assert tools.get_stock("WIDGET-A")["status"] == "found"
    assert len(fake.posts) == 2                      # renewed
    assert fake.tokens_sent == ["jwt-1", "jwt-1", "jwt-2"]   # retried once with the new token


def test_4b_retry_is_bounded_to_one(fake, clock):
    tools.get_stock("WIDGET-A")
    fake.stock_statuses = [401, 401, 401, 401]
    assert tools.get_stock("WIDGET-A")["status"] == "unauthenticated"
    assert len(fake.gets) == 3                       # 1 initial + 1 failed + 1 retry, then stop
    assert len(fake.posts) == 2
    assert tools._cache == {}                        # the rejected token is not kept


def test_4c_fresh_token_rejected_is_not_retried(fake):
    fake.stock_statuses = [401]                      # the very first, freshly minted token
    assert tools.get_stock("WIDGET-A")["status"] == "unauthenticated"
    assert len(fake.posts) == 1 and len(fake.gets) == 1  # renewing can't help a token just issued


def test_5_service_403_is_not_retried_and_does_not_renew(fake, clock):
    tools.get_stock("WIDGET-A")
    fake.stock_statuses = [403]
    assert tools.get_stock("WIDGET-A")["status"] == "forbidden"
    assert len(fake.posts) == 1                      # issuer NOT called again
    assert len(fake.gets) == 2                       # no retry
    tools.get_stock("WIDGET-A")
    assert len(fake.posts) == 1                      # the token is still fine for what it allows


def test_6_cached_class_b_token_is_not_reused_for_class_a(fake, monkeypatch):
    tools.get_stock("WIDGET-B")                      # scope B -> jwt-1
    monkeypatch.setenv("INVENTORY_REQUESTED_SCOPE", A)
    tools.get_stock("WIDGET-A")                      # scope A -> must be a NEW token
    assert [h["X-Scope"] for _, h in fake.posts] == [B, A]
    assert fake.tokens_sent == ["jwt-1", "jwt-2"]
    monkeypatch.setenv("INVENTORY_REQUESTED_SCOPE", B)
    tools.get_stock("WIDGET-B")                      # back to B -> reuse jwt-1
    assert fake.tokens_sent[-1] == "jwt-1" and len(fake.posts) == 2


def test_6b_scope_order_does_not_split_the_cache(fake, monkeypatch):
    monkeypatch.setenv("INVENTORY_REQUESTED_SCOPE", f"{C} {B}")
    tools.get_stock("WIDGET-B")
    monkeypatch.setenv("INVENTORY_REQUESTED_SCOPE", f"{B}  {C}")
    tools.get_stock("WIDGET-B")
    assert len(fake.posts) == 1
    assert fake.posts[0][1]["X-Scope"] == f"{B} {C}"   # sent in canonical order


def test_6c_changing_credentials_does_not_reuse_token(fake, monkeypatch):
    tools.get_stock("WIDGET-A")
    monkeypatch.setenv("INVENTORY_CLIENT_SECRET", "different-secret")
    tools.get_stock("WIDGET-A")
    monkeypatch.setenv("INVENTORY_CLIENT_ID", "restricted-agent")
    tools.get_stock("WIDGET-A")
    assert len(fake.posts) == 3


def test_7_issuer_down_but_cached_token_still_works(fake, clock):
    tools.get_stock("WIDGET-A")
    fake.issuer_down = True
    clock.advance(120)
    assert tools.get_stock("WIDGET-A")["status"] == "found"   # issuer outage != service outage


def test_8_issuer_down_and_token_expired_fails_closed(fake, clock):
    tools.get_stock("WIDGET-A")
    fake.issuer_down = True
    clock.advance(301)
    assert tools.get_stock("WIDGET-A")["status"] == "error"
    assert len(fake.gets) == 1                       # the expired token was never sent


def test_8b_issuer_down_inside_margin_fails_closed(fake, clock):
    tools.get_stock("WIDGET-A")
    fake.issuer_down = True
    clock.advance(280)                               # 20 s left: inside the margin
    assert tools.get_stock("WIDGET-A")["status"] == "error"


# --------------------------------------------------------------------------- #
# Cache hygiene
# --------------------------------------------------------------------------- #
def test_issuer_without_expires_in_is_used_once_not_cached(fake):
    fake.expires_in = 0
    tools.get_stock("WIDGET-A")
    tools.get_stock("WIDGET-A")
    assert len(fake.posts) == 2
    assert tools._cache == {}


def test_cache_key_never_contains_the_secret(fake):
    tools.get_stock("WIDGET-A")
    assert all("agent-secret" not in part for key in tools._cache for part in key)


def test_lifetime_is_measured_from_before_the_request(fake, clock, monkeypatch):
    real_post = fake.post

    def slow_post(*a, **k):
        clock.advance(5)                             # the issuer takes 5 s to answer
        return real_post(*a, **k)
    monkeypatch.setattr(tools.httpx, "post", slow_post)
    tools.get_stock("WIDGET-A")
    (_, expires_at), = tools._cache.values()
    assert expires_at == 1000.0 + 300                # counted from before the request


# --------------------------------------------------------------------------- #
# Carried over from 05.3-05.5
# --------------------------------------------------------------------------- #
def test_two_interactions_issuer_then_service(fake):
    tools.get_stock("WIDGET-A")
    (post_url, post_headers), = fake.posts
    assert post_url == "http://issuer.test/token"
    assert post_headers == {"X-Client-ID": "inventory-agent", "X-Client-Secret": "agent-secret", "X-Scope": B}
    (get_url, get_headers), = fake.gets
    assert get_url == "http://inventory.test/stock/WIDGET-A"
    assert get_headers["Authorization"] == "Bearer jwt-1"
    assert "X-Client-Secret" not in get_headers      # the client secret goes only to the issuer


def test_agent_never_sends_a_sub(fake):
    tools.get_stock("WIDGET-A")
    url, headers = fake.posts[0]
    assert "sub" not in url and not any("sub" in k.lower() for k in headers)


def test_scope_comes_from_config_not_the_model(fake):
    assert list(inspect.signature(tools.get_stock).parameters) == ["sku"]


def test_no_scope_configured_fails_closed(fake, monkeypatch):
    monkeypatch.delenv("INVENTORY_REQUESTED_SCOPE")
    assert tools.get_stock("WIDGET-A")["status"] == "error"
    assert fake.posts == [] and fake.gets == []


def test_no_credentials_configured(fake, monkeypatch):
    monkeypatch.delenv("INVENTORY_CLIENT_SECRET")
    assert tools.get_stock("WIDGET-A")["status"] == "unauthenticated"
    assert fake.posts == [] and fake.gets == []


def test_issuer_rejects_credentials(fake):
    fake.issuer_status = 401
    assert tools.get_stock("WIDGET-A")["status"] == "unauthenticated"
    assert fake.gets == []


def test_issuer_refusing_scope_is_forbidden(fake):
    fake.issuer_status = 403
    assert tools.get_stock("WIDGET-A")["status"] == "forbidden"
    assert fake.gets == []


def test_issuer_unreachable_with_empty_cache_is_error(fake):
    fake.issuer_down = True
    assert tools.get_stock("WIDGET-A")["status"] == "error"
    assert fake.gets == []


def test_flow_logs_never_contain_secret_or_token(fake, caplog, clock):
    with caplog.at_level(logging.INFO, logger="inventory_agent.flow"):
        tools.get_stock("WIDGET-A")
        clock.advance(10)
        tools.get_stock("WIDGET-A")
    assert "agent -> issuer" in caplog.text and "reusing cached token" in caplog.text
    assert "agent-secret" not in caplog.text
    assert "jwt-1" not in caplog.text
