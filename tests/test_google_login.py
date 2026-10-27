"""Days 07-08: Google sign-in for Alice, against a FAKE Google and in-memory stores.

FakeGoogle stands in for discovery, the token endpoint and the JWKS endpoint
through an httpx MockTransport, signing ID tokens with a throwaway test key.
Real Google keys are never test fixtures, and nothing here touches the network.
"""

import base64
import hashlib
import logging
import os
import secrets
import subprocess
import sys
import threading
import time
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from fastapi.testclient import TestClient

from tests.support import IDENTITY_PRIVATE_FILE, IDENTITY_PUBLIC_PEM

from identity_service import app as identity_app  # noqa: E402  (after support sets the config)
from identity_service import google_login
from identity_service.config import load_config
from identity_service.datastore import StoreUnavailable
from identity_service.external_identities import MemoryLinkStore
from identity_service.google_oidc import (
    CANONICAL_ISSUER, GOOGLE_DISCOVERY_URL, GoogleOIDC, GoogleSettings, load_google_settings,
)
from identity_service.oauth_transactions import MemoryTransactionStore, TransactionStoreFull
from identity_service.tokens import load_private_key
from identity_service.users import MemoryUserDirectory
from inventory_agent import app as agent_app
from tests.test_delegation import ask, wired  # noqa: F401  (wired is a fixture)

CLIENT_ID = "test-client.apps.googleusercontent.com"
CLIENT_SECRET = "test-google-client-secret-value"
REDIRECT_URI = "http://localhost:8002/auth/google/callback"
SETTINGS = GoogleSettings(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI)

ALICE_SUB, BOB_SUB = "110248495921238986420", "220000000000000000002"
ALICE_EMAIL = "alice.persona@example.com"
AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"
PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _rsa():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


class FakeGoogle:
    """Just enough of Google's OIDC provider to exercise our side of the protocol."""

    def __init__(self):
        self.key, self.kid = _rsa(), "google-test-1"
        self.codes: dict[str, dict] = {}
        self.down: set[str] = set()            # "discovery" | "token" | "jwks"
        self.token_calls = 0

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    def _handle(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url).split("?", 1)[0]
        for name, target in (("discovery", GOOGLE_DISCOVERY_URL), ("token", TOKEN_URL), ("jwks", JWKS_URL)):
            if url == target and name in self.down:
                raise httpx.ConnectTimeout("simulated outage", request=request)
        if url == GOOGLE_DISCOVERY_URL:
            return httpx.Response(200, json={
                "issuer": CANONICAL_ISSUER, "authorization_endpoint": AUTH_URL, "token_endpoint": TOKEN_URL,
                "jwks_uri": JWKS_URL, "id_token_signing_alg_values_supported": ["RS256"],
                "code_challenge_methods_supported": ["plain", "S256"]})
        if url == JWKS_URL:
            jwk = jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key(), as_dict=True)
            return httpx.Response(200, json={"keys": [{**jwk, "kid": self.kid, "use": "sig", "alg": "RS256"}]})
        if url == TOKEN_URL:
            return self._token(request)
        return httpx.Response(404)

    def _token(self, request: httpx.Request) -> httpx.Response:
        self.token_calls += 1
        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        user, _, pw = base64.b64decode(request.headers["authorization"].split()[1]).decode().partition(":")
        if (user, pw) != (CLIENT_ID, CLIENT_SECRET):
            return httpx.Response(401, json={"error": "invalid_client"})
        grant = self.codes.get(form.get("code"))
        if grant is None or grant["used"] or form.get("redirect_uri") != grant["redirect_uri"]:
            return httpx.Response(400, json={"error": "invalid_grant"})
        grant["used"] = True                                   # single-use, like Google
        challenge = base64.urlsafe_b64encode(hashlib.sha256(form["code_verifier"].encode()).digest())
        if challenge.rstrip(b"=").decode() != grant["challenge"]:
            return httpx.Response(400, json={"error": "invalid_grant"})
        return httpx.Response(200, json={"access_token": "ya29.fake-google-access-token", "expires_in": 3599,
                                         "token_type": "Bearer", "scope": "openid email",
                                         "id_token": self.id_token(grant["nonce"], **grant["claims"])})

    def id_token(self, request_nonce, sub=ALICE_SUB, *, key=None, kid=None, drop=(), **overrides) -> str:
        now = int(time.time())
        claims = {"iss": CANONICAL_ISSUER, "azp": CLIENT_ID, "aud": CLIENT_ID, "sub": sub, "email": ALICE_EMAIL,
                  "email_verified": True, "iat": now, "exp": now + 3600, "nonce": request_nonce}
        claims.update({k: v(now) if callable(v) else v for k, v in overrides.items()})   # v(now): relative times
        for name in drop:
            claims.pop(name, None)
        return jwt.encode(claims, key or self.key, algorithm="RS256", headers={"kid": kid or self.kid})

    def approve(self, location: str, sub=ALICE_SUB, **claims) -> str:
        """Alice picks an account and consents; return the callback URL Google redirects to."""
        q = {k: v[0] for k, v in parse_qs(urlsplit(location).query).items()}
        code = secrets.token_urlsafe(16)
        self.codes[code] = {"challenge": q["code_challenge"], "nonce": q["nonce"], "used": False,
                            "redirect_uri": q["redirect_uri"], "claims": {"sub": sub, **claims}}
        return callback(code=code, state=q["state"])


def callback(**params) -> str:
    return "/auth/google/callback?" + urlencode(params)


@pytest.fixture
def directory():
    return MemoryUserDirectory({"user-001": True, "user-002": True})


@pytest.fixture
def links():
    store = MemoryLinkStore()
    store.link(CANONICAL_ISSUER, ALICE_SUB, "user-001")       # only Alice is enrolled
    return store


@pytest.fixture
def google():
    return FakeGoogle()


@pytest.fixture
def store():
    return MemoryTransactionStore()


@pytest.fixture
def idp(monkeypatch, directory, links, google, store):
    login = google_login.GoogleLogin(load_config(), load_private_key(IDENTITY_PRIVATE_FILE),
                                     GoogleOIDC(SETTINGS, transport=google.transport()),
                                     users=directory, links=links, store=store)
    monkeypatch.setattr(identity_app.app.state, "google_login", login)
    return TestClient(identity_app.app)


def start(idp):
    return idp.get("/auth/google", follow_redirects=False)


def sign_in(idp, google, sub=ALICE_SUB, **claims):
    return idp.get(google.approve(start(idp).headers["location"], sub=sub, **claims))


def verify_app_token(token):
    return jwt.decode(token, load_pem_public_key(IDENTITY_PUBLIC_PEM), algorithms=["RS256"],
                      audience="inventory-agent", issuer="a2a-human-identity-service")


def assert_rejected(r, status, error):
    assert r.status_code == status, r.text
    body = r.json()
    assert body["status"] == error and body["correlation_id"] and "access_token" not in body


# --------------------------------------------------------------------------- #
# Starting the login
# --------------------------------------------------------------------------- #
def test_start_redirects_to_google_with_state_nonce_and_pkce(idp, store):
    r = start(idp)
    assert r.status_code == 302
    url = urlsplit(r.headers["location"])
    q = {k: v[0] for k, v in parse_qs(url.query).items()}
    assert f"{url.scheme}://{url.netloc}{url.path}" == AUTH_URL
    assert {k: q[k] for k in ("response_type", "client_id", "redirect_uri", "scope", "code_challenge_method",
                              "prompt")} == {"response_type": "code", "client_id": CLIENT_ID,
                                             "redirect_uri": REDIRECT_URI, "scope": "openid email",
                                             "code_challenge_method": "S256", "prompt": "select_account"}
    assert q["state"] and q["nonce"] and q["code_challenge"]
    assert "access_type" not in q and "code_verifier" not in q and CLIENT_SECRET not in r.headers["location"]
    assert len(store) == 1
    assert r.headers["cache-control"] == "no-store" and r.headers["referrer-policy"] == "no-referrer"


def test_transaction_cookie_is_host_only_httponly_lax_and_short_lived(idp):
    cookie = start(idp).headers["set-cookie"]
    parts = {p.strip().split("=")[0].lower(): p.strip() for p in cookie.split(";")}
    assert cookie.startswith(f"{google_login.COOKIE_NAME}=")
    assert "httponly" in parts and parts["samesite"].lower() == "samesite=lax"
    assert parts["path"] == "Path=/auth/google" and parts["max-age"] == "Max-Age=300"
    assert "domain" not in parts and "secure" not in parts   # loopback http only; https sets Secure


def test_cookie_holds_only_a_random_binding_id_not_state_or_nonce(idp):
    r = start(idp)
    q = parse_qs(urlsplit(r.headers["location"]).query)
    value = r.cookies[google_login.COOKIE_NAME]
    assert value not in (q["state"][0], q["nonce"][0]) and "." not in value


def test_https_redirect_uri_makes_the_cookie_secure():
    assert GoogleSettings(CLIENT_ID, CLIENT_SECRET, "https://idp.example/auth/google/callback").cookie_secure
    assert not SETTINGS.cookie_secure


def test_discovery_outage_is_503_and_sets_no_cookie(idp, google, store):
    google.down.add("discovery")
    r = start(idp)
    assert_rejected(r, 503, "identity_provider_unavailable")
    assert len(store) == 0
    assert "max-age=0" in r.headers["set-cookie"].lower()            # only ever a deletion


# --------------------------------------------------------------------------- #
# The happy path and identity resolution
# --------------------------------------------------------------------------- #
def test_linked_subject_gets_the_existing_application_jwt_for_user_001(idp, google):
    r = sign_in(idp, google)
    assert r.status_code == 200, r.text
    body = r.json()
    assert {k: body[k] for k in ("status", "human_sub", "token_type", "expires_in")} == \
        {"status": "authenticated", "human_sub": "user-001", "token_type": "Bearer", "expires_in": 300}
    claims = verify_app_token(body["access_token"])
    assert set(claims) == {"iss", "sub", "aud", "iat", "exp"}     # no Google claims copied in
    assert claims["sub"] == "user-001" and claims["exp"] - claims["iat"] == 300
    assert jwt.get_unverified_header(body["access_token"])["kid"] == "identity-key-1"
    assert r.headers["cache-control"] == "no-store" and r.headers["referrer-policy"] == "no-referrer"
    assert "ya29" not in r.text                                    # Google's access token is discarded


def test_cookie_is_cleared_on_success(idp, google):
    r = sign_in(idp, google)
    assert google_login.COOKIE_NAME in r.headers["set-cookie"] and "max-age=0" in r.headers["set-cookie"].lower()


def test_same_subject_with_a_changed_verified_email_is_still_user_001(idp, google):
    r = sign_in(idp, google, email="alice.renamed@example.org")
    assert r.status_code == 200 and verify_app_token(r.json()["access_token"])["sub"] == "user-001"


def test_issuer_without_https_scheme_is_accepted_and_normalized(idp, google):
    assert sign_in(idp, google, iss="accounts.google.com").json()["human_sub"] == "user-001"


def test_different_subject_showing_alices_email_is_403(idp, google):
    assert_rejected(sign_in(idp, google, sub=BOB_SUB, email=ALICE_EMAIL), 403, "account_not_allowed")


def test_unlinked_bob_is_403(idp, google):
    assert_rejected(sign_in(idp, google, sub=BOB_SUB, email="bob@example.com"), 403, "account_not_allowed")


def test_disabled_alice_is_403(idp, google, directory, caplog):
    directory.put("user-001", enabled=False)
    with caplog.at_level(logging.INFO):
        assert_rejected(sign_in(idp, google), 403, "account_not_allowed")
    assert "stage=account_disabled" in caplog.text and "user_id=user-001" in caplog.text


def test_link_to_a_missing_internal_user_is_403(idp, google, monkeypatch):
    monkeypatch.setattr(identity_app.app.state.google_login, "users", MemoryUserDirectory({"user-002": True}))
    assert_rejected(sign_in(idp, google), 403, "account_not_allowed")


# --------------------------------------------------------------------------- #
# The transaction: state, cookie, expiry, single use
# --------------------------------------------------------------------------- #
def approved(idp, google):
    return google.approve(start(idp).headers["location"])


def test_missing_state_is_400(idp, google):
    url = urlsplit(approved(idp, google))
    q = {k: v[0] for k, v in parse_qs(url.query).items()}
    assert_rejected(idp.get(callback(code=q["code"])), 400, "invalid_login_transaction")


def test_wrong_state_is_400_and_ends_that_login(idp, google):
    url = approved(idp, google)
    q = {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}
    assert_rejected(idp.get(callback(code=q["code"], state="forged")), 400, "invalid_login_transaction")
    assert_rejected(idp.get(url), 400, "invalid_login_transaction")    # the real state is now useless too
    assert google.token_calls == 0


def test_missing_cookie_is_400(idp, google):
    url = approved(idp, google)
    idp.cookies.clear()
    assert_rejected(idp.get(url), 400, "invalid_login_transaction")


def test_another_browsers_cookie_is_400(idp, google):
    url = approved(idp, google)
    other = TestClient(identity_app.app)
    start(other)                                                     # a different, valid transaction
    assert_rejected(other.get(url), 400, "invalid_login_transaction")


def test_expired_transaction_is_400(idp, google, store, monkeypatch):
    url = approved(idp, google)
    now = time.time()
    monkeypatch.setattr(store, "_clock", lambda: now + 301)
    assert_rejected(idp.get(url), 400, "invalid_login_transaction")
    assert google.token_calls == 0


def test_missing_code_is_400(idp, google):
    q = {k: v[0] for k, v in parse_qs(urlsplit(approved(idp, google)).query).items()}
    assert_rejected(idp.get(callback(state=q["state"])), 400, "invalid_login_transaction")


def test_replayed_callback_is_400_and_issues_once(idp, google):
    url = approved(idp, google)
    assert idp.get(url).status_code == 200
    assert_rejected(idp.get(url), 400, "invalid_login_transaction")
    assert google.token_calls == 1


def test_simultaneous_duplicate_callbacks_issue_at_most_one_token(idp, google):
    url = approved(idp, google)
    cookie = idp.cookies.get(google_login.COOKIE_NAME)
    barrier, results = threading.Barrier(8), []

    def hit():
        c = TestClient(identity_app.app, cookies={google_login.COOKIE_NAME: cookie})
        barrier.wait()
        results.append(c.get(url).status_code)

    threads = [threading.Thread(target=hit) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(results) == [200] + [400] * 7 and google.token_calls == 1


def test_store_claim_is_atomic_under_contention():
    store = MemoryTransactionStore()
    binding, tx = store.begin("cid")
    barrier, won = threading.Barrier(16), []

    def claim():
        barrier.wait()
        if store.claim(binding, tx.state):
            won.append(1)

    threads = [threading.Thread(target=claim) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert won == [1]


def test_store_is_bounded():
    store = MemoryTransactionStore(max_pending=2)
    store.begin("a")
    store.begin("b")
    with pytest.raises(TransactionStoreFull):
        store.begin("c")


def test_full_store_is_503(idp, monkeypatch):
    monkeypatch.setattr(identity_app.app.state.google_login, "store", MemoryTransactionStore(max_pending=0))
    assert_rejected(start(idp), 503, "identity_provider_unavailable")


# --------------------------------------------------------------------------- #
# Google errors, outages
# --------------------------------------------------------------------------- #
def state_of(idp):
    return parse_qs(urlsplit(start(idp).headers["location"]).query)["state"][0]


def test_cancellation_with_valid_transaction_is_400_login_cancelled(idp):
    assert_rejected(idp.get(callback(error="access_denied", state=state_of(idp))), 400, "login_cancelled")


def test_google_error_is_still_state_checked(idp):
    state_of(idp)
    assert_rejected(idp.get(callback(error="access_denied", state="forged")), 400, "invalid_login_transaction")


def test_other_google_error_is_401(idp):
    assert_rejected(idp.get(callback(error="server_error", state=state_of(idp))), 401,
                    "google_authentication_failed")


def test_token_endpoint_timeout_is_503_with_no_retry(idp, google):
    url = approved(idp, google)
    google.down.add("token")
    assert_rejected(idp.get(url), 503, "identity_provider_unavailable")
    google.down.clear()
    assert_rejected(idp.get(url), 400, "invalid_login_transaction")   # a fresh login is required


def test_signing_key_fetch_failure_is_503(idp, google):
    google.down.add("jwks")
    assert_rejected(sign_in(idp, google), 503, "identity_provider_unavailable")


def test_rotated_google_key_is_fetched_on_unknown_kid(idp, google):
    assert sign_in(idp, google).status_code == 200                    # caches key google-test-1
    google.key, google.kid = _rsa(), "google-test-2"
    oidc = identity_app.app.state.google_login.oidc
    oidc._jwks._last_successful_fetch = None                          # cooldown elapsed
    assert sign_in(idp, google).status_code == 200


# --------------------------------------------------------------------------- #
# Code exchange: PKCE and single-use codes
# --------------------------------------------------------------------------- #
def test_wrong_pkce_verifier_fails_the_exchange(idp, google):
    url = approved(idp, google)
    next(iter(google.codes.values()))["challenge"] = "not-the-challenge-we-sent"
    assert_rejected(idp.get(url), 401, "google_authentication_failed")


def test_reused_authorization_code_fails_the_exchange(idp, google):
    first = approved(idp, google)
    assert idp.get(first).status_code == 200
    code = parse_qs(urlsplit(first).query)["code"][0]
    assert_rejected(idp.get(callback(code=code, state=state_of(idp))), 401, "google_authentication_failed")


# --------------------------------------------------------------------------- #
# ID-token validation: every check rejects
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("claims", [
    {"nonce": "a-different-nonce"},
    {"drop": ("nonce",)},
    {"iss": "https://evil.example"},
    {"aud": "someone-elses-client.apps.googleusercontent.com"},
    {"aud": [CLIENT_ID, "other-client"], "drop": ("azp",)},
    {"azp": "other-client"},
    {"exp": lambda now: now - 31},
    {"iat": lambda now: now + 120},
    {"drop": ("sub",)},
    {"sub": ""},
    {"email_verified": False},
    {"email_verified": "true"},
    {"drop": ("email",)},
    {"drop": ("email_verified",)},
], ids=["wrong-nonce", "no-nonce", "wrong-iss", "wrong-aud", "multi-aud-no-azp", "wrong-azp", "expired",
        "iat-future", "no-sub", "empty-sub", "unverified-email", "string-email-verified", "no-email",
        "no-email-verified"])
def test_invalid_id_token_is_401(idp, google, claims):
    assert_rejected(sign_in(idp, google, **claims), 401, "google_authentication_failed")


def test_id_token_signed_by_another_key_is_401(idp, google):
    assert_rejected(sign_in(idp, google, key=_rsa()), 401, "google_authentication_failed")


def test_id_token_with_unknown_kid_is_401(idp, google):
    assert_rejected(sign_in(idp, google, kid="not-a-google-kid"), 401, "google_authentication_failed")


def test_expiry_within_30s_leeway_is_accepted(idp, google):
    assert sign_in(idp, google, exp=lambda now: now - 10).status_code == 200


def test_multiple_audiences_with_our_azp_is_accepted(idp, google):
    assert sign_in(idp, google, aud=[CLIENT_ID, "other-client"]).status_code == 200


# --------------------------------------------------------------------------- #
# Token boundaries downstream
# --------------------------------------------------------------------------- #
def test_raw_google_id_token_is_rejected_by_the_agent(google):
    raw = google.id_token("n", aud="inventory-agent")
    r = TestClient(agent_app.app).get("/agent/stock/WIDGET-B", headers={"Authorization": f"Bearer {raw}"})
    assert r.status_code == 401


def test_google_issued_application_jwt_reads_stock_through_the_agent(idp, google, wired):
    token = sign_in(idp, google).json()["access_token"]
    r = ask(token, "WIDGET-B")
    assert r.status_code == 200 and r.json()["result"]["sku"] == "WIDGET-B"
    assert r.json()["authenticated_human"] == "user-001"


def test_google_issued_application_jwt_keeps_existing_denials(idp, google, wired):
    token = sign_in(idp, google).json()["access_token"]
    r = ask(token, "WIDGET-A")                                         # delegation grants class_b only
    assert r.status_code == 403 and wired["spy"].detail_lookup is False


# --------------------------------------------------------------------------- #
# No credential leakage
# --------------------------------------------------------------------------- #
def test_logs_contain_no_codes_tokens_state_nonce_or_secrets(idp, google, caplog):
    with caplog.at_level(logging.DEBUG):
        location = start(idp).headers["location"]
        q = {k: v[0] for k, v in parse_qs(urlsplit(location).query).items()}
        cb = google.approve(location)
        body = idp.get(cb).json()
        sign_in(idp, google, sub=BOB_SUB)
    code = parse_qs(urlsplit(cb).query)["code"][0]
    # The test client (standing in for the browser) logs the URLs IT requests via httpx;
    # those lines are the browser's, not the Identity Service's, so they are excluded.
    server_log = "\n".join(r.getMessage() for r in caplog.records
                           if not (r.name == "httpx" and "http://testserver/" in r.getMessage()))
    for secret in (code, q["state"], q["nonce"], q["code_challenge"], CLIENT_SECRET, body["access_token"],
                   "ya29.fake-google-access-token", idp.cookies.get(google_login.COOKIE_NAME) or "x" * 40):
        assert secret not in server_log
    assert "GOOGLE LOGIN OK correlation_id=" in server_log and "user_id=user-001" in server_log
    assert "outcome=account_not_allowed stage=unlinked_subject" in server_log


def test_error_body_correlation_id_matches_the_log(idp, google, caplog):
    with caplog.at_level(logging.INFO):
        r = sign_in(idp, google, sub=BOB_SUB)
    assert f"correlation_id={r.json()['correlation_id']}" in caplog.text


def test_start_and_callback_of_one_login_share_a_correlation_id(idp, google, caplog):
    with caplog.at_level(logging.INFO):
        sign_in(idp, google)
        r = sign_in(idp, google, sub=BOB_SUB)
    started = [line.split("correlation_id=")[1] for line in caplog.messages if "GOOGLE LOGIN STARTED" in line]
    ok = [m for m in caplog.messages if "GOOGLE LOGIN OK" in m][0]
    assert len(started) == 2 and started[0] != started[1]
    assert f"correlation_id={started[0]} " in ok
    assert r.json()["correlation_id"] == started[1]


def test_access_log_filter_drops_callback_query_strings():
    record = logging.LogRecord("uvicorn.access", logging.INFO, "", 0, '%s - "%s %s HTTP/%s" %d',
                               ("127.0.0.1:5000", "GET", "/auth/google/callback?code=SECRET&state=S", "1.1", 200),
                               None)
    google_login.RedactAuthQueryStrings().filter(record)
    assert "SECRET" not in record.getMessage() and "/auth/google/callback?[redacted]" in record.getMessage()


def test_access_log_filter_is_installed():
    assert any(isinstance(f, google_login.RedactAuthQueryStrings)
               for f in logging.getLogger("uvicorn.access").filters)


# --------------------------------------------------------------------------- #
# Configuration fails closed
# --------------------------------------------------------------------------- #
GOOD_ENV = {"GOOGLE_CLIENT_ID": CLIENT_ID, "GOOGLE_CLIENT_SECRET": CLIENT_SECRET, "GOOGLE_REDIRECT_URI": REDIRECT_URI}


def test_settings_absent_is_none_so_the_app_refuses_to_start():
    assert load_google_settings({}) is None


def test_settings_load_and_hide_the_secret():
    s = load_google_settings(GOOD_ENV)
    assert s == SETTINGS and CLIENT_SECRET not in repr(s)


@pytest.mark.parametrize("env", [
    {"GOOGLE_CLIENT_ID": CLIENT_ID},
    {**GOOD_ENV, "GOOGLE_CLIENT_SECRET": ""},
    {**GOOD_ENV, "GOOGLE_OIDC_DISCOVERY_URL": "https://evil.example/.well-known/openid-configuration"},
    {**GOOD_ENV, "GOOGLE_REDIRECT_URI": "http://127.0.0.1:8002/auth/google/callback"},
    {**GOOD_ENV, "GOOGLE_REDIRECT_URI": "http://idp.example/auth/google/callback"},
    {**GOOD_ENV, "GOOGLE_REDIRECT_URI": "http://localhost:8002/other"},
], ids=["partial", "empty-secret", "foreign-discovery", "127-not-localhost", "plain-http", "wrong-path"])
def test_bad_settings_stop_startup(env):
    with pytest.raises(RuntimeError):
        load_google_settings(env)


def test_app_refuses_to_start_without_google_settings():
    # Blank values, not missing ones: load_dotenv never overrides a variable that is
    # already set, so a developer's real identity_service/.env can't fill these in.
    env = {**os.environ, "GOOGLE_CLIENT_ID": "", "GOOGLE_CLIENT_SECRET": "", "GOOGLE_REDIRECT_URI": ""}
    r = subprocess.run([sys.executable, "-c", "import identity_service.app"], env=env, cwd=PROJECT_ROOT,
                       capture_output=True, text=True, timeout=60)
    assert r.returncode != 0 and "Google sign-in is the only login" in r.stderr


# --------------------------------------------------------------------------- #
# Day 08: Firestore outages fail closed with 503, never a token
# --------------------------------------------------------------------------- #
class DownStore:
    """Raises StoreUnavailable from every method, like Firestore during an outage."""

    def __getattr__(self, name):
        def fail(*args, **kwargs):
            raise StoreUnavailable(f"fake.{name}")
        return fail


def test_transaction_store_outage_at_start_is_503(idp, monkeypatch):
    monkeypatch.setattr(identity_app.app.state.google_login, "store", DownStore())
    r = start(idp)
    assert_rejected(r, 503, "identity_store_unavailable")
    assert "location" not in r.headers


def test_transaction_store_outage_at_callback_is_503(idp, google, monkeypatch):
    url = approved(idp, google)
    monkeypatch.setattr(identity_app.app.state.google_login, "store", DownStore())
    assert_rejected(idp.get(url), 503, "identity_store_unavailable")
    assert google.token_calls == 0


@pytest.mark.parametrize("which", ["links", "users"])
def test_directory_outage_after_google_is_503(idp, google, monkeypatch, which):
    url = approved(idp, google)
    monkeypatch.setattr(identity_app.app.state.google_login, which, DownStore())
    assert_rejected(idp.get(url), 503, "identity_store_unavailable")
