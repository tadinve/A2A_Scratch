"""Day 05.9: JWT security attack drill. Attacks every layer, expects every attack to fail safely.

    uv run python scripts/attack_drill.py

Runs IN-PROCESS against the real token issuer app, the real inventory service app,
and the real agent tool, using the test suite's throwaway keys and configs
(tests/support.py). It never reads ~/secrets and needs no running services.
SQLite access is replaced by a spy so every denial can prove no protected
detail lookup happened.
"""

import base64
import inspect
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Must come first: creates throwaway keys/configs and points both services at them.
from tests.support import (  # noqa: E402
    ATTACKER_PRIVATE_PEM, KEY2_PRIVATE_FILE, KEY2_PRIVATE_PEM, KEY2_PUBLIC_FILE, PRIVATE_PEM,
    PRIVATE_KEY_FILE, PUBLIC_KEY_FILE, READER_CLIENT, RESTRICTED_CLIENT, RepoSpy, make_token, service,
)

import httpx  # noqa: E402
import jwt  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from inventory_agent import tools  # noqa: E402
from inventory_service import auth as service_auth  # noqa: E402
from inventory_service.tokens import load_trusted_keys  # noqa: E402
from token_issuer import app as issuer_app  # noqa: E402
from token_issuer import issuer  # noqa: E402

A, B, C = "inventory.read.class_a", "inventory.read.class_b", "inventory.read.class_c"
ALL = f"{A} {B} {C}"
PROTECTED = ("Standard Widget", "Heavy-duty Widget", "Mini Widget", "quantity", "inventory_class",
             '"name"', "class_a", "class_b", "class_c")


# --------------------------------------------------------------------------- #
# Harness
# --------------------------------------------------------------------------- #
class Drill:
    def __init__(self, verbose=True):
        self.verbose = verbose
        self.results: list[tuple[str, str, bool, str]] = []
        self.section_name = ""
        self._patches: list[tuple[object, str, object]] = []
        self.spy = RepoSpy()
        self.patch(service, "get_classification", self.spy.get_classification)
        self.patch(service, "lookup_sku", self.spy.lookup_sku)
        self.issuer_http = TestClient(issuer_app.app)
        self.service_http = TestClient(service.app)

    # tiny monkeypatch, undone in close()
    def patch(self, obj, name, value):
        self._patches.append((obj, name, getattr(obj, name)))
        setattr(obj, name, value)

    def close(self):
        for obj, name, value in reversed(self._patches):
            setattr(obj, name, value)
        tools._clear_cache()

    def section(self, name):
        self.section_name = name
        if self.verbose:
            print(f"\n== {name} ==")

    def check(self, label, passed, detail=""):
        self.results.append((self.section_name, label, bool(passed), detail))
        if self.verbose:
            print(f"[{'PASS' if passed else 'FAIL'}] {label:<56} {detail}")

    # requests
    def token_request(self, creds=None, scope=B, headers=None):
        h = dict(headers or {})
        if creds:
            h["X-Client-ID"], h["X-Client-Secret"] = creds
        if scope is not None:
            h["X-Scope"] = scope
        return self.issuer_http.post("/token", headers=h)

    def issue(self, creds=READER_CLIENT, scope=B):
        r = self.token_request(creds, scope)
        assert r.status_code == 200, r.text
        return r.json()["access_token"]

    def stock(self, sku, token=None, headers=None, params=None):
        self.spy.class_calls.clear()
        self.spy.detail_calls.clear()
        h = dict(headers or {})
        if token is not None:
            h["Authorization"] = f"Bearer {token}"
        return self.service_http.get(f"/stock/{sku}", headers=h, params=params)

    def expect_stock(self, label, sku, token, want, headers=None, params=None):
        r = self.stock(sku, token, headers, params)
        ok = r.status_code == want
        if want in (401, 403):
            ok = ok and not self.spy.detail_lookup          # protected details never read
        if want == 401:
            ok = ok and not self.spy.sqlite_touched         # authn failures never touch SQLite
        self.check(label, ok, f"-> {r.status_code}")
        return r

    # key configuration, as a restart with edited config would load it
    def trust(self, **kid_files):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "inventory_service.json"
            cfg.write_text(json.dumps({"trusted_keys": {k: str(v) for k, v in kid_files.items()}}))
            self.patch(service_auth, "_TRUSTED_KEYS", load_trusted_keys(cfg, ROOT))

    def sign_with(self, kid, private_file):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "issuer.json"
            cfg.write_text(json.dumps({"active_kid": kid, "private_key_path": str(private_file)}))
            active_kid, key = issuer.load_signing_config(cfg)
        self.patch(issuer, "ACTIVE_KID", active_kid)
        self.patch(issuer, "_PRIVATE_KEY", key)


def edit_claim(token, **changes):
    """Change claims AFTER signing, keeping the original signature."""
    header, payload, signature = token.split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    claims.update(changes)
    forged = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    return ".".join([header, forged, signature])


def with_header(token, header):
    raw = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    return ".".join([raw, *token.split(".")[1:]])


# --------------------------------------------------------------------------- #
# The drill
# --------------------------------------------------------------------------- #
def run(verbose=True) -> list[tuple[str, str, bool, str]]:
    d = Drill(verbose)
    try:
        _authentication(d)
        _integrity(d)
        _algorithms(d)
        _claims(d)
        _scope(d)
        _spoofing(d)
        _key_rotation(d)
        _lifecycle(d)
        _leakage(d)
        _isolation(d)
    finally:
        d.close()
    return d.results


def _authentication(d):
    d.section("1. Authentication (issuer)")
    for label, creds, headers in [
        ("missing client credentials -> 401", None, None),
        ("client id without secret -> 401", None, {"X-Client-ID": READER_CLIENT[0]}),
        ("wrong client secret -> 401", (READER_CLIENT[0], "wrong"), None),
        ("unknown client -> 401", ("admin-agent", "anything"), None),
        ("another client's secret -> 401", (RESTRICTED_CLIENT[0], READER_CLIENT[1]), None),
    ]:
        r = d.token_request(creds, headers=headers)
        d.check(label, r.status_code == 401 and "access_token" not in r.text, f"-> {r.status_code}")
    r = d.token_request(RESTRICTED_CLIENT, B, headers={"X-Sub": "inventory-agent"})
    sub = jwt.decode(r.json()["access_token"], options={"verify_signature": False})["sub"]
    d.check("caller cannot choose its own sub", sub == "restricted-agent", f"-> sub={sub}")


def _integrity(d):
    d.section("2. Token integrity (service)")
    restricted = d.issue(RESTRICTED_CLIENT, B)
    d.expect_stock("edit sub after signing -> 401", "WIDGET-B", edit_claim(restricted, sub="inventory-agent"), 401)
    d.expect_stock("edit scope after signing -> 401", "WIDGET-A", edit_claim(restricted, scope=ALL), 401)
    d.expect_stock("edit aud after signing -> 401", "WIDGET-B",
                   edit_claim(make_token(aud="billing-service"), aud="inventory-service"), 401)
    d.expect_stock("edit exp after signing -> 401", "WIDGET-B",
                   edit_claim(make_token(iat=1_000_000, exp=1_000_300), exp=9_999_999_999), 401)
    d.expect_stock("signed with attacker's private key -> 401", "WIDGET-B", make_token(key=ATTACKER_PRIVATE_PEM), 401)
    d.expect_stock("garbage token -> 401", "WIDGET-B", "not-a-jwt", 401)


def _algorithms(d):
    d.section("3. Algorithm attacks (service)")
    claims = jwt.decode(make_token(), options={"verify_signature": False})
    unsigned = jwt.encode(claims, None, algorithm="none", headers={"kid": "key-1"})
    d.expect_stock("alg=none -> 401", "WIDGET-B", unsigned, 401)
    d.expect_stock("HS256 instead of RS256 -> 401", "WIDGET-B",
                   make_token(key="a-shared-secret-of-at-least-32-bytes!!", algorithm="HS256"), 401)
    d.expect_stock("RS512 with the real key -> 401", "WIDGET-B", make_token(algorithm="RS512"), 401)


def _claims(d):
    d.section("4. Claim validation (service)")
    for claim in ("sub", "aud", "exp", "iss", "iat", "scope"):
        d.expect_stock(f"missing {claim} -> 401", "WIDGET-B", make_token(drop=(claim,)), 401)
    d.expect_stock("wrong iss -> 401", "WIDGET-B", make_token(iss="evil-issuer"), 401)
    d.expect_stock("wrong aud -> 401", "WIDGET-B", make_token(aud="billing-service"), 401)
    d.expect_stock("expired -> 401", "WIDGET-B", make_token(iat=1_000_000, exp=1_000_300), 401)


def _scope(d):
    d.section("5. Scope escalation")
    r = d.token_request(RESTRICTED_CLIENT, A)
    d.check("restricted-agent requests class_a -> issuer 403", r.status_code == 403 and "access_token" not in r.text,
            f"-> {r.status_code}")
    r = d.token_request(RESTRICTED_CLIENT, f"{B} {A}")
    d.check("restricted-agent sneaks class_a into a list -> issuer 403", r.status_code == 403, f"-> {r.status_code}")
    for trick in ("inventory.read.*", "inventory.read", "*"):
        r = d.token_request(RESTRICTED_CLIENT, trick)
        d.check(f"issuer rejects scope trick {trick!r}", r.status_code == 400, f"-> {r.status_code}")
    class_b = d.issue(READER_CLIENT, B)
    d.expect_stock("class_b token on WIDGET-A -> service 403", "WIDGET-A", class_b, 403)
    d.expect_stock("class_b token on WIDGET-B -> 200", "WIDGET-B", class_b, 200)
    d.expect_stock("fake X-Scope header to service -> still 403", "WIDGET-A", class_b, 403, headers={"X-Scope": A})
    for trick in ("inventory.read.*", "inventory.read", "inventory.read.class_a_extra", "INVENTORY.READ.CLASS_A", ""):
        d.expect_stock(f"service rejects token scope {trick!r} -> 403", "WIDGET-A",
                       make_token("inventory-agent", scope=trick), 403)
    d.expect_stock("class_a scope on restricted role -> 403 (scope can't exceed role)", "WIDGET-A",
                   make_token("restricted-agent", scope=A), 403)


def _spoofing(d):
    d.section("6. Authorization spoofing (service)")
    restricted = d.issue(RESTRICTED_CLIENT, f"{B} {C}")
    for label, headers, params in [
        ("fake X-Role: inventory_reader", {"X-Role": "inventory_reader"}, None),
        ("fake X-Identity: inventory-agent", {"X-Identity": "inventory-agent"}, None),
        ("fake X-Inventory-Class: C", {"X-Inventory-Class": "C"}, None),
        ("query ?inventory_class=C", None, {"inventory_class": "C"}),
        ("old X-API-Key header", {"X-API-Key": "demo-local-secret"}, None),
    ]:
        d.expect_stock(f"{label} -> 403", "WIDGET-A", restricted, 403, headers=headers, params=params)
    d.expect_stock("X-API-Key alone, no bearer token -> 401", "WIDGET-C", None, 401,
                   headers={"X-API-Key": "demo-local-secret"})


def _key_rotation(d):
    d.section("7. Key rotation")
    d.expect_stock("unknown kid -> 401", "WIDGET-B", make_token(kid="key-9"), 401)
    d.expect_stock("missing kid -> 401", "WIDGET-B", make_token(kid=None), 401)
    d.expect_stock("non-string kid -> 401", "WIDGET-B",
                   with_header(make_token(), {"alg": "RS256", "typ": "JWT", "kid": 7}), 401)
    d.expect_stock("kid as a file path -> 401", "WIDGET-B", make_token(kid=str(PUBLIC_KEY_FILE)), 401)
    d.expect_stock("attacker key claiming kid=key-1 -> 401", "WIDGET-B",
                   make_token(key=ATTACKER_PRIVATE_PEM, kid="key-1"), 401)

    old = d.issue()                                               # key-1 era
    d.trust(**{"key-1": PUBLIC_KEY_FILE, "key-2": KEY2_PUBLIC_FILE})
    d.expect_stock("signed key-1, header says kid=key-2 -> 401", "WIDGET-B", make_token(key=PRIVATE_PEM, kid="key-2"), 401)
    d.expect_stock("signed key-2, header says kid=key-1 -> 401", "WIDGET-B", make_token(key=KEY2_PRIVATE_PEM, kid="key-1"), 401)
    d.sign_with("key-2", KEY2_PRIVATE_FILE)
    new = d.issue()
    d.check("issuer token carries the active kid", jwt.get_unverified_header(new).get("kid") == "key-2",
            f"-> kid={jwt.get_unverified_header(new).get('kid')}")
    ok = d.stock("WIDGET-B", old).status_code == 200 and d.stock("WIDGET-B", new).status_code == 200
    d.check("overlap: old key-1 and new key-2 tokens both accepted", ok)
    d.trust(**{"key-2": KEY2_PUBLIC_FILE})
    d.expect_stock("retired key-1 token -> 401", "WIDGET-B", old, 401)
    d.expect_stock("active key-2 token -> 200", "WIDGET-B", new, 200)


def _lifecycle(d):
    """The REAL agent tool, with its HTTP routed into the two in-process apps and a fake clock."""
    d.section("8. Token lifecycle (real agent tool)")
    calls = {"issuer": 0, "service": 0}
    state = {"issuer_down": False, "t": 1000.0}

    def post(url, headers=None, timeout=None):
        if state["issuer_down"]:
            raise httpx.ConnectError("issuer down")
        calls["issuer"] += 1
        return d.issuer_http.post("/token", headers=headers)

    def get(url, headers=None, timeout=None):
        calls["service"] += 1
        return d.service_http.get(urlsplit(url).path, headers=headers)

    d.patch(tools.httpx, "post", post)
    d.patch(tools.httpx, "get", get)
    d.patch(tools, "_now", lambda: state["t"])
    env = {"INVENTORY_CLIENT_ID": READER_CLIENT[0], "INVENTORY_CLIENT_SECRET": READER_CLIENT[1],
           "INVENTORY_REQUESTED_SCOPE": B, "INVENTORY_ISSUER_URL": "http://issuer",
           "INVENTORY_SERVICE_URL": "http://inventory"}
    saved_env = {k: os.environ.get(k) for k in env}
    os.environ.update(env)
    tools._clear_cache()
    # Rotation already moved everything to key-2 (section 7), which is the live state too.
    try:
        r1 = tools.get_stock("WIDGET-B")
        d.check("first call gets a token, then calls service", r1.get("status") == "found" and calls == {"issuer": 1, "service": 1},
                f"-> {calls}")
        state["t"] += 60
        tools.get_stock("WIDGET-B")
        d.check("second call reuses the cached token", calls["issuer"] == 1, f"-> issuer calls={calls['issuer']}")
        state["t"] += 300 - 60 - 30                     # 30 s left: inside the margin
        tools.get_stock("WIDGET-B")
        d.check("token near expiry is renewed proactively", calls["issuer"] == 2, f"-> issuer calls={calls['issuer']}")

        # Cached token becomes invalid server-side: rotate to a key the cached token wasn't signed with.
        d.trust(**{"key-1": PUBLIC_KEY_FILE})
        d.sign_with("key-1", PRIVATE_KEY_FILE)
        before = dict(calls)
        r = tools.get_stock("WIDGET-B")
        d.check("cached token rejected (401) -> renew + retry once -> 200",
                r.get("status") == "found" and calls["issuer"] - before["issuer"] == 1
                and calls["service"] - before["service"] == 2, f"-> {r.get('status')}")

        before = dict(calls)
        r = tools.get_stock("WIDGET-A")                 # class_b token on class A
        d.check("403 -> no renewal, no retry", r.get("status") == "forbidden" and calls["issuer"] == before["issuer"]
                and calls["service"] - before["service"] == 1, f"-> {r.get('status')}")

        state["issuer_down"] = True
        r = tools.get_stock("WIDGET-B")
        d.check("issuer down + valid cached token -> still works", r.get("status") == "found", f"-> {r.get('status')}")
        state["t"] += 301
        before = dict(calls)
        r = tools.get_stock("WIDGET-B")
        d.check("issuer down + expired token -> fail closed, token not sent",
                r.get("status") == "error" and calls["service"] == before["service"], f"-> {r.get('status')}")
    finally:
        for k, v in saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _leakage(d):
    d.section("9. Data leakage")
    restricted = d.issue(RESTRICTED_CLIENT, B)
    secrets_to_hide = [READER_CLIENT[1], RESTRICTED_CLIENT[1], restricted, "BEGIN", "PRIVATE KEY"]
    for label, sku, token, want in [
        ("401 body is a generic authentication error", "WIDGET-A", "not-a-jwt", 401),
        ("403 body is a generic authorization error", "WIDGET-A", restricted, 403),
    ]:
        r = d.stock(sku, token)
        body = r.json()
        clean = (r.status_code == want and set(body) == {"status", "message"}
                 and not any(p in r.text for p in PROTECTED)
                 and not any(s in r.text for s in secrets_to_hide)
                 and not d.spy.detail_lookup)
        d.check(label, clean, f"-> {r.status_code} {body}")
    r = d.token_request((READER_CLIENT[0], "wrong"))
    d.check("issuer 401 echoes no secret", not any(s in r.text for s in (READER_CLIENT[1], "wrong")), f"-> {r.json()}")
    r = d.token_request(RESTRICTED_CLIENT, A)
    d.check("issuer 403 issues no token", "access_token" not in r.text and "eyJ" not in r.text, f"-> {r.json()}")


def _isolation(d):
    d.section("10. Isolation")
    probe = ("import sys, inventory_agent.tools; "
             "print(sorted(m for m in ('sqlite3','inventory_service','token_issuer','jwt') if m in sys.modules))")
    out = subprocess.run([sys.executable, "-c", probe], cwd=ROOT, capture_output=True, text=True)
    loaded = out.stdout.strip()
    for module in ("sqlite3", "inventory_service", "token_issuer", "jwt"):
        d.check(f"agent does not import {module}", out.returncode == 0 and f"'{module}'" not in loaded,
                f"-> loaded={loaded or out.stderr.strip()[-80:]}")

    markers = ("private_key_path", "private.pem", "load_pem_private_key", "RSAPrivateKey", "JWT_PRIVATE_KEY_PATH")
    for package in ("inventory_service", "inventory_agent"):
        clean = all(m not in p.read_text() for p in (ROOT / package).glob("*.py") for m in markers)
        d.check(f"{package} code never references a private key", clean)
    d.check("inventory service holds only public keys",
            all(isinstance(k, RSAPublicKey) for k in service_auth._TRUSTED_KEYS.values()))
    d.check("token issuer holds the private signing key", isinstance(issuer._PRIVATE_KEY, RSAPrivateKey))
    real_cfg = json.loads((ROOT / "config" / "inventory_service.json").read_text())
    d.check("real service config lists no private key files",
            all("private" not in str(p) for p in real_cfg.get("trusted_keys", {}).values()))
    d.check("agent tool takes only a SKU (model can't pass scope/identity)",
            list(inspect.signature(tools.get_stock).parameters) == ["sku"])


def main() -> int:
    results = run(verbose=True)
    failed = [r for r in results if not r[2]]
    print(f"\n{len(results) - len(failed)}/{len(results)} attack checks passed")
    print("ALL PASS" if not failed else f"FAILED: {[r[1] for r in failed]}")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
