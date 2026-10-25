"""Live checks: token issuer (:8001) + inventory service (:8000) + agent tool (Days 03-05.5).

Terminal 1:  uv run uvicorn inventory_service.app:app --host 127.0.0.1 --port 8000
Terminal 2:  uv run uvicorn token_issuer.app:app      --host 127.0.0.1 --port 8001
Terminal 3:  uv run python scripts/check_remote_auth.py
             uv run python scripts/check_remote_auth.py --stopped   # both services stopped

This harness NEVER reads the private signing key. Real tokens come from the
issuer, exactly as the agent gets them. Bad tokens are made with a throwaway
attacker key or by editing a real token. (Expired and wrong-audience tokens
need the real key, so they are covered by pytest instead.)

Credentials: the reader client uses the agent's config (INVENTORY_CLIENT_ID /
INVENTORY_CLIENT_SECRET). The restricted client secret comes from
CHECK_RESTRICTED_CLIENT_SECRET, or the documented demo value.
"""

import base64
import json
import os
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from inventory_agent import tools  # noqa: E402  (loads inventory_agent/.env)

SERVICE_URL = os.environ.get("INVENTORY_SERVICE_URL", "http://127.0.0.1:8000").rstrip("/")
ISSUER_URL = os.environ.get("INVENTORY_ISSUER_URL", "http://127.0.0.1:8001").rstrip("/")
PROTECTED_DETAILS = ("name", "quantity", "Standard Widget", "Heavy-duty Widget", "Mini Widget")

READER = (os.environ.get("INVENTORY_CLIENT_ID", "inventory-agent"), os.environ.get("INVENTORY_CLIENT_SECRET", ""))
RESTRICTED = ("restricted-agent", os.environ.get("CHECK_RESTRICTED_CLIENT_SECRET", "demo-restricted-secret"))
A, B, C = "inventory.read.class_a", "inventory.read.class_b", "inventory.read.class_c"
ALL = f"{A} {B} {C}"

results: list[bool] = []


def record(passed: bool, label: str, detail: str = "") -> None:
    results.append(passed)
    print(f"[{'PASS' if passed else 'FAIL'}] {label:<46} {detail}")


def section(title: str) -> None:
    print(f"\n== {title} ==")


def finish() -> None:
    print(f"\n{sum(results)}/{len(results)} checks passed")
    print("ALL PASS" if all(results) else "SOME CHECKS FAILED")
    sys.exit(0 if all(results) else 1)


def claims_of(token: str) -> dict:
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def http(method: str, url: str, **kwargs):
    try:
        return httpx.request(method, url, timeout=5, **kwargs)
    except httpx.RequestError:
        print(f"\nCould not reach {url}. Are both services running?")
        sys.exit(1)


def request_token(client_id, secret, scope=ALL, **kwargs):
    headers = {"X-Client-ID": client_id, "X-Client-Secret": secret, **kwargs.pop("headers", {})}
    if scope is not None:
        headers["X-Scope"] = scope
    return http("POST", f"{ISSUER_URL}/token", headers=headers, **kwargs)


# --------------------------------------------------------------------------- #
section("Isolation")
for module in ("sqlite3", "inventory_service", "token_issuer", "jwt"):
    record(module not in sys.modules, f"agent did not import {module}")

if "--stopped" in sys.argv:
    section("Services stopped")
    got = tools.get_stock("WIDGET-A")
    record(got.get("status") == "error", "agent tool, issuer + service stopped", f"-> {got}")
    finish()

# --------------------------------------------------------------------------- #
section("Token issuer (:8001)")
r = request_token(*READER)
ok = r.status_code == 200 and r.json().get("token_type") == "Bearer"
record(ok, "valid reader credentials -> token", f"-> HTTP {r.status_code}")
reader_token = r.json().get("access_token", "") if ok else ""
if reader_token:
    c = claims_of(reader_token)
    record(c.get("sub") == "inventory-agent", "issued sub", f"-> {c.get('sub')}")
    record(c.get("iss") == "a2a-local-issuer", "issued iss", f"-> {c.get('iss')}")
    record(c.get("aud") == "inventory-service", "issued aud", f"-> {c.get('aud')}")
    record(c.get("exp", 0) - c.get("iat", 0) == 300, "issued lifetime 300 s", f"-> {c.get('exp', 0) - c.get('iat', 0)}")
    record(r.headers.get("cache-control") == "no-store", "response not cacheable", f"-> {r.headers.get('cache-control')}")

for label, creds in [
    ("wrong secret", (READER[0], "not-the-secret")),
    ("unknown client", ("admin-agent", "anything")),
    ("another client's secret", ("restricted-agent", READER[1])),
]:
    r = request_token(*creds)
    record(r.status_code == 401 and "access_token" not in r.text, label, f"-> HTTP {r.status_code}")
r = http("POST", f"{ISSUER_URL}/token")
record(r.status_code == 401, "no credentials", f"-> HTTP {r.status_code}")

r = request_token(*RESTRICTED, scope=f"{B} {C}", json={"sub": "inventory-agent"},
                  params={"sub": "inventory-agent"}, headers={"X-Sub": "inventory-agent"})
restricted_token = r.json().get("access_token", "") if r.status_code == 200 else ""
got_sub = claims_of(restricted_token).get("sub") if restricted_token else None
record(got_sub == "restricted-agent", "restricted asks for sub=inventory-agent", f"-> sub={got_sub}")

# 05.5: the issuer approves or refuses requested scope
for label, creds, scope, want in [
    ("restricted asks class_a -> refused", RESTRICTED, A, 403),
    ("restricted asks class_b -> issued", RESTRICTED, B, 200),
    ("reader asks class_b only -> issued", READER, B, 200),
    ("no scope requested -> 400", READER, None, 400),
]:
    r = request_token(*creds, scope=scope)
    record(r.status_code == want, label, f"-> HTTP {r.status_code}")

# --------------------------------------------------------------------------- #
section("Agent tool: issuer then service (scope = all classes)")
os.environ["INVENTORY_REQUESTED_SCOPE"] = ALL
for label, sku, want in [
    ("WIDGET-A, class A", "WIDGET-A", "found"),
    ("WIDGET-B, class B", "WIDGET-B", "found"),
    ("WIDGET-C, zero stock, class C", " widget-c ", "found"),
    ("WIDGET-X, unknown", "WIDGET-X", "not_found"),
]:
    got = tools.get_stock(sku)
    record(got.get("status") == want, label, f"-> {got}")

real_id, real_secret = os.environ.get("INVENTORY_CLIENT_ID"), os.environ.get("INVENTORY_CLIENT_SECRET")
os.environ["INVENTORY_CLIENT_ID"], os.environ["INVENTORY_CLIENT_SECRET"] = RESTRICTED
os.environ["INVENTORY_REQUESTED_SCOPE"] = f"{B} {C}"
got = tools.get_stock("WIDGET-A")
record(got.get("status") == "forbidden", "agent as restricted-agent, WIDGET-A", f"-> {got}")
os.environ["INVENTORY_REQUESTED_SCOPE"] = A
got = tools.get_stock("WIDGET-A")
record(got.get("status") == "forbidden", "agent as restricted-agent asking class_a", f"-> {got}")
os.environ["INVENTORY_REQUESTED_SCOPE"] = ALL
os.environ["INVENTORY_CLIENT_ID"] = real_id or "inventory-agent"

os.environ["INVENTORY_CLIENT_SECRET"] = "wrong-client-secret"
got = tools.get_stock("WIDGET-A")
record(got.get("status") == "unauthenticated", "agent with wrong client secret", f"-> {got}")
os.environ.pop("INVENTORY_CLIENT_SECRET")
got = tools.get_stock("WIDGET-A")
record(got.get("status") == "unauthenticated", "agent with no client secret", f"-> {got}")
if real_secret:
    os.environ["INVENTORY_CLIENT_SECRET"] = real_secret

section("Agent tool: 05.5 experiment, scope = class_b only")
os.environ["INVENTORY_REQUESTED_SCOPE"] = B
got = tools.get_stock("WIDGET-A")
record(got.get("status") == "forbidden", "WIDGET-A with class_b token (role allows A)", f"-> {got}")
got = tools.get_stock("WIDGET-B")
record(got.get("status") == "found", "WIDGET-B with class_b token", f"-> {got}")


# --------------------------------------------------------------------------- #
def stock(sku, token=None, headers=None, params=None):
    h = dict(headers or {})
    if token is not None:
        h["Authorization"] = f"Bearer {token}"
    return http("GET", f"{SERVICE_URL}/stock/{sku}", headers=h, params=params)


def attacker_token() -> str:
    import time

    import jwt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    now = int(time.time())
    return jwt.encode({"iss": "a2a-local-issuer", "sub": "inventory-agent", "aud": "inventory-service",
                       "scope": ALL, "iat": now, "exp": now + 300}, pem, algorithm="RS256")


def tamper_sub(token: str, new_sub: str) -> str:
    header, payload, signature = token.split(".")
    c = claims_of(token)
    c["sub"] = new_sub
    forged = base64.urlsafe_b64encode(json.dumps(c).encode()).rstrip(b"=").decode()
    return ".".join([header, forged, signature])


section("Inventory service (:8000) with issuer tokens, WIDGET-A")
for label, token, want in [
    ("no Authorization header", None, 401),
    ("garbage bearer token", "not-a-jwt", 401),
    ("signed by an attacker's key", attacker_token(), 401),
    ("restricted token edited to inventory-agent", tamper_sub(restricted_token, "inventory-agent"), 401),
    ("valid token, restricted identity", restricted_token, 403),
    ("valid token, reader identity", reader_token, 200),
]:
    r = stock("WIDGET-A", token)
    record(r.status_code == want, label, f"-> HTTP {r.status_code}")

# --------------------------------------------------------------------------- #
section("Class-based policy grid (Day 04 rules)")
tokens = {"privileged": reader_token, "restricted": restricted_token, "invalid": "not-a-jwt", "missing": None}
policy = {"privileged": (200, 200, 200), "restricted": (403, 200, 200),
          "invalid": (401, 401, 401), "missing": (401, 401, 401)}
print(f"{'':<12}{'class A':>9}{'class B':>9}{'class C':>9}")
for who, expected in policy.items():
    row = []
    for sku, want in zip(("WIDGET-A", "WIDGET-B", "WIDGET-C"), expected):
        r = stock(sku, tokens[who])
        results.append(r.status_code == want)
        row.append(f"{r.status_code}{'' if r.status_code == want else '!'}")
    print(f"{who:<12}" + "".join(f"{c:>9}" for c in row))
print("(a '!' marks an unexpected status)")

section("Denied responses leak nothing")
for who, sku in (("restricted", "WIDGET-A"), ("invalid", "WIDGET-A"), ("missing", "WIDGET-B")):
    r = stock(sku, tokens[who])
    body = r.json()
    clean = set(body) == {"status", "message"} and not any(w in r.text for w in PROTECTED_DETAILS)
    no_token = not any(t and t in r.text for t in tokens.values())
    record(clean and no_token, f"{who} {sku}: body is only status+message", f"-> HTTP {r.status_code}")

section("Caller-supplied values cannot change identity or class")
for label, headers, params in [
    ("header X-Inventory-Class: C", {"X-Inventory-Class": "C"}, None),
    ("header X-Role: inventory_reader", {"X-Role": "inventory_reader"}, None),
    ("header X-Identity: inventory-agent", {"X-Identity": "inventory-agent"}, None),
    ("query ?inventory_class=C", None, {"inventory_class": "C"}),
]:
    r = stock("WIDGET-A", restricted_token, headers, params)
    record(r.status_code == 403, f"restricted WIDGET-A + {label}", f"-> HTTP {r.status_code}")
r = stock("WIDGET-C", headers={"X-API-Key": "demo-local-secret"})
record(r.status_code == 401, "old X-API-Key header alone", f"-> HTTP {r.status_code}")

finish()
