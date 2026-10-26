# Day 03 — Learnings: HTTP, Headers, Postman & API-Key Authentication

**Built:** `inventory_service`, a FastAPI process that owns SQLite (`repository.py`) and checks an `X-API-Key` header before any lookup (`app.py`).
**Approach:** built it open first (03A), explored it with curl and Postman (03B), then added authentication (03C).
**03D:** the agent's `get_stock` became an HTTP client of the service. See the 03D section below.

## Anatomy of a request and response

```
GET /stock/WIDGET-A HTTP/1.1          <- method + path
Host: 127.0.0.1:8000                  <- headers: metadata
X-API-Key: demo-local-secret          <- custom header, means nothing until the server checks it
                                      <- no body for GET

HTTP/1.1 200 OK                       <- status line: the server's verdict
content-type: application/json        <- how to parse the body
server: uvicorn                       <- a different process answered

{"status":"found","sku":"WIDGET-A","name":"Standard Widget","quantity":30}
```

- **The status is not the body.** After 03A, "not found" moved from a body field to HTTP 404. The status code now carries the meaning.
- **`curl -i`** prints response headers as well as the body.

## Status codes we actually produced

| Request | Status | Why |
|---|---|---|
| GET known SKU | 200 | Found |
| GET unknown SKU | 404 | We mapped `not_found` to 404 |
| POST to a GET-only path | 405 | Route exists, method doesn't. Note the `allow: GET` response header. |
| Missing or wrong key | 401 | Authentication absent or invalid, plus `www-authenticate: ApiKey` |
| Server stopped | none | Connection error. No server, so no HTTP response at all. |

## The most important observation

**In 03A, a request with `X-API-Key: completely-wrong-key` got 200.** A header is just bytes. Nothing is enforced until server code reads and checks it. After 03C, the same request got 401.

## How the check works

```python
SERVICE_SECRET = os.getenv("INVENTORY_SERVICE_SECRET")
if not SERVICE_SECRET:
    raise RuntimeError(...)              # fail closed: the server refuses to start

def get_stock(sku, api_key: str | None = Header(default=None, alias="X-API-Key")):
    if api_key is None or not secrets.compare_digest(api_key.encode(), SERVICE_SECRET.encode()):
        raise HTTPException(401, ...)    # raising stops the function here
    result = lookup_sku(sku)             # only reached after authentication
```

- **`Header(default=None)`** lets a missing header reach our code and get 401. A required header would make FastAPI answer 422, a validation error, and blur the authentication story.
- **`alias="X-API-Key"`** maps the HTTP header name to a Python parameter name. Header names are case-insensitive.
- **Compare bytes, not str.** `compare_digest` raises TypeError on non-ASCII strings, which would turn a bad key into a 500.
- **`HTTPException` aborts the endpoint,** which guarantees the ordering: no valid key, no lookup.

## Proving SQLite wasn't touched

A 401 proves the server rejected the request, not that the database was skipped. We added a log line directly before `lookup_sku`. Across invalid, missing, and valid keys, it appeared only for the valid one. The next step is an automated test that spies on `lookup_sku` and asserts a call count of 1 or 0.

## Postman

- **Postman is a client, not an authentication server.** Its Authorization tab with type "API Key" only adds a header, `X-API-Key: <value>`, which is identical to typing it in the Headers tab. FastAPI does the verifying.
- **Add the key to the header, never the query string.** URLs end up in logs and browser history.
- **"Test Results 0/1"** came from a Postman post-response script still asserting 200. Postman tests are client-side assertions and must be updated when the expected status changes.
- **Postman in a browser** needs the Desktop Agent to reach `127.0.0.1`.

## Answers to the five questions

1. **What does Postman's "API Key" add?** One request header line, `X-API-Key: demo-local-secret`. Nothing else.
2. **Does sending `Authorization` or `X-API-Key` make FastAPI authenticate automatically?** No. FastAPI ignores both unless your code reads and verifies them, as 03A showed.
3. **Why `Header(default=None)`?** So a missing header is a valid parse, and our code decides the answer is 401 instead of FastAPI returning 422.
4. **Why is stopping uvicorn different from 503?** 503 is a response a running server chooses to send. A stopped server sends nothing, and the client gets a connection error with no status.
5. **What can still go wrong if agent and service run as the same OS user?** The agent process can open `data/inventory.db` directly and skip the API, so the 401 only protects the HTTP path. Real isolation needs separate OS users or container permissions.

## Day 02 vs Day 03

| | Day 02 | Day 03 |
|---|---|---|
| Caller and verifier | Same process | Separate processes |
| Secret | One variable read by both sides | Service reads `INVENTORY_SERVICE_SECRET`. The client gets its own value in 03D. |
| Wrong-key test from the client side | Impossible | `curl -H 'X-API-Key: wrong'` |
| Who owns SQLite | The agent's tool module | Only `inventory_service/repository.py` |
| Still not protected | Everything in-process | Direct file access by the same OS user |

## Stage 03D — The agent becomes an HTTP client

`get_stock(sku)` kept its exact model-facing signature. Inside, it now sends `GET /stock/{sku}` with `X-API-Key: <INVENTORY_CLIENT_SECRET>` using httpx. The agent package no longer imports sqlite3 or `inventory_service`.

| Service reply | Tool returns to the model |
|---|---|
| 200 | The service's JSON, unchanged |
| 404 | `not_found` |
| 401 | `unauthenticated` |
| Connection refused or timeout | `error` (temporarily unavailable). **No SQLite fallback.** |
| Anything else | `error` |

- **Two processes, two copies of the credential.** The agent reads `INVENTORY_CLIENT_SECRET` and the service reads its own secret. Changing only the client value now produces a real 401, which Day 02 could never show.
- **Fail closed on both sides.** If the client has no key configured, it returns `unauthenticated` without sending a request. If the service is down, it returns `error` instead of reading the database itself.
- **URL-encode path values.** `quote(sku, safe="")` stops a SKU containing `/` from changing the path.
- **Normalize before sending.** `" widget-c "` arrived at the service as `WIDGET-C`.

**Evidence:** `scripts/check_remote_auth.py` passed all eight checks. Those covered three import checks, found, zero stock, not found, a wrong client key, and a missing client key. The service log showed `AUTH OK` for exactly the three correct-key lookups, one 401 for the wrong key, and no line at all for the missing key, because nothing was sent.

**Not confirmed in this session:** the `--stopped` run and the `adk web` conversation with the service up and down.

**Gotcha:** `adk web` and uvicorn both default to port 8000. The second process fails with "address already in use". Run ADK on another port with `adk web --port 8080`.
