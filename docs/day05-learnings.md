# Day 05 — Learnings: Signed Tokens (JWT), a Token Issuer, Scopes, Lifecycle, and Key Rotation

**Built:** the shared API key became an RS256-signed JWT, minted by a separate token issuer and verified by the inventory service with public keys only. Tokens then gained scopes, a client-side lifecycle (caching, renewal, one bounded retry), and rotatable signing keys.

**Final architecture:**

```
Inventory Agent ──(client id + secret + scope)──▶ Token Issuer :8001   private key, chosen by config/issuer.json
       │                                               │ signed JWT {iss, sub, aud, scope, iat, exp}, header kid
       └──────(Authorization: Bearer <jwt>)──────────▶ Inventory Service :8000   public keys by kid, config/inventory_service.json
                                                        verify -> token scope -> role -> class -> SQLite
```

**Evidence:** 209 pytest tests, 55/55 live checks, and the **76/76 attack drill** (05.9) passed. The agent flow demo passed all 6 scenarios. The full key rotation ran end to end per [day05-key-rotation-runbook.txt](day05-key-rotation-runbook.txt):

| Phase | Saved key-1 token | Fresh token |
|---|---|---|
| key-1 only | n/a | key-1 → 200 |
| Overlap (service trusts both, issuer on key-2) | 200 | key-2 → 200 |
| key-1 retired | **401** (`UnknownKeyIdError`) | key-2 → 200 |

---

## 05.1 — What a JWT is

- **Three Base64URL parts, `header.payload.signature`.** Anyone can decode and read the first two. A signed JWT gives **integrity and origin, not secrecy**.
- **The signature covers the header and the payload.** Editing `sub` to `admin-agent` produces valid JSON, a correct audience, and an unexpired token, and it still fails, because the signature no longer matches. That is the foundation of signed-token security.
- **Asymmetric keys:** only the private key can sign, and the public key can only verify. A verifier can't mint tokens.
- **Pin the algorithm in the verifier** (`algorithms=["RS256"]`), never trusting the token's `alg` header. `none`, `HS256`, and even `RS512` signed with the real key were all rejected.
- **Require claims explicitly.** The JWT spec makes them optional, so `options={"require": [...]}` is needed.

## 05.2 — Bearer tokens in the service

- `Authorization: Bearer <jwt>`. The scheme name is case-insensitive. A missing header, a wrong scheme, `Bearer` alone, or extra parts all get **401 before SQLite**.
- The identity is the **verified `sub`**, which replaced the identity derived from the API key. Authorization code was unchanged.
- **A valid signature on an unknown `sub` gives 403, not 401.** The caller is authenticated but has no role.
- The service fails at startup if its key file is missing, is not a public key, or is not RSA.

## 05.3 — A separate token issuer

- **`sub` is the output of authentication, never input.** The issuer authenticates `X-Client-ID` and `X-Client-Secret`, then picks the identity from its own registry. A `sub` sent in the body, the query, or a header was ignored in every test.
- **Only the issuer holds the private key.** Tests assert that the service and agent code never reference one.
- Token responses carry `Cache-Control: no-store`, as OAuth 2.0 requires.
- An unknown client ID is compared against a dummy secret, so it fails the same way as a wrong secret.

## 05.4 — The agent performs the whole flow

- The agent makes two HTTP calls: issuer, then service. No caching at first, deliberately, so every step shows in the logs: `1/2 agent -> issuer`, `2/2 agent -> service`.
- The client secret goes only to the issuer, never to the inventory service.

## 05.5 — Scopes: request authority, never grant it

- **Entitlement** is the most a client may ever get. **Requested scope** is what it asks for in this token.
- **The issuer refuses scopes outside the entitlement.** `restricted-agent` asking for class A got 403 and no token was minted. A caller can request authority but cannot grant it to itself.
- **The service enforces token scope AND role. Both must pass.** `inventory-agent` with a class B token gets 403 on WIDGET-A, even though its role allows class A. Scope can only narrow access, never exceed the role.
- **The agent's scope comes from config, never the model.** `get_stock(sku)` still has a single parameter.
- No scope requested gets 400. There is no silent default to the full entitlement.
- *Design note:* this project uses 403 for a scope outside the entitlement. Standard OAuth returns 400 `invalid_scope`.

## 05.6 — Credentials have a lifecycle

- **Reuse while fresh:** 10 inventory calls cost 1 issuer call. A token is renewed when 30 seconds or less remain, not at the last second.
- **Expiry comes from `expires_in`,** measured from before the request on a monotonic clock. The agent never decodes the JWT.
- **The cache key preserves the authority boundary:** issuer, client, secret fingerprint, and scope. A class B token is never reused for class A.
- **401 on a cached token:** discard it, renew once, retry once. **403: never retry.** A fresh token with the same scope cannot fix insufficient authority.
- **An issuer outage is not a service outage** while a valid cached token exists. An expired token fails closed.
- No refresh tokens. Renewal means re-authenticating with client credentials.

## 05.8 — Signing-key rotation

- **Issuer config answers "which private key do I sign with now?"** Service config answers **"which public keys do I trust?"** After the code change, rotation is new keys plus config changes, with no JWT code changes.
- **`kid` selects a key, it never authenticates.** A missing, empty, non-string, or unknown `kid` gets 401. So does a token signed with key-1 that claims `kid=key-2`. A `kid` is a dictionary lookup, never a path or URL.
- **The order is non-negotiable:** the service trusts the new key, then the issuer switches, then the old key is retired after old tokens expire. Switching the issuer first breaks every new token. We hit exactly this live.
- **Retired vs expired:** a retired-key token fails with `UnknownKeyIdError`. An expired token fails with `ExpiredSignatureError` *after* the signature check passes, which proves that key is still trusted.

---

## Milestones

| | Milestone | Proved |
|---|---|---|
| 05.1 | JWT mechanics | A signature detects any edit. The algorithm is pinned and claims are required. |
| 05.2 | Service verification | A bearer token gives a verified `sub`, with 401 before SQLite |
| 05.3 | Separate issuer | The issuer decides `sub`, and only it holds the private key |
| 05.4 | Agent obtains its own token | Two-hop flow, with the client secret sent only to the issuer |
| 05.5 | Scopes and least privilege | The caller requests authority, the issuer bounds it, and the service enforces scope and role |
| 05.6 | Lifecycle | Reuse, renewal, one retry on 401, never retry on 403 |
| 05.7 | Revocation | Discussed and intentionally skipped. Short lifetimes are the current mitigation. |
| 05.8 | Key rotation | Overlap, then retirement, by config change only |
| 05.9 | Attack drill | Every layer fails safely under attack |

## 05.9 — The attack drill

`scripts/attack_drill.py` attacks every layer in-process, against the real issuer app, service app, and agent tool, with throwaway keys. It prints PASS or FAIL per attack. `tests/test_attack_drill.py` keeps it in the regular suite.

| Section | Checks | Every attack failed with |
|---|---|---|
| Authentication | 6 | Issuer 401, or the caller's chosen `sub` ignored |
| Token integrity | 6 | `InvalidSignatureError` (edited sub, scope, aud, or exp, or an attacker key), `DecodeError` (garbage) |
| Algorithms | 3 | `InvalidAlgorithmError` (none, HS256, RS512) |
| Claims | 9 | `MissingRequiredClaimError`, `InvalidIssuerError`, `InvalidAudienceError`, `ExpiredSignatureError` |
| Scope escalation | 14 | Issuer 403 or 400 (class_a, smuggled class_a, wildcard, prefix), service 403 (wrong, substring, uppercase, or empty scope) |
| Spoofing | 6 | 403. Role, identity, class, query, and API-key headers changed nothing. |
| Key rotation | 11 | `UnknownKeyIdError`, `MissingKeyIdError`, `InvalidSignatureError` for a mismatched kid. Overlap accepted both, retirement rejected key-1. |
| Lifecycle | 7 | Real agent tool: reuse, renewal, a rotation-triggered 401 renewed and retried once, 403 not retried, issuer outage handled |
| Leakage | 4 | Bodies only `{status, message}`, with no data, token, secret, or key, and no detail lookup |
| Isolation | 10 | A fresh process shows the agent loads none of sqlite3, inventory_service, token_issuer, or jwt. The service holds only public keys. |

**What the drill output taught us:**

- **Every attack maps to a distinct, logged reason class.** The service log alone tells you which attack was attempted, which is the raw material for monitoring and alerting. It never logs the token.
- **Defense in depth is visible in the logs.** A restricted identity holding a forged class A scope passed the scope check and was stopped by the role check (`role=restricted ... lacks inventory.read.class_a`). Either layer alone would have been enough.
- **Order of checks matters for what leaks.** Authentication failures stop before any SQLite access. Authorization failures read only the class metadata, never the protected details.
- **A real 401 drove the agent's retry path.** Rotating keys under a cached token produced `UnknownKeyIdError`, then one renewal, then success. This connected 05.6 and 05.8 without any mocking of the security code.

## Gotchas we actually hit

| Symptom | Cause | Lesson |
|---|---|---|
| curl returned 400 "Invalid HTTP request" | DEBUG prints went to standard output, so `$(issue_jwt.py)` captured three lines into the header | Data goes to standard output and diagnostics to standard error |
| Every valid token in tests got `InvalidSignatureError` | `conftest.py` was imported twice, as `conftest` and `tests.conftest`, creating two key pairs | Shared test state goes in a normal module (`tests/support.py`) |
| One test got 401 instead of 403 | The helper took `**headers`, so a stale `key=` keyword silently became a header | Make extra arguments explicit so typos raise errors |
| Fresh token still had the old `kid` | The issuer was not restarted after editing its config | Config is read at startup, so a rotation isn't done until each process restarts |
| Fresh key-2 token got 401 during the overlap | The service was not restarted after it was told to trust key-2 | The verifier must trust the new key before the issuer uses it |
| Saved token failed during the rotation | Five-minute lifetime | Short tokens limit damage and also limit how long a rotation can take |

## Limits to carry forward

- **A bearer token is usable by whoever holds it,** for its lifetime. Theft means impersonation until expiry. There's no revocation yet, no `jti`, and no sender binding.
- **Client secrets are static values in `.env` files.** Real systems use workload identity or managed secrets.
- **All processes run as one OS user,** so code tests prove separation, but the OS doesn't enforce it. Any process could read `~/secrets/keys/`.
- **Keys are files.** Production moves signing into a KMS and publishes public keys over JWKS, so verifiers fetch the trust set instead of reading config.
- **HTTP on localhost only.** Any real network needs TLS to protect tokens and secrets in transit.
