# Day 07 — Learnings: Google Sign-In (OIDC) for a Human

**Built:** Alice signs in with Google instead of a password. The Identity Service (:8002) runs the OIDC authorization-code flow with PKCE, verifies Google's ID token, maps the Google account to `user-001` through an explicit link, and issues the same human JWT the agent already trusts (iss `a2a-human-identity-service`, aud `inventory-agent`, RS256, kid `identity-key-1`, 300s).

**Final architecture:**

```
Browser ──GET /auth/google──▶ Identity Service :8002   new transaction {state, nonce, PKCE verifier} + cookie
   ◀──302 to Google (code_challenge S256, state, nonce, scope "openid email")──┘
Browser ──sign in──▶ Google ──302 /auth/google/callback?code&state──▶ Identity Service
                       claim transaction (single use) -> exchange code + verifier -> verify ID token
                       -> Google sub -> link -> user-001 enabled? -> human JWT
```

**Evidence:**

- A real Google sign-in returned `human_sub: user-001`.
- With that token the agent got 200 on WIDGET-B and 403 on WIDGET-A.
- The access log showed `/auth/google/callback?[redacted]`.
- 446 tests passed against a mocked Google; that count included the password tests later removed on Day 08.

---

## 07.1 — OIDC is OAuth 2.0 plus an ID token

- **OAuth answers "may this app call an API?"; OIDC adds "who is the user?"** The answer is the signed **ID token**, checked like any JWT:
  - signature from Google's JWKS;
  - `iss` is Google;
  - `aud` is our client ID;
  - `exp`;
  - `nonce`;
  - `email_verified`.
- **The authorization code is not the identity.** It is a one-time ticket the server exchanges, with the client secret, for tokens. The browser never sees the client secret or the tokens from Google.
- We request only `openid email`. We never call a Google API, so we ask for no API access.

## 07.2 — Three values, three different attacks

| Value | Stops | Where it lives |
|---|---|---|
| `state` | Login CSRF: an attacker's callback landing in your browser | Server-side transaction, compared on callback |
| `nonce` | Replay of an ID token from another login | Inside the ID token, compared with `hmac.compare_digest` |
| PKCE verifier (S256) | A stolen authorization code being redeemed by someone else | Server-side; only its SHA-256 challenge goes to Google |

- **Login transactions are server-side and single-use.** The cookie carries only an opaque binding id (HttpOnly, SameSite=Lax, Path=/auth/google, 5 minutes). The callback **claims** the transaction atomically before anything else, so a replayed callback finds nothing (400 `invalid_login_transaction`).
- The callback claims the transaction **even when Google returned an error** (`login_cancelled`). Otherwise an abandoned login would stay usable.

## 07.3 — Identity is the `sub`, never the email

- **Google's `sub` is stable and never reassigned.** An email can change owner or be shared, so it is unsafe as an identity. We store the email only as a hint for the operator.
- **Linking is explicit and operator-only** (`scripts/google_enroll.py --link user-001`): sign in once, confirm, write the link. Any account that isn't linked gets **403 `account_not_allowed`**, so signing in to Google is not enough to get in.
- One Google account maps to at most one user, and one user to at most one Google account; a conflict is refused.

## 07.4 — Errors are a contract

| Status | Code | When |
|---|---|---|
| 400 | `invalid_login_transaction` | Missing, unknown, expired or reused transaction; `state` mismatch |
| 400 | `login_cancelled` | Google returned `error=access_denied` |
| 401 | `google_authentication_failed` | Bad code, bad ID token, wrong nonce, unverified email |
| 403 | `account_not_allowed` | Not linked, or user disabled |
| 503 | `identity_provider_unavailable` | Google 5xx or network failure |

Bodies are always `{status, message, correlation_id}`. **One correlation id spans start and callback**: it is stored in the transaction, so both halves of a login can be found together in the logs.

## 07.5 — What never appears in a log

- Client secret, authorization code, tokens, `state`, `nonce` or PKCE verifier.
- **Uvicorn's access log prints full URLs**, and the callback URL contains `code` and `state`. A log filter rewrites `/auth/google…?<anything>` to `?[redacted]`.

---

## Gotchas we actually hit

| Symptom | Cause | Lesson |
|---|---|---|
| The injected test store was ignored | `store or TransactionStore()`: an *empty* store has `len 0`, so it is falsy | Use `is not None` when the default is a container |
| Start and callback had different correlation ids | Each request made its own | Carry it in the server-side transaction |
| A log-leak test failed on a clean app | The test client's own httpx logged the callback URL | Filter the assertion to the app's loggers |
| A route test missed the routes | `include_router` nests routes in `app.routes` | Ask `app.openapi()["paths"]` instead |
| A real client secret was pasted into `.env.example` | Edited the template instead of `.env` | `.env` is gitignored; the example holds placeholders only. Rotate any secret that lands in a tracked file. |
