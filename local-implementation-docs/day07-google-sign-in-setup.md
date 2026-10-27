# Day 07: Google sign-in for Alice, tested locally

> **Updated in Day 08:** password login was removed, and users, the Alice link and pending
> logins moved to Firestore. `GOOGLE_ALICE_SUB` is no longer read: links are written by
> `scripts/google_enroll.py --link user-001`. See [day08-firestore-identity-setup.md](day08-firestore-identity-setup.md).
> The Google client setup below (section 1) is unchanged.

Alice signs in with Google in her browser. The Identity Service (port 8002) checks
Google's answer, looks up the ONE explicitly linked internal user (`user-001`), and
issues the same application human JWT that `POST /login` issues. Google keeps
Alice's Google password; our services never see it. Nothing is deployed.

## What talks to what

| Credential | Issued by / audience | Who uses it |
|---|---|---|
| Authorization code | Google; bound to our client and redirect URI | Identity Service exchanges it once |
| Google ID token | Google / our `GOOGLE_CLIENT_ID` | Identity Service validates it, then drops it |
| Google access token | Google | Nobody: discarded on arrival |
| Application human JWT | `a2a-human-identity-service` / `inventory-agent` | Inventory Agent (unchanged) |
| Machine and delegation JWTs | unchanged | unchanged |

The link key is `(https://accounts.google.com, Google sub)`. It is never the email.

| Module | Job |
|---|---|
| `identity_service/google_login.py` | `GET /auth/google`, `GET /auth/google/callback`, error contract, access-log redaction |
| `identity_service/google_oidc.py` | Discovery, PKCE authorization URL and code exchange (Authlib), ID-token checks (PyJWT + cached JWKS) |
| `identity_service/oauth_transactions.py` | Server-side state/nonce/verifier, 5-minute expiry, claimed exactly once |
| `identity_service/external_identities.py` | `GOOGLE_ALICE_SUB` -> `user-001`; malformed or ambiguous links stop startup |
| `scripts/google_enroll.py` | Operator-only: shows a verified `sub` and email, mints nothing |

## 1. Google Cloud console (once)

1. **Google Auth Platform > Branding**: app name, support email.
2. **Audience**: *External*, publishing status *Testing*. Under **Test users**, add the
   real Google account you choose to represent Alice. (Optional: add a second account to
   prove the unlinked-account 403.)
3. **Data access**: scopes `openid` and `.../auth/userinfo.email` only. Do not enable
   the Gmail or Drive APIs.
4. **Clients > Create client**: type **Web application**. Under *Authorized redirect URIs*
   add exactly `http://localhost:8002/auth/google/callback`. No JavaScript origins.
5. Copy the client ID and client secret.

## 2. Local configuration

```bash
cp identity_service/.env.example identity_service/.env
chmod 600 identity_service/.env
# edit: GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET. Leave GOOGLE_ALICE_SUB empty for now.
```

`identity_service/.env` is git-ignored. The secret is used only server-side for the code
exchange. It does not sign anything; our RSA key `identity-key-1` signs our JWT.

## 3. Enroll Alice's Google subject (operator only)

Stop the Identity Service if it is running: the enrollment CLI listens on its callback.

```bash
export UV_PROJECT_ENVIRONMENT="$HOME/venv/a2aS"
uv run python scripts/google_enroll.py
```

Pick Alice's account. The terminal prints the verified `subject` and `email`. If it is
the intended account, put `GOOGLE_ALICE_SUB=<subject>` in `identity_service/.env`.

## 4. Run the five services

One terminal each, all from the repo root, all with `UV_PROJECT_ENVIRONMENT` set:

```bash
uv run uvicorn inventory_service.app:app    --host 127.0.0.1 --port 8000
uv run uvicorn token_issuer.app:app         --host 127.0.0.1 --port 8001
uv run uvicorn identity_service.app:app     --host 127.0.0.1 --port 8002 --workers 1
uv run uvicorn inventory_agent.app:app      --host 127.0.0.1 --port 8003
uv run uvicorn delegation_authority.app:app --host 127.0.0.1 --port 8004
```

The Identity Service log should show `GOOGLE SIGN-IN client_id=... linked_users=['user-001']`.
Pending logins live in memory: one worker only, and a restart cancels them.

## 5. Sign in

Open **http://localhost:8002/auth/google** (localhost, not 127.0.0.1, for the whole attempt).
Choose Alice's account. The browser shows:

```json
{"status": "authenticated", "human_sub": "user-001", "token_type": "Bearer",
 "expires_in": 300, "access_token": "<application human JWT>"}
```

Use the token within 5 minutes; don't save it to a file:

```bash
TOKEN='<paste access_token>'
uv run python scripts/verify_human_jwt.py "$TOKEN"
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8003/agent/stock/WIDGET-B
unset TOKEN
```

## Error contract

| Condition | Response |
|---|---|
| Missing, mismatched, expired or reused transaction; missing code | 400 `invalid_login_transaction` |
| Alice cancels at Google (valid transaction) | 400 `login_cancelled` |
| Rejected code exchange or invalid ID token | 401 `google_authentication_failed` |
| Unlinked Google subject, or disabled internal account | 403 `account_not_allowed` |
| Google timeout/outage, or keys unavailable | 503 `identity_provider_unavailable` |

Each login gets one `correlation_id`. The `GOOGLE LOGIN STARTED` line and its callback's
`OK`/`FAILED` line (`outcome`, `stage`, `user_id`) share it, and so does an error body.
A callback with no valid transaction gets a fresh id, since it can't be tied to a start. Codes, tokens, state, nonce and the
PKCE verifier are never logged, and the access log prints `/auth/google/callback?[redacted]`.

## Limits that remain

- A stolen application JWT still works until it expires (5 minutes). Google sign-in doesn't change that.
- `Secure=false` on the transaction cookie is allowed only because the redirect URI is `http://localhost`.
  An `https` redirect URI automatically makes it `Secure`.
- Pending-login storage is per process. Several instances would need shared storage.
