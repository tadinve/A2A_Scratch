# Day 08 (part 1): Google-only sign-in, state in Firestore

Password login is gone. The Identity Service has one way in, Google sign-in, and
keeps all of its state in Firestore instead of SQLite and `.env`:

| Collection | Document | Holds | Written by |
|---|---|---|---|
| `identity_users` | `user-001` | `enabled`, `display_name` | `scripts/identity_users.py` |
| `identity_external_identities` | `sha256(issuer \n sub)` | `issuer`, `subject`, `user_id`, `linked_by`, `linked_at` | `scripts/google_enroll.py --link` |
| `identity_oauth_transactions` | `sha256(cookie value)` | `state`, `nonce`, `code_verifier`, `correlation_id`, `expires_at`, `expire_at` | `/auth/google`; deleted by the callback |

What did NOT change: the Google flow and its checks, the error contract (plus one new
`503 identity_store_unavailable`), and the human JWT (`iss`, `sub=user-001`, `aud`,
`iat`, `exp`, RS256, `identity-key-1`, 300 s). The agent, delegation authority, token
issuer and inventory service are untouched.

## Why these choices

- **Links are data, not config.** `GOOGLE_ALICE_SUB` is gone. A link is a Firestore record
  written only after an operator sees the verified account and types `yes`. A second link
  for the same Google account, or a second Google account for the same user, is refused.
- **No database password.** Firestore access is IAM: locally your ADC login, on Cloud Run
  the service's own service account with `roles/datastore.user`.
- **Pending logins work across instances.** The callback claims its transaction in a
  Firestore transaction that reads and deletes it together, so only one of two
  concurrent callbacks wins, even on different instances. Only a hash of the cookie is
  stored, so someone who can read the database still can't rebuild a browser's cookie.
- **Fail closed.** If Firestore can't be reached, sign-in returns 503. It never falls back
  to "allow" and never issues a token.

## 1. Set up the Google Cloud project (project id given once; safe to rerun)

Use the same project as the OAuth client, or any project you own. **Not** the temporary
`qwiklabs-gcp-…` project.

```bash
scripts/setup_google_project.sh <your-project-id>   # FIRST run only: saves it to infra/.env
scripts/setup_google_project.sh --upload-secrets     # later runs: no project id; fills empty secrets
```

It enables the APIs, creates the Firestore database (Native mode; its location is
permanent), the Artifact Registry repository, the `a2a-identity-service` service account
with `roles/datastore.user`, the two secrets readable only by that account, and the TTL
policy that deletes abandoned logins. The project id and region are saved to `infra/.env`
(git-ignored) on the first run; every later script, including the deploy, reads them from
there and stops with "run setup first" if they're missing. Anything that exists is reported as `already exists`
and left alone. Run one part with `--only identity_service` (steps: apis, firestore,
artifact_registry, identity_service, oauth_client, local_env). The OAuth client can only
be made in the console; the script lists those steps as `todo`.

The generic helpers live in `infra/gcp-setup/` (shared-library candidate, see its README);
A2A's names are in `infra/config.sh`, and its steps in `infra/identity_service.sh` and
`infra/oauth_client.sh`.

## 2. Local credentials

```bash
gcloud auth application-default login
gcloud auth application-default set-quota-project <your-project-id>
```

Your user needs `roles/datastore.user` on the project. A project Owner already has it.

The setup script writes `IDENTITY_FIRESTORE_PROJECT` and `IDENTITY_FIRESTORE_DATABASE` into
`identity_service/.env` for you. Delete the old `GOOGLE_ALICE_SUB=` line there (nothing reads
it any more).

## 3. Create Alice and link her Google account

Stop the Identity Service first: enrollment listens on its callback port.

```bash
export UV_PROJECT_ENVIRONMENT="$HOME/venv/a2aS"
uv run python scripts/identity_users.py add user-001 --name Alice
uv run python scripts/google_enroll.py --link user-001     # pick Alice's account, type yes
uv run python scripts/identity_users.py list
```

## 4. Run and sign in

```bash
uv run uvicorn identity_service.app:app --host 127.0.0.1 --port 8002 --workers 1
```

The startup log shows `IDENTITY STORE firestore project=<id> database=(default)`. Then open
`http://localhost:8002/auth/google`. In the Firestore console, a document appears in
`identity_oauth_transactions` while you're at Google and disappears after the callback.

## Optional: the emulator

```bash
gcloud emulators firestore start --host-port=localhost:8085      # needs Java
export FIRESTORE_EMULATOR_HOST=localhost:8085
uv run pytest tests/test_identity_stores.py -v                    # runs the firestore half too
```

With `FIRESTORE_EMULATOR_HOST` set, the service and both scripts talk to the emulator, not
to real Firestore.

## Limits that remain

- `roles/datastore.user` covers every collection in the database. Keeping other apps'
  data out of reach means a separate project or database, or an IAM condition.
- `/auth/google` writes a document for every anonymous visit. The in-memory store was
  capped at 1000 pending logins; Firestore has no cap, so abuse costs writes. Cloud
  Run's instance limit and TTL cleanup bound it, and real rate limiting comes later.
- A stolen application JWT still works until it expires (5 minutes).

# Day 08 (part 2): the Identity Service on Cloud Run

Same code, same Firestore data (users and Google links enrolled locally are already there),
now behind a real HTTPS URL. Nothing about the human JWT changes.

| Piece | How it reaches the container |
|---|---|
| Code + dependencies | one image for all services (`Dockerfile`, `uv.lock`), `SERVICE_APP=identity_service.app:app` |
| `GOOGLE_CLIENT_ID`, redirect URI, Firestore project | plain env vars (identifiers, not secrets) |
| `GOOGLE_CLIENT_SECRET` | Secret Manager `a2a-google-oauth-client-secret`, as an env var |
| Signing private key | Secret Manager `a2a-identity-signing-key`, mounted at `/secrets/identity/signing-key.pem` |
| Firestore credentials | none: the service runs AS `a2a-identity-service`, which holds `roles/datastore.user` |

Scaling for every service: **min 0, max 1 instances** (library defaults). Public HTTPS,
because Alice's browser and Google's redirect must reach `/auth/google`.

## Steps

```bash
scripts/setup_google_project.sh --upload-secrets   # adds the a2a-builder account too
scripts/deploy_cloud_run.sh --only image           # build only (a few minutes)
```

Before the first sign-in, add the callback the deploy prints, of the form
`https://a2a-identity-service-<project-number>.<region>.run.app/auth/google/callback`,
to the OAuth client's **Authorized redirect URIs** (keep the localhost one). The URL is
deterministic, so this can be done before deploying.

```bash
scripts/deploy_cloud_run.sh                        # build if needed, then deploy
```

Rerunning with no code or config change reports `already exists` / `already deployed`.
Uncommitted changes produce a new `-dirty-<hash>` image tag, so they are built and deployed.

Optional local check of the image before building in the cloud:

```bash
docker build -t a2a-services .
docker run --rm -p 8002:8080 --env-file identity_service/.env \
  -e SERVICE_APP=identity_service.app:app -e IDENTITY_PRIVATE_KEY_PATH=/key.pem \
  -v ~/secrets/keys/identity-key-1-private.pem:/key.pem:ro \
  -v ~/.config/gcloud/application_default_credentials.json:/adc.json:ro \
  -e GOOGLE_APPLICATION_CREDENTIALS=/adc.json \
  a2a-services
```

`-p 8002:8080` keeps the browser on `localhost:8002`, so the existing redirect URI still works.
The two mounted files stand in for what Cloud Run provides: the key from Secret Manager and
the service account's identity. Neither is inside the image.
