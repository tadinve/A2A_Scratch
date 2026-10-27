# Day 08 — Learnings: Firestore State and the Identity Service on Cloud Run

**Built:**

- **Google only.** Password login was removed.
- **State in Firestore.** Users, Google links and pending logins moved there.
- **Repeatable setup and deploy.** Two idempotent, modular scripts set up a GCP project and deploy to Cloud Run.
- **On Cloud Run.** The Identity Service runs there with a dedicated service account, with its secrets in Secret Manager, over public HTTPS.

**Final architecture:**

```
Browser ──HTTPS──▶ Cloud Run a2a-identity-service (min 0, max 1)   runs as SA a2a-identity-service
                     ├─ env:    GOOGLE_CLIENT_ID, GOOGLE_REDIRECT_URI, IDENTITY_FIRESTORE_*
                     ├─ secret: GOOGLE_CLIENT_SECRET   (Secret Manager -> env var)
                     ├─ secret: /secrets/identity/signing-key.pem  (Secret Manager -> file)
                     └─ Firestore (roles/datastore.user): identity_users, identity_external_identities,
                                                          identity_oauth_transactions (TTL expire_at)
Image: Artifact Registry a2a/a2a-services:<git sha>[-dirty-<hash>], built by Cloud Build as SA a2a-builder
```

**Evidence:**

- **Sign-in:** a real Google sign-in through Cloud Run returned `human_sub: user-001`.
- **Local verification:** `verify_human_jwt.py` verified that token on a laptop with the public key only.
- **Unlinked account:** another Google account got 403 `account_not_allowed`.
- **Logs:** Cloud Logging shows `callback?[redacted]`.
- **Secrets:** the service settings show the client secret and the signing key only as Secret Manager references.
- **Idempotency:** a repeat deploy reported `already exists` and `already deployed`.
- **Tests:** 439 passed and 29 skipped. The 29 are Firestore contract tests that run only against the emulator.

---

## 08.1 — Cloud native means no local state

- A Cloud Run instance can be replaced at any moment and its disk is temporary. **Anything that must survive goes in a managed store.** With min 0, an instance disappears whenever the service is idle.
- **Pending logins in Firestore** mean a restart or a second instance no longer breaks a login in progress. The atomic claim is a Firestore transaction (get + delete), so a callback is still single-use across instances.
- **Firestore TTL** deletes expired transactions in the background. It can take a day or more, so the code still checks `expires_at` itself.
- **Store outage = 503 `identity_store_unavailable`**, with a 5s timeout. If the store is down, sign-in fails closed rather than skipping the link check.
- **One interface, two backends:** memory for tests, Firestore in the cloud. The same contract tests run against both (Firestore via the emulator, with a `demo-` project so no real project can be touched).

## 08.2 — Idempotent infrastructure scripts

- **Check, then create; "already exists" is success.** Rerunning any script is safe and prints `exists ... already exists` per resource, never an error.
- **Generic library + project config:**
  - `infra/gcp-setup/` knows no project. It is ready to split into its own repo with `git subtree split`.
  - `infra/config.sh` and `infra/*.sh` hold the A2A-specific names, roles and secrets.
- **Steps run by name** (`--only firestore`). Each one is safe to repeat.
- **Choose the project once.** The setup script saves `GCP_PROJECT_ID` and `GCP_REGION` to `infra/.env`. Every other script reads them, and stops with "run the setup first" if they are missing. Every gcloud call passes `--project` explicitly and never relies on the global gcloud project.
- **Existing secret versions are never replaced.** Secret values are never printed or passed on a command line; they are read from a file or from `.env` on stdin.

## 08.3 — One image, many services

- Every A2A service shares one image. **`SERVICE_APP`** picks the ASGI app at start-up. Dependencies come only from `uv.lock` (`--frozen`), and the container runs as a non-root user.
- **`.dockerignore` is a security control.** It keeps `.env` files, `*.pem` keys, data, tests and `.git` out of the build context. Secrets reach the container only from Secret Manager at runtime.
- **The tag is the git sha**, with `-dirty-<hash of changes>` when there are uncommitted changes. The same content is built once, and different content never reuses an old image.
- **Cloud Build runs as `a2a-builder`**, a service account with only the roles it needs (`artifactregistry.writer`, `logging.logWriter`, `storage.objectViewer`), instead of the broad default build account.

## 08.4 — Deploying to Cloud Run

- **Least-privilege runtime identity:** the `a2a-identity-service` service account has `roles/datastore.user` and read access to exactly two secrets.
- **Secrets two ways:** the client secret as an env var (`secretKeyRef`), and the signing key as a mounted file pointed to by `IDENTITY_PRIVATE_KEY_PATH`.
- **Scale defaults for every service: min 0, max 1.** That means no idle cost, at the price of a cold start.
- **Skip unchanged deploys.** A fingerprint of image + settings is kept as a service label, so an unchanged deploy is skipped. Env vars and secrets are *set*, not merged, so the service always matches the script exactly.
- **Deterministic URL** `https://SERVICE-PROJECTNUMBER.REGION.run.app` is known before the first deploy, so the OAuth redirect URI can be built into the deploy. The service also answers on an older hash-style URL. **Use one host only:** the login cookie is bound to a host, so starting on one URL and returning to the other fails with `invalid_login_transaction`.

---

## Gotchas we actually hit

| Symptom | Cause | Lesson |
|---|---|---|
| Cloud Build failed: `dial tcp ... i/o timeout` on `COPY --from=ghcr.io/astral-sh/uv` | A transient network failure reaching a second registry | Fewer external sources mean fewer failure points: install uv from PyPI. Surface the build's own log tail, not "BUILD FAILURE". |
| `Layer already exists` in a failed build counted as success | "already exists" matched in the build output | Builds and deploys use a strict wrapper; only creates treat "already exists" as success |
| gcloud `WARNING: filter keys were not present` leaked into output | Read calls let gcloud's stderr through | Silence stderr on read calls, but still stop with a clear message on real failure |
| Two URLs printed for one service | gcloud reports the hash URL | Always report the deterministic URL |
| Two signing-key volumes in the service spec | `--set-secrets` replaced the mount but kept the old volume | Harmless (only one is mounted), but each settings change leaves another one |
| Cloud sign-in got 403 at first | The new cloud Firestore was empty; the old links were elsewhere | A new store needs its users and links seeded (`identity_users.py add`, `google_enroll.py --link`) |
| `GCP_PROJECT_ID: unbound variable` | The script was run while it was half-edited | Rerun after edits finish; `set -u` catches it immediately |
| Two pytest warnings | Starlette's httpx deprecation, and google-genai on Python 3.14 | Third-party, not our code; nothing to fix |

The project used is a temporary Qwiklabs lab. To start again elsewhere:

1. Delete `infra/.env` and run `scripts/setup_google_project.sh <project>`.
2. Create an OAuth client in that project.
3. Seed Alice.
4. Deploy.
