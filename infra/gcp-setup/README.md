# gcp-setup

Idempotent Google Cloud setup helpers in bash, shared across projects. This directory
knows nothing about any one project: values arrive as arguments or `GCP_*` variables.
It's kept self-contained so it can be split into its own repo
(`git subtree split --prefix=infra/gcp-setup`) and consumed as a pinned submodule.

## Contract

Every `gcp_ensure_*` call prints one line and never fails because something exists:

| Status | Meaning |
|---|---|
| `exists` | already there: "... already exists", nothing changed |
| `created` / `enabled` / `granted` | was missing, made now |
| `warn` | exists but differs from what we'd create; left as is |
| `todo` | needs a human (e.g. a secret with no value yet) |
| `ok` | a check passed (project access, billing) |

- A create that races with an existing resource ("already exists") is reported as `exists`.
- gcloud's raw output is shown only when a command really fails; then the script stops.
- Every gcloud call names the project explicitly; the global gcloud project is never used.
- Secret values are never printed, echoed or passed on a command line, and an existing
  secret version is never replaced.

## Use from a project

```bash
source "path/to/gcp-setup/gcp-setup.sh"          # core + all modules

my_firestore() { gcp_setup_firestore "(default)" "$GCP_REGION"; }
my_service()   {
  gcp_setup_service_account my-api "My API runtime" roles/datastore.user
  gcp_setup_secret my-api-key "serviceAccount:$(gcp_sa_email my-api)" file ~/secrets/my-api-key
}

GCP_ENV_FILE="$PWD/infra/.env"                     # where the chosen project is saved
GCP_SETUP_HINT="scripts/setup.sh PROJECT_ID"
GCP_STEP_NAMES="apis firestore service"
gcp_parse_args "$@"                                 # [PROJECT_ID] [--region] [--upload-secrets] [--only]
gcp_use_project setup                               # deploy scripts: gcp_use_project use
gcp_require_project
gcp_save_project                                    # setup only: saves GCP_PROJECT_ID, GCP_REGION
gcp_run_steps apis=my_apis firestore=my_firestore service=my_service
gcp_summary
```

**The project is chosen once.** Only the setup script takes `PROJECT_ID`, and it saves it
(with the region) to `GCP_ENV_FILE` after confirming access. Every other script calls
`gcp_use_project use`, which reads the saved value and, if there is none, stops with
`GCP_SETUP_HINT`. A different `PROJECT_ID` or `--region` than the saved one is refused.

## Steps (modules/)

| Function | Creates |
|---|---|
| `gcp_setup_apis API...` | enabled APIs; checks billing |
| `gcp_setup_firestore DB LOCATION` | Native-mode Firestore database |
| `gcp_setup_artifact_registry REPO LOCATION [DESC]` | Docker repository |
| `gcp_setup_service_account NAME DISPLAY [ROLE...]` | service account + project roles |
| `gcp_setup_secret NAME READER [file PATH \| dotenv FILE KEY]` | secret, one reader, optional first value |

Lower-level helpers in `lib.sh`: `gcp_ensure_apis`, `gcp_ensure_firestore_database`,
`gcp_ensure_firestore_ttl`, `gcp_ensure_artifact_repo`, `gcp_ensure_service_account`,
`gcp_ensure_project_role`, `gcp_ensure_secret`, `gcp_ensure_secret_accessor`,
`gcp_ensure_secret_value_from_file`, `gcp_ensure_secret_value_from_dotenv`, plus
`gcp_cmd` (read-only gcloud) and `gcp_apply` (mutating gcloud with "already exists" = success).

New modules (e.g. Cloud Run deploys) follow the same contract.
