#!/usr/bin/env bash
# Set up (or check) everything A2A needs in one Google Cloud project.
# Idempotent: anything that already exists is left alone and reported as "already
# exists", never recreated and never a failure. Safe to rerun at any time.
#
#   scripts/setup_google_project.sh PROJECT_ID [--region us-central1]   # first time only
#   scripts/setup_google_project.sh [--upload-secrets] [--only STEPS]     # every time after
#
# The first run saves GCP_PROJECT_ID and GCP_REGION to infra/.env (git-ignored), after
# confirming you can access the project, and IDENTITY_FIRESTORE_PROJECT to
# identity_service/.env. Every script after that uses the saved project. Passing a
# different PROJECT_ID or --region later is refused, never applied.
#
# --upload-secrets adds a FIRST version to a secret that has none, from local files:
#   a2a-google-oauth-client-secret  <- GOOGLE_CLIENT_SECRET in identity_service/.env
#   a2a-identity-signing-key        <- ~/secrets/keys/identity-key-1-private.pem
# It never replaces an existing version and never prints a value.
#
# Layout:
#   infra/gcp-setup/        generic library, shared across projects (no A2A knowledge)
#   infra/config.sh         A2A names and settings
#   infra/*.sh              A2A steps composed from library calls
#
# This creates infrastructure only. Building the image and deploying Cloud Run services
# is scripts/deploy_cloud_run.sh.

INFRA="$(cd "$(dirname "${BASH_SOURCE[0]}")/../infra" && pwd)"
# shellcheck source=infra/config.sh
source "$INFRA/config.sh"
# shellcheck source=infra/gcp-setup/gcp-setup.sh
source "$INFRA/gcp-setup/gcp-setup.sh"
# shellcheck source=infra/identity_service.sh
source "$INFRA/identity_service.sh"
# shellcheck source=infra/oauth_client.sh
source "$INFRA/oauth_client.sh"
# shellcheck source=infra/image.sh
source "$INFRA/image.sh"

step_apis()              { gcp_setup_apis "${REQUIRED_APIS[@]}"; }
step_firestore()         { gcp_setup_firestore "$FIRESTORE_DATABASE" "${FIRESTORE_LOCATION:-$GCP_REGION}"; }
step_artifact_registry() { gcp_setup_artifact_registry "$ARTIFACT_REPO" "$GCP_REGION" "A2A service images"; }
step_local_env() {
  gcp_section "local identity_service/.env"
  gcp_dotenv_set "$IDENTITY_ENV_FILE" IDENTITY_FIRESTORE_PROJECT "$GCP_PROJECT_ID"
  gcp_dotenv_set "$IDENTITY_ENV_FILE" IDENTITY_FIRESTORE_DATABASE "$FIRESTORE_DATABASE"
}

STEPS=(
  apis=step_apis
  firestore=step_firestore
  artifact_registry=step_artifact_registry
  builder=a2a_setup_builder
  identity_service=a2a_setup_identity_service
  oauth_client=a2a_setup_oauth_client
  local_env=step_local_env
  # later days: inventory_service=...
)
GCP_STEP_NAMES="${STEPS[*]%%=*}"

gcp_parse_args "$@"
gcp_check_steps "${STEPS[@]}"
gcp_use_project setup
gcp_section "project $GCP_PROJECT_ID in $GCP_REGION"
gcp_require_project
gcp_save_project
gcp_run_steps "${STEPS[@]}"
gcp_summary
