# shellcheck shell=bash
# A2A's Google Cloud settings. PROJECT-SPECIFIC: this file is not part of the gcp-setup
# library (infra/gcp-setup/), which only receives these values as arguments.
# Every value can be overridden from the environment, e.g. GCP_REGION=europe-west1.

A2A_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# The project id and region are chosen ONCE, by scripts/setup_google_project.sh PROJECT_ID,
# and saved here (git-ignored). Every other script reads them from this file.
GCP_ENV_FILE="$A2A_ROOT/infra/.env"
GCP_SETUP_HINT="scripts/setup_google_project.sh PROJECT_ID"

: "${GCP_REGION:=us-central1}"
: "${FIRESTORE_DATABASE:=(default)}"
# Firestore's location is permanent once created; defaults to GCP_REGION.
: "${FIRESTORE_LOCATION:=}"
: "${ARTIFACT_REPO:=a2a}"

# APIs every later day needs. cloudresourcemanager is what reads/writes project IAM.
REQUIRED_APIS=(
  serviceusage.googleapis.com
  cloudresourcemanager.googleapis.com
  iam.googleapis.com
  iamcredentials.googleapis.com
  firestore.googleapis.com
  secretmanager.googleapis.com
  artifactregistry.googleapis.com
  cloudbuild.googleapis.com
  run.googleapis.com
)

# --- Identity Service (Day 08) -----------------------------------------------
IDENTITY_ENV_FILE="$A2A_ROOT/identity_service/.env"
IDENTITY_SA="a2a-identity-service"
IDENTITY_SA_DISPLAY="A2A Identity Service (Cloud Run runtime)"
IDENTITY_PROJECT_ROLES=(roles/datastore.user)          # Firestore read/write; nothing else
IDENTITY_SECRET_GOOGLE_CLIENT="a2a-google-oauth-client-secret"
IDENTITY_SECRET_SIGNING_KEY="a2a-identity-signing-key"
: "${IDENTITY_SIGNING_KEY_FILE:=$HOME/secrets/keys/identity-key-1-private.pem}"
IDENTITY_TTL_COLLECTION="identity_oauth_transactions"
IDENTITY_TTL_FIELD="expire_at"
IDENTITY_LOCAL_REDIRECT_URI="http://localhost:8002/auth/google/callback"

# --- Image build (Day 08) -----------------------------------------------------
# One image for all services; SERVICE_APP picks the app. Built by a dedicated
# Cloud Build account that can push images and write logs, nothing more.
A2A_IMAGE_NAME="a2a-services"
BUILD_SA="a2a-builder"
BUILD_SA_DISPLAY="A2A image builder (Cloud Build)"
BUILD_SA_ROLES=(roles/artifactregistry.writer roles/logging.logWriter roles/storage.objectViewer)

# --- Cloud Run (Day 08) -------------------------------------------------------
# Scaling: every service uses the library defaults, min 0 / max 1 instances
# (GCP_RUN_MIN_INSTANCES / GCP_RUN_MAX_INSTANCES). Override per step only on purpose.
IDENTITY_RUN_SERVICE="a2a-identity-service"
IDENTITY_RUN_KEY_PATH="/secrets/identity/signing-key.pem"
