#!/usr/bin/env bash
# Build the A2A image and deploy Cloud Run services. Idempotent: an image tag that
# exists is not rebuilt, and a service already running this image with the same
# settings is not redeployed; both are reported as "already ...".
#
#   scripts/deploy_cloud_run.sh [--only STEPS]
#   scripts/deploy_cloud_run.sh --only identity_service
#
# The project and region come from infra/.env, saved once by
# scripts/setup_google_project.sh PROJECT_ID. With nothing saved, this stops there.
#
# Every service: min 0, max 1 instances (library defaults; see infra/config.sh).
# Run scripts/setup_google_project.sh first: it creates the repository, service
# accounts and secrets that these steps use.
#
# Image tag: the commit's short sha, plus -dirty-<hash> when there are uncommitted
# changes, so the same source is built once and new source never reuses an old image.

INFRA="$(cd "$(dirname "${BASH_SOURCE[0]}")/../infra" && pwd)"
# shellcheck source=infra/config.sh
source "$INFRA/config.sh"
# shellcheck source=infra/gcp-setup/gcp-setup.sh
source "$INFRA/gcp-setup/gcp-setup.sh"
# shellcheck source=infra/image.sh
source "$INFRA/image.sh"
# shellcheck source=infra/identity_service.sh
source "$INFRA/identity_service.sh"

STEPS=(
  image=a2a_ensure_image
  identity_service=a2a_deploy_identity_service
  # later days: inventory_service=..., inventory_agent=...
)
GCP_STEP_NAMES="${STEPS[*]%%=*}"
GCP_PROJECT_USAGE=""                      # no PROJECT_ID: it comes from infra/.env

gcp_parse_args "$@"
gcp_check_steps "${STEPS[@]}"
gcp_use_project use
gcp_section "project $GCP_PROJECT_ID in $GCP_REGION"
gcp_require_project
gcp_run_steps "${STEPS[@]}"
gcp_summary
