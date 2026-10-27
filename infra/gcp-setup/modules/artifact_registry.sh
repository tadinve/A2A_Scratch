# shellcheck shell=bash
# gcp_setup_artifact_registry REPO LOCATION [DESCRIPTION]   Docker repository for service images.
gcp_setup_artifact_registry() {
  gcp_section "Artifact Registry"
  gcp_ensure_artifact_repo "$@"
}
