# shellcheck shell=bash
# gcp_setup_service_account NAME DISPLAY_NAME [ROLE...]
#   A dedicated runtime identity (e.g. for one Cloud Run service) holding exactly these
#   project roles. Its IAM member string is "serviceAccount:$(gcp_sa_email NAME)".
gcp_setup_service_account() {
  local name="$1" display="$2" member role
  shift 2
  member="serviceAccount:$(gcp_sa_email "$name")"
  gcp_section "service account $name"
  gcp_ensure_service_account "$name" "$display"
  for role in "$@"; do gcp_ensure_project_role "$member" "$role"; done
}
