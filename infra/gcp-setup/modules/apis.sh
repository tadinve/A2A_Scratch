# shellcheck shell=bash
# gcp_setup_apis API...   Enable the given APIs, then check billing.
gcp_setup_apis() {
  gcp_section "APIs"
  gcp_ensure_apis "$@"
  gcp_section "billing"
  gcp_check_billing
}
