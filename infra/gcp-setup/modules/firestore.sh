# shellcheck shell=bash
# gcp_setup_firestore DATABASE LOCATION   Native-mode database. Its location is permanent.
gcp_setup_firestore() {
  gcp_section "Firestore"
  gcp_ensure_firestore_database "$1" "$2"
}
