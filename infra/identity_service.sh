# shellcheck shell=bash
# A2A step: everything the Identity Service needs except its Cloud Run service itself.
# Built only from gcp-setup library calls; the names come from infra/config.sh.
#
# Its service account gets ONLY roles/datastore.user (project) and read access to its
# own two secrets. No inventory data, no other secrets, no admin roles.

a2a_setup_identity_service() {
  local member
  member="serviceAccount:$(gcp_sa_email "$IDENTITY_SA")"

  gcp_setup_service_account "$IDENTITY_SA" "$IDENTITY_SA_DISPLAY" "${IDENTITY_PROJECT_ROLES[@]}"

  gcp_section "Identity Service: secrets"
  gcp_setup_secret "$IDENTITY_SECRET_GOOGLE_CLIENT" "$member" dotenv "$IDENTITY_ENV_FILE" GOOGLE_CLIENT_SECRET
  gcp_setup_secret "$IDENTITY_SECRET_SIGNING_KEY" "$member" file "$IDENTITY_SIGNING_KEY_FILE"

  gcp_section "Identity Service: Firestore"
  gcp_ensure_firestore_ttl "$FIRESTORE_DATABASE" "$IDENTITY_TTL_COLLECTION" "$IDENTITY_TTL_FIELD"
}

# The Identity Service on Cloud Run: public HTTPS (Alice's browser and Google must reach
# it), its own service account, the Google client secret as an env var and the signing
# key as a mounted file, both from Secret Manager. Scaling: library defaults (min 0, max 1).
a2a_deploy_identity_service() {
  local url client_id
  a2a_ensure_image
  url="$(gcp_run_url "$IDENTITY_RUN_SERVICE")"
  client_id="$(gcp_dotenv_get "$IDENTITY_ENV_FILE" GOOGLE_CLIENT_ID || true)"
  [[ -n "$client_id" && "$client_id" != replace-with* ]] \
    || gcp_die "GOOGLE_CLIENT_ID missing from identity_service/.env"

  gcp_deploy_cloud_run "$IDENTITY_RUN_SERVICE" \
    --image "$A2A_IMAGE_REF" \
    --service-account "$(gcp_sa_email "$IDENTITY_SA")" \
    --public \
    --env "SERVICE_APP=identity_service.app:app" \
    --env "GOOGLE_CLIENT_ID=$client_id" \
    --env "GOOGLE_REDIRECT_URI=$url/auth/google/callback" \
    --env "IDENTITY_FIRESTORE_PROJECT=$GCP_PROJECT_ID" \
    --env "IDENTITY_FIRESTORE_DATABASE=$FIRESTORE_DATABASE" \
    --env "IDENTITY_PRIVATE_KEY_PATH=$IDENTITY_RUN_KEY_PATH" \
    --secret "GOOGLE_CLIENT_SECRET=$IDENTITY_SECRET_GOOGLE_CLIENT:latest" \
    --secret "$IDENTITY_RUN_KEY_PATH=$IDENTITY_SECRET_SIGNING_KEY:latest"

  gcp_log note "the Google OAuth client must list $url/auth/google/callback as a redirect URI"
  gcp_log note "sign in at $url/auth/google"
}
