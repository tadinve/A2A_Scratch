# shellcheck shell=bash
# A2A step: the Google sign-in OAuth client and consent screen have no public API for
# creating them, so this checks what it can locally and lists the console steps.

a2a_setup_oauth_client() {
  local console="https://console.cloud.google.com/auth" p="?project=$GCP_PROJECT_ID"
  gcp_section "Google sign-in OAuth client (console only)"
  if gcp_dotenv_has "$IDENTITY_ENV_FILE" GOOGLE_CLIENT_ID && gcp_dotenv_has "$IDENTITY_ENV_FILE" GOOGLE_CLIENT_SECRET; then
    gcp_log exists "OAuth client already configured in identity_service/.env ($console/clients$p)"
    return
  fi
  gcp_log todo "branding:   $console/branding$p"
  gcp_log todo "audience:   $console/audience$p  (External, Testing, add test users)"
  gcp_log todo "scopes:     $console/scopes$p  (openid, userinfo.email only)"
  gcp_log todo "client:     $console/clients$p  (Web application, redirect URI"
  gcp_log todo "            $IDENTITY_LOCAL_REDIRECT_URI), then put GOOGLE_CLIENT_ID and"
  gcp_log todo "            GOOGLE_CLIENT_SECRET in identity_service/.env"
}
