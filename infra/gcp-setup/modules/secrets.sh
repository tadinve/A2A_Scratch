# shellcheck shell=bash
# gcp_setup_secret NAME READER_MEMBER [file PATH | dotenv FILE KEY]
#   The secret, read access for exactly one member, and (with --upload-secrets) a first
#   value from a local file or a dotenv key. An existing value is never replaced.
gcp_setup_secret() {
  local name="$1" reader="$2" source="${3:-}"
  gcp_ensure_secret "$name"
  gcp_ensure_secret_accessor "$name" "$reader"
  case "$source" in
    file)   gcp_ensure_secret_value_from_file "$name" "$4" ;;
    dotenv) gcp_ensure_secret_value_from_dotenv "$name" "$4" "$5" ;;
    "")     ;;
    *)      gcp_die "gcp_setup_secret $name: unknown value source '$source' (file | dotenv)" ;;
  esac
}
