# shellcheck shell=bash
# gcp-setup core: reusable, IDEMPOTENT helpers for Google Cloud setup. Source it; don't run it.
# Knows nothing about any one project: every value arrives as an argument or a GCP_* variable.
#
# Contract for every gcp_ensure_* function, each printing one status line:
#   - already there  -> "exists   <resource> already exists"; nothing changed, never a failure
#   - missing        -> "created  <resource>" (or enabled / granted)
#   - a create that races with an existing resource ("already exists") is reported as exists
#   - an existing resource that differs from what we'd create -> "warn", never a failure
#   - gcloud's own raw output appears only when a command really fails
#
# Secret VALUES are never printed, echoed or passed on a command line.
# Pipelines are avoided around `grep -q`: with pipefail, grep exiting early can
# SIGPIPE gcloud and turn a match into a failure. Output is captured first instead.
#
# Inputs (set by the caller, or by gcp_parse_args + gcp_use_project):
#   GCP_PROJECT_ID       chosen once at setup, then read from GCP_ENV_FILE
#   GCP_REGION           default us-central1
#   GCP_UPLOAD_SECRETS   1 lets gcp_ensure_secret_value_* add a FIRST version
#   GCP_ONLY             comma-separated step names for gcp_run_steps (empty = all)
#   GCP_RUN_MIN_INSTANCES / GCP_RUN_MAX_INSTANCES   Cloud Run scaling defaults: 0 and 1

[[ -n "${_GCP_SETUP_LIB:-}" ]] && return 0
_GCP_SETUP_LIB=1
set -euo pipefail

: "${GCP_REGION:=us-central1}"
: "${GCP_UPLOAD_SECRETS:=0}"
: "${GCP_ONLY:=}"
: "${GCP_RUN_MIN_INSTANCES:=0}"
: "${GCP_RUN_MAX_INSTANCES:=1}"
GCP_CHANGES=0
GCP_TODOS=0
GCP_APPLIED=""
GCP_APPLY_ERROR=""

# --- output -------------------------------------------------------------------
gcp_section() { printf '\n== %s\n' "$*"; }
gcp_log() {   # gcp_log STATUS MESSAGE
  # STATUS: ok | exists | created | enabled | granted | built | deployed | saved | todo | warn | note | working
  case "$1" in
    created|enabled|granted|built|deployed|saved) GCP_CHANGES=$((GCP_CHANGES + 1)) ;;
    todo) GCP_TODOS=$((GCP_TODOS + 1)) ;;
  esac
  printf '  %-8s %s\n' "$1" "$2"
}
gcp_die() { printf 'error: %s\n' "$*" >&2; exit 1; }
gcp_summary() {
  printf '\n'
  if ((GCP_CHANGES == 0)); then printf 'Up to date: everything already exists'
  else printf '%d change(s) made' "$GCP_CHANGES"; fi
  if ((GCP_TODOS)); then printf ', %d manual step(s) listed above' "$GCP_TODOS"; fi
  printf '.\n'
}

# --- arguments, preflight, steps ----------------------------------------------
gcp_usage() {   # optional: GCP_STEP_NAMES (space-separated) to list valid --only values
  cat <<EOF
usage: $(basename "$0") ${GCP_PROJECT_USAGE:-[PROJECT_ID]} [--region REGION] [--upload-secrets] [--only STEP[,STEP...]]

  PROJECT_ID          given once, to the setup script; saved to ${GCP_ENV_FILE:-the project env file}
  --region REGION     location for regional resources (first setup only; default: $GCP_REGION)
  --upload-secrets    add first secret versions from local sources if a secret has none
  --only STEPS        run only these steps${GCP_STEP_NAMES:+: ${GCP_STEP_NAMES// /, }}
EOF
}

GCP_PROJECT_ARG=""
GCP_REGION_ARG=""
gcp_parse_args() {
  while (($#)); do
    case "$1" in
      --region) [[ $# -ge 2 ]] || gcp_die "--region needs a value"; GCP_REGION_ARG="$2"; shift 2 ;;
      --upload-secrets) GCP_UPLOAD_SECRETS=1; shift ;;
      --only) [[ $# -ge 2 ]] || gcp_die "--only needs step names"; GCP_ONLY="$2"; shift 2 ;;
      -h|--help) gcp_usage; exit 0 ;;
      -*) gcp_die "unknown option: $1" ;;
      *) [[ -z "$GCP_PROJECT_ARG" ]] || gcp_die "only one PROJECT_ID may be given"; GCP_PROJECT_ARG="$1"; shift ;;
    esac
  done
  export GCP_UPLOAD_SECRETS GCP_ONLY
}

# --- the project is chosen ONCE ----------------------------------------------
# The setup script saves GCP_PROJECT_ID and GCP_REGION to GCP_ENV_FILE (git-ignored);
# every later script reads them from there. Inputs set by the project's config:
#   GCP_ENV_FILE     where they are saved, e.g. infra/.env
#   GCP_SETUP_HINT   what to tell the user when nothing is saved yet
#
# gcp_use_project setup|use
#   setup: use the saved project; or, if none, the PROJECT_ID argument (saved later by
#          gcp_save_project, once gcp_require_project proved it exists).
#   use:   the saved project only; if none, stop and point to the setup script.
# A PROJECT_ID or --region that differs from the saved one is refused, never applied.
gcp_use_project() {
  local mode="$1" saved_project saved_region
  [[ -n "${GCP_ENV_FILE:-}" ]] || gcp_die "GCP_ENV_FILE is not set by the project's config"
  saved_project="$(gcp_dotenv_get "$GCP_ENV_FILE" GCP_PROJECT_ID 2>/dev/null || true)"
  saved_region="$(gcp_dotenv_get "$GCP_ENV_FILE" GCP_REGION 2>/dev/null || true)"

  if [[ -n "$saved_project" ]]; then
    if [[ -n "$GCP_PROJECT_ARG" && "$GCP_PROJECT_ARG" != "$saved_project" ]]; then
      gcp_die "this checkout is set up for project $saved_project (in $GCP_ENV_FILE), not $GCP_PROJECT_ARG. To switch, delete GCP_PROJECT_ID from that file and run setup again."
    fi
    GCP_PROJECT_ID="$saved_project"
  elif [[ "$mode" == setup ]]; then
    [[ -n "$GCP_PROJECT_ARG" ]] || { printf 'No project set up yet: pass PROJECT_ID once.\n\n' >&2; gcp_usage >&2; exit 2; }
    GCP_PROJECT_ID="$GCP_PROJECT_ARG"
  else
    gcp_die "no project set up yet: run ${GCP_SETUP_HINT:-the setup script with PROJECT_ID} first"
  fi

  if [[ -n "$saved_region" ]]; then
    if [[ -n "$GCP_REGION_ARG" && "$GCP_REGION_ARG" != "$saved_region" ]]; then
      gcp_die "this checkout is set up for region $saved_region (in $GCP_ENV_FILE), not $GCP_REGION_ARG"
    fi
    GCP_REGION="$saved_region"
  elif [[ -n "$GCP_REGION_ARG" ]]; then
    GCP_REGION="$GCP_REGION_ARG"
  fi

  [[ "$GCP_PROJECT_ID" =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]$ ]] || gcp_die "not a valid project id: $GCP_PROJECT_ID"
  export GCP_PROJECT_ID GCP_REGION
}

# Save the project and region, after gcp_require_project confirmed access. Idempotent.
gcp_save_project() {
  gcp_section "local settings ($GCP_ENV_FILE)"
  gcp_dotenv_set "$GCP_ENV_FILE" GCP_PROJECT_ID "$GCP_PROJECT_ID"
  gcp_dotenv_set "$GCP_ENV_FILE" GCP_REGION "$GCP_REGION"
}

gcp_require_project() {
  command -v gcloud >/dev/null || gcp_die "gcloud is not installed"
  local account
  account="$(gcloud auth list --filter=status:ACTIVE --format='value(account)' 2>/dev/null || true)"
  [[ -n "$account" ]] || gcp_die "no active gcloud login: run 'gcloud auth login'"
  gcloud projects describe "$GCP_PROJECT_ID" --format='value(projectId)' >/dev/null 2>&1 \
    || gcp_die "project $GCP_PROJECT_ID not found, or $account cannot see it"
  gcp_log ok "project $GCP_PROJECT_ID as $account"
}

# gcp_check_steps NAME=FUNCTION ...  Fail fast on an --only name that isn't a step.
gcp_check_steps() {
  local spec wanted known=" "
  for spec in "$@"; do known+="${spec%%=*} "; done
  for wanted in ${GCP_ONLY//,/ }; do
    [[ "$known" == *" $wanted "* ]] || gcp_die "unknown step '$wanted' (steps:${known% })"
  done
}

# gcp_run_steps NAME=FUNCTION ...  Runs each in order, or only those named in GCP_ONLY.
gcp_run_steps() {
  local spec
  gcp_check_steps "$@"
  for spec in "$@"; do
    if [[ -z "$GCP_ONLY" || ",$GCP_ONLY," == *",${spec%%=*},"* ]]; then "${spec#*=}"; fi
  done
}

# --- running gcloud -----------------------------------------------------------
# Read-only calls: explicit project, never the global default.
gcp_cmd() { gcloud --project="$GCP_PROJECT_ID" --quiet "$@"; }

# Mutating calls. Output is captured, not shown. Sets GCP_APPLIED=created|existed and
# returns 0; "already exists" counts as success. On a real failure, returns 1 with the
# output kept in GCP_APPLY_ERROR for gcp_fail to show.
gcp_apply() {
  local out
  if out="$(gcp_cmd "$@" 2>&1)"; then GCP_APPLIED=created; return 0; fi
  if grep -Eqi 'already exists|ALREADY_EXISTS' <<<"$out"; then GCP_APPLIED=existed; return 0; fi
  GCP_APPLY_ERROR="$out"
  return 1
}
gcp_fail() { if [[ -n "$GCP_APPLY_ERROR" ]]; then printf '%s\n' "$GCP_APPLY_ERROR" >&2; fi; gcp_die "$*"; }

# Like gcp_apply, but "already exists" in the output is NOT success. For builds and
# deploys, whose logs say "Layer already exists" even when they fail.
gcp_apply_strict() {
  local out
  if out="$(gcp_cmd "$@" 2>&1)"; then GCP_APPLIED=created; return 0; fi
  GCP_APPLY_ERROR="$out"
  return 1
}

# Log the outcome of the last gcp_apply: a race with an existing resource is "exists".
gcp_applied() {   # gcp_applied STATUS RESOURCE
  if [[ "$GCP_APPLIED" == existed ]]; then gcp_log exists "$2 already exists"; else gcp_log "$1" "$2"; fi
}

# Retry (for IAM, which lags a few seconds behind a new service account).
gcp_retry() {
  local attempt=1
  until "$@"; do
    ((attempt >= 6)) && return 1
    sleep $((attempt * 5)); attempt=$((attempt + 1))
  done
}

# --- APIs and billing ---------------------------------------------------------
gcp_ensure_apis() {   # gcp_ensure_apis API...
  local enabled missing=() api
  enabled="$(gcp_cmd services list --enabled --format='value(config.name)')"
  for api in "$@"; do
    if grep -qx "$api" <<<"$enabled"; then gcp_log exists "api $api already enabled"; else missing+=("$api"); fi
  done
  if ((${#missing[@]})); then
    gcp_apply services enable "${missing[@]}" || gcp_fail "could not enable APIs: ${missing[*]}"
    for api in "${missing[@]}"; do gcp_log enabled "api $api"; done
  fi
}

gcp_check_billing() {
  local billing
  billing="$(gcloud billing projects describe "$GCP_PROJECT_ID" --format='value(billingEnabled)' 2>/dev/null || true)"
  case "$billing" in
    True|true) gcp_log ok "billing enabled" ;;
    False|false) gcp_log warn "billing is NOT enabled: Cloud Run, Artifact Registry and Cloud Build need it" ;;
    *) gcp_log warn "billing status not readable with this login; check the console if deploys fail" ;;
  esac
}

# --- Firestore ----------------------------------------------------------------
gcp_ensure_firestore_database() {   # gcp_ensure_firestore_database DATABASE LOCATION
  local db="$1" location="$2" found type loc
  if found="$(gcp_cmd firestore databases describe --database="$db" --format='value(type,locationId)' 2>/dev/null)"; then
    read -r type loc <<<"$found"
    if [[ "$type" != "FIRESTORE_NATIVE" ]]; then
      gcp_log warn "firestore database $db exists in $type mode (left as is); expected Native mode"
    elif [[ "$loc" != "$location" ]]; then
      gcp_log exists "firestore database $db already exists (native, $loc; kept, not $location)"
    else
      gcp_log exists "firestore database $db already exists (native, $loc)"
    fi
    return
  fi
  gcp_apply firestore databases create --database="$db" --location="$location" --type=firestore-native \
    || gcp_fail "could not create firestore database $db"
  gcp_applied created "firestore database $db (native, $location)"
}

gcp_ensure_firestore_ttl() {   # gcp_ensure_firestore_ttl DATABASE COLLECTION_GROUP FIELD
  local db="$1" group="$2" field="$3" listed
  listed="$(gcp_cmd firestore fields ttls list --database="$db" --collection-group="$group" \
              --format='value(name,ttlConfig.state)' 2>/dev/null || true)"
  if grep -Eq "/fields/${field}[[:space:]]+(ACTIVE|CREATING)" <<<"$listed"; then
    gcp_log exists "firestore TTL $group.$field already enabled"
    return
  fi
  # Enabling an already-enabled TTL is a no-op, so a stale or failed list is harmless.
  gcp_apply firestore fields ttls update "$field" --database="$db" --collection-group="$group" \
    --enable-ttl --async || gcp_fail "could not enable TTL on $group.$field"
  gcp_applied created "firestore TTL $group.$field (activates in the background)"
}

# --- Artifact Registry --------------------------------------------------------
gcp_ensure_artifact_repo() {   # gcp_ensure_artifact_repo REPO LOCATION [DESCRIPTION]
  local repo="$1" location="$2" description="${3:-container images}"
  if gcp_cmd artifacts repositories describe "$repo" --location="$location" >/dev/null 2>&1; then
    gcp_log exists "artifact registry $location/$repo already exists"
    return
  fi
  gcp_apply artifacts repositories create "$repo" --location="$location" --repository-format=docker \
    --description="$description" || gcp_fail "could not create artifact registry $location/$repo"
  gcp_applied created "artifact registry $location/$repo"
}

# --- service accounts and IAM -------------------------------------------------
gcp_sa_email() { printf '%s@%s.iam.gserviceaccount.com' "$1" "$GCP_PROJECT_ID"; }

gcp_ensure_service_account() {   # gcp_ensure_service_account NAME DISPLAY_NAME
  local name="$1" display="$2" email
  email="$(gcp_sa_email "$name")"
  if gcp_cmd iam service-accounts describe "$email" >/dev/null 2>&1; then
    gcp_log exists "service account $email already exists"
    return
  fi
  gcp_apply iam service-accounts create "$name" --display-name="$display" \
    || gcp_fail "could not create service account $email"
  gcp_applied created "service account $email"
}

gcp_ensure_project_role() {   # gcp_ensure_project_role MEMBER ROLE
  local member="$1" role="$2" found
  # 2>/dev/null: gcloud warns when the policy has no bindings yet; a real failure still stops.
  found="$(gcp_cmd projects get-iam-policy "$GCP_PROJECT_ID" --flatten='bindings[].members' \
             --filter="bindings.role=$role AND bindings.members=$member" --format='value(bindings.role)' 2>/dev/null)" \
    || gcp_die "could not read the IAM policy of project $GCP_PROJECT_ID"
  if [[ -n "$found" ]]; then gcp_log exists "$role -> $member already granted"; return; fi
  # add-iam-policy-binding is itself idempotent; retry covers a just-created account.
  gcp_retry gcp_apply projects add-iam-policy-binding "$GCP_PROJECT_ID" --member="$member" --role="$role" \
    --condition=None || gcp_fail "could not grant $role to $member"
  gcp_log granted "$role -> $member"
}

# --- Secret Manager -----------------------------------------------------------
gcp_ensure_secret() {   # gcp_ensure_secret NAME
  local name="$1"
  if gcp_cmd secrets describe "$name" >/dev/null 2>&1; then gcp_log exists "secret $name already exists"; return; fi
  gcp_apply secrets create "$name" --replication-policy=automatic || gcp_fail "could not create secret $name"
  gcp_applied created "secret $name (no value yet)"
}

gcp_secret_has_version() {
  local found
  found="$(gcp_cmd secrets versions list "$1" --filter='state=ENABLED' --limit=1 --format='value(name)' 2>/dev/null || true)"
  [[ -n "$found" ]]
}

# Add a first version from a file, only if the secret has none. Never replaces one.
gcp_ensure_secret_value_from_file() {   # gcp_ensure_secret_value_from_file NAME FILE
  local name="$1" file="$2"
  if gcp_secret_has_version "$name"; then gcp_log exists "secret $name already has a value (kept)"; return; fi
  if [[ "$GCP_UPLOAD_SECRETS" != 1 ]]; then
    gcp_log todo "secret $name has no value: rerun with --upload-secrets (source: $file)"; return
  fi
  if [[ ! -r "$file" ]]; then gcp_log warn "secret $name: $file not readable; not uploaded"; return; fi
  gcp_apply secrets versions add "$name" --data-file="$file" || gcp_fail "could not add a version to secret $name"
  gcp_log created "secret $name value from $file"
}

# Same, from KEY=value in a dotenv file. The value goes through a 0600 temp file, never argv.
gcp_ensure_secret_value_from_dotenv() {   # gcp_ensure_secret_value_from_dotenv NAME FILE KEY
  local name="$1" file="$2" key="$3" tmp
  if gcp_secret_has_version "$name"; then gcp_log exists "secret $name already has a value (kept)"; return; fi
  if [[ "$GCP_UPLOAD_SECRETS" != 1 ]]; then
    gcp_log todo "secret $name has no value: rerun with --upload-secrets (source: $key in $file)"; return
  fi
  if ! gcp_dotenv_has "$file" "$key"; then
    gcp_log warn "secret $name: no real $key in $file; not uploaded"; return
  fi
  tmp="$(mktemp)"; chmod 600 "$tmp"
  sed -n "s/^${key}=//p" "$file" | tail -n 1 | tr -d '\r' \
    | sed -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'$/\1/" | tr -d '\n' >"$tmp"
  if gcp_apply secrets versions add "$name" --data-file="$tmp"; then
    rm -f "$tmp"
  else
    rm -f "$tmp"; gcp_fail "could not add a version to secret $name"
  fi
  gcp_log created "secret $name value from $key in $file"
}

gcp_ensure_secret_accessor() {   # gcp_ensure_secret_accessor NAME MEMBER
  local name="$1" member="$2" role="roles/secretmanager.secretAccessor" found
  # 2>/dev/null: gcloud warns when the policy has no bindings yet; a real failure still stops.
  found="$(gcp_cmd secrets get-iam-policy "$name" --flatten='bindings[].members' \
             --filter="bindings.role=$role AND bindings.members=$member" --format='value(bindings.role)' 2>/dev/null)" \
    || gcp_die "could not read the IAM policy of secret $name"
  if [[ -n "$found" ]]; then gcp_log exists "secret $name already readable by $member"; return; fi
  gcp_retry gcp_apply secrets add-iam-policy-binding "$name" --member="$member" --role="$role" \
    || gcp_fail "could not let $member read secret $name"
  gcp_log granted "secret $name readable by $member"
}

# --- local files --------------------------------------------------------------
# gcp_dotenv_get FILE KEY: print a NON-SECRET value (an id, a URL). Never use it for secrets:
# those go through gcp_ensure_secret_value_from_dotenv, which never puts them in argv.
gcp_dotenv_get() {
  [[ -r "$1" ]] || return 1
  sed -n "s/^$2=//p" "$1" | tail -n 1 | tr -d '\r' | sed -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'$/\1/"
}

# gcp_dotenv_set FILE KEY VALUE: write a NON-SECRET setting, idempotently.
#   same value -> exists; missing, empty or placeholder -> saved; a DIFFERENT real
#   value -> warn and leave it (someone set it on purpose). New files are 0600.
gcp_dotenv_set() {
  local file="$1" key="$2" value="$3" current tmp
  current="$(gcp_dotenv_get "$file" "$key" 2>/dev/null || true)"
  if [[ "$current" == "$value" ]]; then gcp_log exists "$key=$value already set in $file"; return; fi
  if [[ -n "$current" && "$current" != replace-with* ]]; then
    gcp_log warn "$key in $file is $current, not $value (left as is)"; return
  fi
  if [[ ! -e "$file" ]]; then
    mkdir -p "$(dirname "$file")"; (umask 077; : >"$file")
  fi
  if grep -q "^$key=" "$file"; then
    tmp="$(mktemp)"
    awk -v k="$key" -v v="$value" 'index($0, k "=") == 1 { print k "=" v; next } { print }' "$file" >"$tmp"
    cat "$tmp" >"$file"; rm -f "$tmp"            # cat keeps the file's owner and mode
  else
    if [[ -s "$file" && -n "$(tail -c 1 "$file")" ]]; then printf '\n' >>"$file"; fi
    printf '%s=%s\n' "$key" "$value" >>"$file"
  fi
  gcp_log saved "$key=$value in $file"
}

gcp_dotenv_has() {   # gcp_dotenv_has FILE KEY: true if KEY has a non-placeholder value
  local value
  [[ -r "$1" ]] || return 1
  value="$(sed -n "s/^$2=//p" "$1" | tail -n 1)"
  [[ -n "$value" && "$value" != replace-with* ]]
}
