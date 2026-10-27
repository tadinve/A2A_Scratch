# shellcheck shell=bash
# Cloud Run: build an image with Cloud Build, and deploy a service. Idempotent:
#   - an image tag that already exists in Artifact Registry is not rebuilt
#   - a service already running this image with exactly these settings is not redeployed
#     (a fingerprint of the settings is kept in the service label gcp_setup_fingerprint)
# Scaling defaults for EVERY service: min GCP_RUN_MIN_INSTANCES (0), max GCP_RUN_MAX_INSTANCES (1).
# Compatible with macOS's bash 3.2: empty arrays are expanded as ${a[@]+"${a[@]}"}.

gcp_image_uri() {   # gcp_image_uri REPO NAME   -> REGION-docker.pkg.dev/PROJECT/REPO/NAME
  printf '%s-docker.pkg.dev/%s/%s/%s' "$GCP_REGION" "$GCP_PROJECT_ID" "$1" "$2"
}

# gcp_source_tag DIR: the commit's short sha for a clean checkout. With uncommitted
# changes: sha-dirty-<hash of those changes>, so the same content always gets the same
# tag and is built once, while different content never reuses an old image.
gcp_source_tag() {
  local dir="$1" sha changes
  sha="$(git -C "$dir" rev-parse --short=12 HEAD 2>/dev/null)" || gcp_die "$dir is not a git checkout with a commit"
  changes="$(git -C "$dir" status --porcelain)"
  if [[ -z "$changes" ]]; then printf '%s' "$sha"; return; fi
  printf '%s-dirty-%s' "$sha" "$(
    { git -C "$dir" diff HEAD --binary
      git -C "$dir" ls-files --others --exclude-standard
      git -C "$dir" ls-files --others --exclude-standard -z | (cd "$dir" && xargs -0 cat 2>/dev/null)
    } | shasum -a 256 | cut -c1-10)"
}

# gcp_build_image IMAGE_URI TAG CONTEXT_DIR BUILDER_SA_EMAIL
#   Builds CONTEXT_DIR/Dockerfile with Cloud Build as BUILDER_SA (not the broad default
#   build account) and pushes IMAGE_URI:TAG. Skipped when that tag already exists.
gcp_build_image() {
  local image="$1" tag="$2" context="$3" builder="$4" cfg
  if gcp_cmd artifacts docker images describe "$image:$tag" >/dev/null 2>&1; then
    gcp_log exists "image $image:$tag already exists"
    return
  fi
  cfg="$(mktemp)"
  cat >"$cfg" <<EOF
steps:
  - name: gcr.io/cloud-builders/docker
    args: ["build", "--tag", "$image:$tag", "."]
images: ["$image:$tag"]
serviceAccount: projects/$GCP_PROJECT_ID/serviceAccounts/$builder
options:
  logging: CLOUD_LOGGING_ONLY
EOF
  gcp_log working "building $image:$tag with Cloud Build (a few minutes)"
  if gcp_apply_strict builds submit "$context" --config="$cfg" --region="$GCP_REGION"; then
    rm -f "$cfg"
  else
    rm -f "$cfg"
    gcp_build_failure_log
    gcp_fail "image build failed"
  fi
  gcp_log built "image $image:$tag"
}

# Replace gcloud's generic "BUILD FAILURE" with the end of that build's own log.
# Builds log to Cloud Logging only (CLOUD_LOGGING_ONLY), which can lag a few seconds.
gcp_build_failure_log() {
  local id tail attempt
  id="$(grep -Eo 'builds/[0-9a-f-]{36}' <<<"$GCP_APPLY_ERROR" | tail -n 1)"
  id="${id#builds/}"
  [[ -n "$id" ]] || return 0
  for attempt in 1 2 3; do
    tail="$(gcp_cmd logging read "resource.type=\"build\" AND resource.labels.build_id=\"$id\"" \
              --format='value(textPayload)' --order=asc --limit=2000 2>/dev/null | grep -v '^[[:space:]]*$' | tail -n 25 || true)"
    [[ -n "$tail" ]] && break
    sleep 5
  done
  GCP_APPLY_ERROR="--- last lines of build $id ---
${tail:-(log not available yet)}
--- full log: https://console.cloud.google.com/cloud-build/builds;region=$GCP_REGION/$id?project=$GCP_PROJECT_ID"
}

# gcp_run_url SERVICE: the service's deterministic URL, known BEFORE the first deploy.
gcp_run_url() {
  local number
  number="$(gcp_cmd projects describe "$GCP_PROJECT_ID" --format='value(projectNumber)')"
  printf 'https://%s-%s.%s.run.app' "$1" "$number" "$GCP_REGION"
}

# gcp_deploy_cloud_run SERVICE --image URI:TAG --service-account EMAIL
#     [--env KEY=VALUE]...                 plain settings (never secrets)
#     [--secret KEY=SECRET:VERSION]...     secret as an env var
#     [--secret /path/file=SECRET:VERSION]...  secret mounted as a file
#     [--public | --private] [--min-instances N] [--max-instances N] [--memory 512Mi]
# The env vars and secrets given REPLACE the service's current ones, so the deployed
# service always matches this call exactly. --private is the default.
gcp_deploy_cloud_run() {
  local service="$1"; shift
  local image="" sa="" auth="--no-allow-unauthenticated" memory="512Mi"
  local min="$GCP_RUN_MIN_INSTANCES" max="$GCP_RUN_MAX_INSTANCES"
  local envs=() secrets=() item joined fingerprint current url
  while (($#)); do
    case "$1" in
      --image) image="$2"; shift 2 ;;
      --service-account) sa="$2"; shift 2 ;;
      --env) envs+=("$2"); shift 2 ;;
      --secret) secrets+=("$2"); shift 2 ;;
      --public) auth="--allow-unauthenticated"; shift ;;
      --private) auth="--no-allow-unauthenticated"; shift ;;
      --min-instances) min="$2"; shift 2 ;;
      --max-instances) max="$2"; shift 2 ;;
      --memory) memory="$2"; shift 2 ;;
      *) gcp_die "gcp_deploy_cloud_run $service: unknown option $1" ;;
    esac
  done
  [[ -n "$image" && -n "$sa" ]] || gcp_die "gcp_deploy_cloud_run $service: --image and --service-account are required"

  gcp_section "Cloud Run $service"
  fingerprint="$(printf '%s\n' "image=$image" "sa=$sa" "auth=$auth" "min=$min" "max=$max" "memory=$memory" \
                   ${envs[@]+"${envs[@]}"} -- ${secrets[@]+"${secrets[@]}"} | shasum -a 256 | cut -c1-40)"
  current="$(gcp_cmd run services describe "$service" --region="$GCP_REGION" \
               --format='value(metadata.labels.gcp_setup_fingerprint)' 2>/dev/null || true)"
  # Always report the deterministic URL: a service also answers on an older hash-style
  # URL, but host-bound things (cookies, OAuth redirect URIs) should use one host only.
  url="$(gcp_run_url "$service")"
  if [[ "$current" == "$fingerprint" ]]; then
    gcp_log exists "cloud run $service already deployed with this image and settings ($url)"
    return
  fi

  local args=(run deploy "$service" --image="$image" --region="$GCP_REGION" --service-account="$sa"
              "$auth" --ingress=all --min-instances="$min" --max-instances="$max" --memory="$memory"
              --update-labels="gcp_setup_fingerprint=$fingerprint")
  # ^@@^ switches gcloud's list delimiter from "," to "@@", so values may contain commas.
  joined=""; for item in ${envs[@]+"${envs[@]}"}; do joined+="${joined:+@@}$item"; done
  if [[ -n "$joined" ]]; then args+=("--set-env-vars=^@@^$joined"); else args+=(--clear-env-vars); fi
  joined=""; for item in ${secrets[@]+"${secrets[@]}"}; do joined+="${joined:+@@}$item"; done
  if [[ -n "$joined" ]]; then args+=("--set-secrets=^@@^$joined"); else args+=(--clear-secrets); fi

  gcp_log working "deploying cloud run $service (min $min, max $max instances)"
  gcp_apply_strict "${args[@]}" || gcp_fail "deploy of cloud run $service failed"
  gcp_log deployed "cloud run $service -> $url (min $min, max $max, $([[ $auth == --allow-unauthenticated ]] && echo public || echo private))"
}
