# shellcheck shell=bash
# A2A step: the one container image all services run, tagged by source content.

A2A_IMAGE_REF=""

a2a_setup_builder() {
  gcp_setup_service_account "$BUILD_SA" "$BUILD_SA_DISPLAY" "${BUILD_SA_ROLES[@]}"
}

# Build once per source state; later calls in the same run reuse the result.
a2a_ensure_image() {
  [[ -n "$A2A_IMAGE_REF" ]] && return 0
  local image tag
  image="$(gcp_image_uri "$ARTIFACT_REPO" "$A2A_IMAGE_NAME")"
  tag="$(gcp_source_tag "$A2A_ROOT")"
  gcp_section "image"
  gcp_build_image "$image" "$tag" "$A2A_ROOT" "$(gcp_sa_email "$BUILD_SA")"
  A2A_IMAGE_REF="$image:$tag"
}
