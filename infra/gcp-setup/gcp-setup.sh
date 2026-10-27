# shellcheck shell=bash
# gcp-setup: idempotent Google Cloud setup helpers, shared across projects.
# Consumers source this one file:   source path/to/gcp-setup/gcp-setup.sh
# See README.md for the contract and the available steps.
_gcp_setup_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=infra/gcp-setup/lib.sh
source "$_gcp_setup_dir/lib.sh"
for _gcp_module in "$_gcp_setup_dir"/modules/*.sh; do
  # shellcheck source=/dev/null
  source "$_gcp_module"
done
unset _gcp_module
