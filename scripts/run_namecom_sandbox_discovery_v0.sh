#!/usr/bin/env bash
set -euo pipefail

# Interactive credential-bearing runner for authenticated read-only Name.com
# sandbox discovery. The provider currently exposes one Development/Test token
# surface to this account, so this proof authenticates that single credential
# and makes no executor/observer credential-separation claim.
#
# Secrets are read silently and are never accepted as CLI arguments, written to
# disk, echoed, or committed.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if [[ "${PULPO_NAMECOM_FIRE:-0}" != "0" ]]; then
  echo "BLOCKED: PULPO_NAMECOM_FIRE must remain 0 for discovery" >&2
  exit 2
fi

read -r -p "Name.com sandbox username (must end -test): " NAMECOM_SANDBOX_USERNAME
printf "Name.com sandbox Development/Test token: "
IFS= read -r -s NAMECOM_SANDBOX_TOKEN
printf "\n"

cleanup() {
  unset NAMECOM_SANDBOX_USERNAME || true
  unset NAMECOM_SANDBOX_TOKEN || true
}
trap cleanup EXIT

export NAMECOM_SANDBOX_USERNAME
export NAMECOM_SANDBOX_TOKEN
export PULPO_NAMECOM_FIRE=0

if [[ -z "${GITHUB_SHA:-}" ]]; then
  GITHUB_SHA="$(git rev-parse HEAD)"
  export GITHUB_SHA
fi

python3 scripts/prove_namecom_sandbox_discovery_v0.py

artifact=".pulpo-artifacts/namecom-sandbox-discovery.json"
if [[ ! -f "$artifact" ]]; then
  echo "BLOCKED: sanitized discovery artifact missing" >&2
  exit 2
fi

printf "\nSanitized evidence artifact: %s\n" "$artifact"
printf "No provider write was authorized or attempted by this runner.\n"
printf "Distinct executor/observer provider credentials are not claimed by this proof.\n"
