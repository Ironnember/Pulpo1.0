#!/bin/sh
set -eu

export AWS_PAGER=""
umask 077

if ! command -v aws >/dev/null 2>&1; then
  echo "aws CLI not found" >&2
  exit 2
fi

region="${PULPO_AWS_REGION:-${AWS_REGION:-${AWS_DEFAULT_REGION:-}}}"
if [ -z "$region" ]; then
  region="$(aws configure get region 2>/dev/null || true)"
fi
if [ -z "$region" ]; then
  echo "No AWS region configured. Set PULPO_AWS_REGION or AWS_REGION." >&2
  exit 3
fi

run_id="$(date -u +%Y%m%dT%H%M%SZ)"
root="${PULPO_AGENTCORE_DISCOVERY_DIR:-build/agentcore-readonly-discovery}"
out="$root/$run_id"
mkdir -p "$out"

printf '%s\n' "$region" > "$out/region.txt"
aws sts get-caller-identity --output json > "$out/caller-identity.json"
aws bedrock-agentcore-control list-gateways --region "$region" --output json > "$out/gateways.json"
aws bedrock-agentcore-control list-agent-runtimes --region "$region" --output json > "$out/runtimes.json"

python3 - "$out" "$region" <<'PY'
import json
import pathlib
import subprocess
import sys

out = pathlib.Path(sys.argv[1])
region = sys.argv[2]

identity = json.loads((out / "caller-identity.json").read_text())
gateways = json.loads((out / "gateways.json").read_text())
runtimes = json.loads((out / "runtimes.json").read_text())

summary = {
    "schema": "pulpo.agentcore-readonly-discovery.v0",
    "authority_effect": "none",
    "aws_resource_effect": "none",
    "provider_effect": "none",
    "region": region,
    "account": identity.get("Account"),
    "caller_arn": identity.get("Arn"),
    "gateways": [],
    "runtimes": [],
}

for item in gateways.get("items", []):
    gid = item.get("gatewayId")
    if not gid:
        continue
    raw = subprocess.check_output([
        "aws","bedrock-agentcore-control","get-gateway",
        "--gateway-identifier",gid,
        "--region",region,
        "--output","json",
    ])
    gateway = json.loads(raw)
    summary["gateways"].append({
        "gateway_id": gateway.get("gatewayId"),
        "gateway_arn": gateway.get("gatewayArn"),
        "gateway_url": gateway.get("gatewayUrl"),
        "role_arn": gateway.get("roleArn"),
        "authorizer_type": (gateway.get("authorizerType") or gateway.get("authorizerConfiguration")),
    })

for item in runtimes.get("agentRuntimes", []):
    rid = item.get("agentRuntimeId")
    if not rid:
        continue
    raw = subprocess.check_output([
        "aws","bedrock-agentcore-control","get-agent-runtime",
        "--agent-runtime-id",rid,
        "--region",region,
        "--output","json",
    ])
    runtime = json.loads(raw)
    summary["runtimes"].append({
        "runtime_id": runtime.get("agentRuntimeId"),
        "runtime_arn": runtime.get("agentRuntimeArn"),
        "role_arn": runtime.get("roleArn"),
        "status": runtime.get("status"),
    })

(out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
print(out / "summary.json")
PY
