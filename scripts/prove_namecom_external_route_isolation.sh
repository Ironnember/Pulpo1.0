#!/usr/bin/env bash
set -euo pipefail

provider_host="${PULPO_EXTERNAL_PROVIDER_HOST:-api.dev.name.com}"
worker_network="pulpo-worker-external-route-v0-${GITHUB_RUN_ID}"
egress_network="pulpo-egress-external-route-v0-${GITHUB_RUN_ID}"
volume="pulpo-custody-external-route-v0-${GITHUB_RUN_ID}"
custody="pulpo-custody-external-route-v0-${GITHUB_RUN_ID}"
worker="pulpo-hostile-worker-external-route-v0-${GITHUB_RUN_ID}"
image="pulpo-custody-v0:${GITHUB_SHA}"

cleanup() {
  docker rm -f "$worker" "$custody" >/dev/null 2>&1 || true
  docker network rm "$worker_network" "$egress_network" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker network create --internal "$worker_network" >/dev/null
docker network create "$egress_network" >/dev/null
docker volume create "$volume" >/dev/null

# These values are explicit non-secret sentinels. They satisfy local runtime
# configuration only; no authenticated Name.com request is sent in this proof.
docker run -d \
  --name "$custody" \
  --network "$egress_network" \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  -v "$volume:/var/lib/pulpo:rw" \
  -e PULPO_CUSTODY_STATE_PATH=/var/lib/pulpo/custody.sqlite3 \
  -e PULPO_KERNEL_SECRET_HEX=1111111111111111111111111111111111111111111111111111111111111111 \
  -e PULPO_CUSTODY_SECRET_HEX=2222222222222222222222222222222222222222222222222222222222222222 \
  -e PULPO_AUTHORITY_PUBLIC_KEY_HEX=d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a \
  -e PULPO_AUTHORITY_ID=authority:external-route-test \
  -e PULPO_AUTHORITY_VERIFIER_ID=verifier:external-route-ed25519 \
  -e PULPO_AUTHORITY_KEY_ID=key:external-route-v0 \
  -e PULPO_AUTHORITY_DEPLOYMENT_ID=deployment:external-route-v0 \
  -e PULPO_AUTHORITY_MAX_TTL_SECONDS=300 \
  -e PULPO_PILOT_BUDGET_CENTS=3000 \
  -e PULPO_OWNER_REF=owner://iron-ember/external-route-test \
  -e NAMECOM_SANDBOX_USERNAME=pulpo-external-route-test \
  -e NAMECOM_SANDBOX_EXECUTOR_TOKEN=executor-token-not-real \
  -e NAMECOM_SANDBOX_OBSERVER_TOKEN=observer-token-not-real \
  "$image" >/dev/null

docker network connect "$worker_network" "$custody"

healthy=0
for _ in $(seq 1 30); do
  status="$(docker inspect -f '{{.State.Status}}' "$custody")"
  health="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$custody")"
  if [ "$status" = "exited" ] || [ "$status" = "dead" ]; then
    docker logs "$custody" >&2 || true
    exit 1
  fi
  if [ "$health" = "healthy" ]; then
    healthy=1
    break
  fi
  sleep 1
done
test "$healthy" = "1"

test "$(docker inspect -f '{{len .NetworkSettings.Networks}}' "$custody")" = "2"
test -z "$(docker port "$custody")"

# Positive control: custody resolves one current IPv4 and completes a
# certificate-validated TLS handshake. No HTTP request is sent.
provider_ip="$(docker exec "$custody" python -c '
import socket, ssl, sys
host = sys.argv[1]
infos = [
    item for item in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    if item[0] == socket.AF_INET
]
assert infos, "provider_ipv4_not_resolved"
ip = infos[0][4][0]
context = ssl.create_default_context()
with socket.create_connection((host, 443), timeout=5) as raw:
    with context.wrap_socket(raw, server_hostname=host) as tls:
        assert tls.version()
print(ip)
' "$provider_host")"
test -n "$provider_ip"

docker run -d \
  --name "$worker" \
  --network "$worker_network" \
  -e PROVIDER_HOST="$provider_host" \
  -e PROVIDER_IP="$provider_ip" \
  python:3.11-slim sleep 300 >/dev/null

test "$(docker inspect -f '{{len .NetworkSettings.Networks}}' "$worker")" = "1"

# Negative controls: worker can reach custody, holds no tested secrets, and
# cannot reach the same external provider by DNS or the exact resolved IPv4.
docker exec "$worker" python -c '
import os, socket, sys, urllib.request
custody_host = sys.argv[1]
forbidden = {
    "PULPO_KERNEL_SECRET_HEX",
    "PULPO_CUSTODY_SECRET_HEX",
    "PULPO_AUTHORITY_PUBLIC_KEY_HEX",
    "NAMECOM_SANDBOX_USERNAME",
    "NAMECOM_SANDBOX_EXECUTOR_TOKEN",
    "NAMECOM_SANDBOX_OBSERVER_TOKEN",
}
assert forbidden.isdisjoint(os.environ), sorted(forbidden.intersection(os.environ))
data = urllib.request.urlopen(f"http://{custody_host}:8080/health", timeout=2).read()
assert b"\"authority_effect\":\"none\"" in data
for target in (os.environ["PROVIDER_HOST"], os.environ["PROVIDER_IP"]):
    try:
        connection = socket.create_connection((target, 443), timeout=2)
    except OSError:
        continue
    else:
        connection.close()
        raise AssertionError("hostile worker unexpectedly reached external provider: " + target)
' "$custody"

printf 'external_provider_host=%s\n' "$provider_host"
printf 'custody_tls_positive_control=PASS\n'
printf 'worker_provider_dns_route=BLOCKED\n'
printf 'worker_provider_raw_ipv4_route=BLOCKED\n'
printf 'real_provider_credentials_used=NO\n'
printf 'authenticated_provider_request_sent=NO\n'
printf 'provider_mutation_attempted=NO\n'
