#!/usr/bin/env bash
set -euo pipefail

run_id="${GITHUB_RUN_ID:-local-$(date +%Y%m%d%H%M%S)-$$}"
sha="${GITHUB_SHA:-local}"
worker_network="pulpo-worker-route-${run_id}"
provider_network="pulpo-provider-route-${run_id}"
volume="pulpo-custody-route-${run_id}"
custody="pulpo-custody-route-${run_id}"
provider="pulpo-provider-route-${run_id}"
worker="pulpo-hostile-worker-route-${run_id}"
custody_image="${PULPO_CUSTODY_IMAGE:-pulpo-custody-v0:${sha}}"
python_image="${PULPO_PROOF_PYTHON_IMAGE:-python:3.11-slim}"

created_worker_network=0
created_provider_network=0
created_volume=0

cleanup() {
  docker rm -f "$worker" "$custody" "$provider" >/dev/null 2>&1 || true
  if [ "$created_worker_network" = "1" ]; then
    docker network rm "$worker_network" >/dev/null 2>&1 || true
  fi
  if [ "$created_provider_network" = "1" ]; then
    docker network rm "$provider_network" >/dev/null 2>&1 || true
  fi
  if [ "$created_volume" = "1" ]; then
    docker volume rm "$volume" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

docker image inspect "$custody_image" >/dev/null
if ! docker image inspect "$python_image" >/dev/null 2>&1; then
  docker pull "$python_image" >/dev/null
fi

docker network create --internal "$worker_network" >/dev/null
created_worker_network=1
docker network create --internal "$provider_network" >/dev/null
created_provider_network=1
docker volume create "$volume" >/dev/null
created_volume=1

test "$(docker network inspect -f '{{.Internal}}' "$worker_network")" = "true"
test "$(docker network inspect -f '{{.Internal}}' "$provider_network")" = "true"

docker run -d   --pull=never   --name "$provider"   --network "$provider_network"   --read-only   --tmpfs /tmp:rw,noexec,nosuid,size=16m   --cap-drop ALL   --security-opt no-new-privileges:true   "$python_image"   python -c '
from http.server import BaseHTTPRequestHandler, HTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/probe":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"provider-route-ok")
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, *_args):
        return

HTTPServer(("0.0.0.0", 8081), Handler).serve_forever()
' >/dev/null

docker run -d   --pull=never   --name "$custody"   --network "$provider_network"   --read-only   --tmpfs /tmp:rw,noexec,nosuid,size=16m   --cap-drop ALL   --security-opt no-new-privileges:true   -v "$volume:/var/lib/pulpo:rw"   -e PULPO_CUSTODY_STATE_PATH=/var/lib/pulpo/custody.sqlite3   -e PULPO_KERNEL_SECRET_HEX=1111111111111111111111111111111111111111111111111111111111111111   -e PULPO_CUSTODY_SECRET_HEX=2222222222222222222222222222222222222222222222222222222222222222   -e PULPO_AUTHORITY_PUBLIC_KEY_HEX=d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a   -e PULPO_AUTHORITY_ID=authority:container-route-test   -e PULPO_AUTHORITY_VERIFIER_ID=verifier:container-route-ed25519   -e PULPO_AUTHORITY_KEY_ID=key:container-route-v1   -e PULPO_AUTHORITY_DEPLOYMENT_ID=deployment:container-route-v1   -e PULPO_AUTHORITY_MAX_TTL_SECONDS=300   -e PULPO_PILOT_BUDGET_CENTS=3000   -e PULPO_OWNER_REF=owner://iron-ember/container-route-test   -e NAMECOM_SANDBOX_USERNAME=pulpo-container-route-test   -e NAMECOM_SANDBOX_EXECUTOR_TOKEN=executor-token-not-real   -e NAMECOM_SANDBOX_OBSERVER_TOKEN=observer-token-not-real   "$custody_image" >/dev/null

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

test "$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$custody")" = "true"
docker exec "$custody" sh -c 'test "$(id -u)" -ne 0'
docker exec "$custody" sh -c 'test -f /var/lib/pulpo/custody.sqlite3'
test -z "$(docker port "$custody")"
test -z "$(docker port "$provider")"
test "$(docker inspect -f '{{len .NetworkSettings.Networks}}' "$custody")" = "2"
test "$(docker inspect -f '{{len .NetworkSettings.Networks}}' "$provider")" = "1"

provider_ready=0
for _ in $(seq 1 20); do
  if docker exec "$custody" python -c "
import urllib.request
data = urllib.request.urlopen(
    'http://$provider:8081/probe',
    timeout=2,
).read()
assert data == b'provider-route-ok'
"; then
    provider_ready=1
    break
  fi
  sleep 1
done
test "$provider_ready" = "1"

provider_ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$provider")"
test -n "$provider_ip"

docker run -d   --pull=never   --name "$worker"   --network "$worker_network"   --read-only   --tmpfs /tmp:rw,noexec,nosuid,size=16m   --cap-drop ALL   --security-opt no-new-privileges:true   --pids-limit 64   -e PROVIDER_IP="$provider_ip"   "$python_image"   python -c 'import time; time.sleep(300)' >/dev/null

test "$(docker inspect -f '{{len .NetworkSettings.Networks}}' "$worker")" = "1"

docker exec "$worker" python -c "
import os
import socket
import urllib.error
import urllib.request

forbidden = {
    'PULPO_KERNEL_SECRET_HEX',
    'PULPO_CUSTODY_SECRET_HEX',
    'PULPO_AUTHORITY_PUBLIC_KEY_HEX',
    'NAMECOM_SANDBOX_EXECUTOR_TOKEN',
    'NAMECOM_SANDBOX_OBSERVER_TOKEN',
}
assert forbidden.isdisjoint(os.environ), sorted(forbidden.intersection(os.environ))
assert not os.path.exists('/var/lib/pulpo/custody.sqlite3')
assert not os.path.exists('/var/run/docker.sock')

data = urllib.request.urlopen(
    'http://$custody:8080/health',
    timeout=2,
).read()
assert b'\"authority_effect\":\"none\"' in data

for path in ('/docs', '/redoc', '/openapi.json'):
    try:
        urllib.request.urlopen(
            'http://$custody:8080' + path,
            timeout=2,
        )
    except urllib.error.HTTPError as exc:
        assert exc.code == 404
    else:
        raise AssertionError(path + ' unexpectedly exposed')

for host, label in (
    ('$provider', 'provider_dns_route'),
    (os.environ['PROVIDER_IP'], 'provider_raw_ip_route'),
):
    try:
        connection = socket.create_connection((host, 8081), timeout=1)
    except OSError:
        print(label + '_blocked: PASS')
        continue
    connection.close()
    raise AssertionError(label + ' unexpectedly reachable by hostile worker')
"

echo "worker_to_custody: PASS"
echo "custody_to_provider: PASS"
echo "worker_to_provider_dns: DENIED"
echo "worker_to_provider_raw_ip: DENIED"
echo "exclusive_provider_route_isolation: PASS"
echo "scope: exact Docker proof topology only"
