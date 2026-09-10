#!/usr/bin/env bash
set -euo pipefail

worker_network="pulpo-worker-route-v0-${GITHUB_RUN_ID}"
provider_network="pulpo-provider-route-v0-${GITHUB_RUN_ID}"
volume="pulpo-custody-route-v0-${GITHUB_RUN_ID}"
custody="pulpo-custody-route-v0-${GITHUB_RUN_ID}"
provider="pulpo-provider-route-v0-${GITHUB_RUN_ID}"
worker="pulpo-hostile-worker-route-v0-${GITHUB_RUN_ID}"
image="pulpo-custody-v0:${GITHUB_SHA}"
provider_script="${RUNNER_TEMP}/pulpo-provider-route-v0.py"

cat > "$provider_script" <<'PY'
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
PY

docker network create --internal "$worker_network" >/dev/null
docker network create --internal "$provider_network" >/dev/null
docker volume create "$volume" >/dev/null
cleanup() {
  docker rm -f "$worker" "$custody" "$provider" >/dev/null 2>&1 || true
  docker network rm "$worker_network" "$provider_network" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
  rm -f "$provider_script"
}
trap cleanup EXIT

docker run -d \
  --name "$provider" \
  --network "$provider_network" \
  -v "$provider_script:/provider.py:ro" \
  python:3.11-slim python /provider.py >/dev/null

docker run -d \
  --name "$custody" \
  --network "$provider_network" \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  -v "$volume:/var/lib/pulpo:rw" \
  -e PULPO_CUSTODY_STATE_PATH=/var/lib/pulpo/custody.sqlite3 \
  -e PULPO_KERNEL_SECRET_HEX=1111111111111111111111111111111111111111111111111111111111111111 \
  -e PULPO_CUSTODY_SECRET_HEX=2222222222222222222222222222222222222222222222222222222222222222 \
  -e PULPO_AUTHORITY_PUBLIC_KEY_HEX=d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a \
  -e PULPO_AUTHORITY_ID=authority:container-route-test \
  -e PULPO_AUTHORITY_VERIFIER_ID=verifier:container-route-ed25519 \
  -e PULPO_AUTHORITY_KEY_ID=key:container-route-v0 \
  -e PULPO_AUTHORITY_DEPLOYMENT_ID=deployment:container-route-v0 \
  -e PULPO_AUTHORITY_MAX_TTL_SECONDS=300 \
  -e PULPO_PILOT_BUDGET_CENTS=3000 \
  -e PULPO_OWNER_REF=owner://iron-ember/container-route-test \
  -e NAMECOM_SANDBOX_USERNAME=pulpo-container-route-test \
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

provider_ready=0
for _ in $(seq 1 20); do
  if docker exec "$custody" python -c "import urllib.request; assert urllib.request.urlopen('http://${provider}:8081/probe', timeout=2).read() == b'provider-route-ok'"; then
    provider_ready=1
    break
  fi
  sleep 1
done
test "$provider_ready" = "1"

test "$(docker inspect -f '{{len .NetworkSettings.Networks}}' "$custody")" = "2"
test "$(docker inspect -f '{{len .NetworkSettings.Networks}}' "$provider")" = "1"
test -z "$(docker port "$custody")"
test -z "$(docker port "$provider")"
provider_ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$provider")"
test -n "$provider_ip"

docker run -d \
  --name "$worker" \
  --network "$worker_network" \
  -e PROVIDER_IP="$provider_ip" \
  python:3.11-slim sleep 300 >/dev/null

test "$(docker inspect -f '{{len .NetworkSettings.Networks}}' "$worker")" = "1"
docker exec "$worker" python -c "
import os, socket, urllib.request
forbidden = {
    'PULPO_KERNEL_SECRET_HEX',
    'PULPO_CUSTODY_SECRET_HEX',
    'PULPO_AUTHORITY_PUBLIC_KEY_HEX',
    'NAMECOM_SANDBOX_EXECUTOR_TOKEN',
    'NAMECOM_SANDBOX_OBSERVER_TOKEN',
}
assert forbidden.isdisjoint(os.environ), sorted(forbidden.intersection(os.environ))
data = urllib.request.urlopen('http://${custody}:8080/health', timeout=2).read()
assert b'\"authority_effect\":\"none\"' in data
for host in ('${provider}', os.environ['PROVIDER_IP']):
    try:
        connection = socket.create_connection((host, 8081), timeout=1)
    except OSError:
        continue
    else:
        connection.close()
        raise AssertionError('hostile worker unexpectedly reached provider: ' + host)
"
