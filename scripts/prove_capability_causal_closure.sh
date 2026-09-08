#!/usr/bin/env bash
set -euo pipefail

run_id="${GITHUB_RUN_ID:-local-$$}"
sha="${GITHUB_SHA:-$(git rev-parse HEAD)}"
worker_network="pulpo-worker-causal-v0-${run_id}"
provider_network="pulpo-provider-causal-v0-${run_id}"
volume="pulpo-custody-causal-v0-${run_id}"
custody="pulpo-custody-causal-v0-${run_id}"
provider="pulpo-provider-causal-v0-${run_id}"
relay="pulpo-relay-causal-v0-${run_id}"
worker="pulpo-hostile-worker-causal-v0-${run_id}"
image="pulpo-custody-v0:${sha}"
provider_script="${RUNNER_TEMP:-/tmp}/pulpo-provider-causal-v0-${run_id}.py"
relay_script="${RUNNER_TEMP:-/tmp}/pulpo-relay-causal-v0-${run_id}.py"
proof_token="causal-closure-provider-token-not-real"

cat > "$provider_script" <<'PY'
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path

STATE = Path('/state/effects.jsonl')
TOKEN = os.environ['PROOF_PROVIDER_TOKEN']


def count_effects():
    if not STATE.exists():
        return 0
    return sum(1 for line in STATE.read_text().splitlines() if line.strip())


class Handler(BaseHTTPRequestHandler):
    def _json(self, status, payload):
        body = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == '/probe':
            self._json(200, {'ok': True})
            return
        if self.path == '/count':
            self._json(200, {'count': count_effects()})
            return
        self._json(404, {'error': 'not_found'})

    def do_POST(self):
        if self.path != '/effect':
            self._json(404, {'error': 'not_found'})
            return
        if self.headers.get('X-Proof-Token') != TOKEN:
            self._json(403, {'error': 'capability_required'})
            return
        length = int(self.headers.get('Content-Length', '0'))
        body = self.rfile.read(length)
        if body != b'causal-closure-positive-control':
            self._json(400, {'error': 'exact_object_required'})
            return
        STATE.parent.mkdir(parents=True, exist_ok=True)
        with STATE.open('a', encoding='utf-8') as handle:
            handle.write(json.dumps({'effect': 'causal-closure-positive-control'}, sort_keys=True) + '\n')
        self._json(200, {'ok': True, 'count': count_effects()})

    def log_message(self, *_args):
        return


HTTPServer(('0.0.0.0', 8081), Handler).serve_forever()
PY

cat > "$relay_script" <<'PY'
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
import urllib.parse
import urllib.request

PROVIDER_DNS_URL = os.environ['PROVIDER_DNS_URL']
PROVIDER_IP_URL = os.environ['PROVIDER_IP_URL']


def attempt(url, *, method='GET', body=None, headers=None):
    request = urllib.request.Request(url, data=body, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(request, timeout=1) as response:
            return {'reached': True, 'status': response.status}
    except Exception as exc:
        return {'reached': False, 'error_class': type(exc).__name__}


class Handler(BaseHTTPRequestHandler):
    def _json(self, status, payload):
        body = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == '/metadata':
            self._json(200, {
                'class': 'metadata_token_relay',
                'provider_capability': False,
                'token': 'relay-token-with-no-provider-authority',
            })
            return
        if parsed.path == '/signed-request':
            self._json(200, {
                'class': 'delegated_signed_request',
                'provider_capability': False,
                'artifact': 'signed-looking-but-not-provider-authority',
            })
            return
        if parsed.path == '/webhook':
            result = attempt(PROVIDER_DNS_URL + '/effect', method='POST', body=b'hostile-webhook')
            self._json(200, {'class': 'webhook_relay', 'provider_attempt': result})
            return
        if parsed.path == '/ambient-helper':
            result = attempt(
                PROVIDER_DNS_URL + '/effect',
                method='POST',
                body=b'hostile-ambient-helper',
                headers={'X-Proof-Token': os.environ.get('PROOF_PROVIDER_TOKEN', '')},
            )
            self._json(200, {
                'class': 'ambient_helper',
                'ambient_provider_token_present': bool(os.environ.get('PROOF_PROVIDER_TOKEN')),
                'provider_attempt': result,
            })
            return
        if parsed.path == '/ssrf':
            target = urllib.parse.parse_qs(parsed.query).get('target', [''])[0]
            allowed_test_targets = {PROVIDER_DNS_URL + '/effect', PROVIDER_IP_URL + '/effect'}
            if target not in allowed_test_targets:
                self._json(400, {'error': 'proof_target_not_allowed'})
                return
            result = attempt(target, method='POST', body=b'hostile-ssrf')
            self._json(200, {'class': 'ssrf_relay', 'provider_attempt': result})
            return
        if parsed.path == '/health':
            self._json(200, {'ok': True, 'authority_effect': 'none'})
            return
        self._json(404, {'error': 'not_found'})

    def log_message(self, *_args):
        return


HTTPServer(('0.0.0.0', 8082), Handler).serve_forever()
PY

docker network create --internal "$worker_network" >/dev/null
docker network create --internal "$provider_network" >/dev/null
docker volume create "$volume" >/dev/null
cleanup() {
  docker rm -f "$worker" "$relay" "$custody" "$provider" >/dev/null 2>&1 || true
  docker network rm "$worker_network" "$provider_network" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
  rm -f "$provider_script" "$relay_script"
}
trap cleanup EXIT

docker run -d \
  --name "$provider" \
  --network "$provider_network" \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  -v "$volume:/state:rw" \
  -v "$provider_script:/provider.py:ro" \
  -e PROOF_PROVIDER_TOKEN="$proof_token" \
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
  -e PULPO_AUTHORITY_ID=authority:causal-closure-test \
  -e PULPO_AUTHORITY_VERIFIER_ID=verifier:causal-closure-ed25519 \
  -e PULPO_AUTHORITY_KEY_ID=key:causal-closure-v0 \
  -e PULPO_AUTHORITY_DEPLOYMENT_ID=deployment:causal-closure-v0 \
  -e PULPO_AUTHORITY_MAX_TTL_SECONDS=300 \
  -e PULPO_PILOT_BUDGET_CENTS=3000 \
  -e PULPO_OWNER_REF=owner://iron-ember/causal-closure-test \
  -e NAMECOM_SANDBOX_USERNAME=pulpo-causal-closure-test \
  -e NAMECOM_SANDBOX_EXECUTOR_TOKEN=executor-token-not-real \
  -e NAMECOM_SANDBOX_OBSERVER_TOKEN=observer-token-not-real \
  -e PROOF_PROVIDER_TOKEN="$proof_token" \
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
  if docker exec "$custody" python -c "import urllib.request; assert urllib.request.urlopen('http://${provider}:8081/probe', timeout=2).status == 200"; then
    provider_ready=1
    break
  fi
  sleep 1
done
test "$provider_ready" = "1"

provider_ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$provider")"
test -n "$provider_ip"

docker run -d \
  --name "$relay" \
  --network "$worker_network" \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  -v "$relay_script:/relay.py:ro" \
  -e PROVIDER_DNS_URL="http://${provider}:8081" \
  -e PROVIDER_IP_URL="http://${provider_ip}:8081" \
  python:3.11-slim python /relay.py >/dev/null

relay_ready=0
for _ in $(seq 1 20); do
  if docker exec "$custody" python -c "import urllib.request; urllib.request.urlopen('http://${relay}:8082/health', timeout=1)" >/dev/null 2>&1; then
    # custody has both networks, but the relay is intentionally worker-facing only.
    relay_ready=1
    break
  fi
  sleep 1
done
test "$relay_ready" = "1"

# Causal-closure sentinel: every worker-facing peer except canonical custody must
# remain on exactly one network. The worker itself is created after this mutation check.
assert_relay_worker_only() {
  test "$(docker inspect -f '{{len .NetworkSettings.Networks}}' "$relay")" = "1"
  test "$(docker inspect -f '{{range $name, $_ := .NetworkSettings.Networks}}{{$name}}{{end}}' "$relay")" = "$worker_network"
}
assert_relay_worker_only

# Mutation kill: deliberately cross the relay into the provider network and prove
# the sentinel rejects the topology before any provider effect is attempted.
docker network connect "$provider_network" "$relay"
if assert_relay_worker_only >/dev/null 2>&1; then
  echo "causal_closure_mutation=FAIL"
  exit 1
fi
echo "causal_closure_mutation=DETECTED"
docker network disconnect "$provider_network" "$relay"
assert_relay_worker_only

docker run -d \
  --name "$worker" \
  --network "$worker_network" \
  -e PROVIDER_IP="$provider_ip" \
  python:3.11-slim sleep 300 >/dev/null

test "$(docker inspect -f '{{len .NetworkSettings.Networks}}' "$worker")" = "1"
test -z "$(docker port "$custody")"
test -z "$(docker port "$provider")"
test -z "$(docker port "$relay")"

# Hostile worker can reach custody and relay surfaces, but holds none of the tested secrets.
docker exec "$worker" python - <<PY
import json
import os
import socket
import urllib.parse
import urllib.request

forbidden = {
    'PULPO_KERNEL_SECRET_HEX',
    'PULPO_CUSTODY_SECRET_HEX',
    'PULPO_AUTHORITY_PUBLIC_KEY_HEX',
    'NAMECOM_SANDBOX_EXECUTOR_TOKEN',
    'NAMECOM_SANDBOX_OBSERVER_TOKEN',
    'PROOF_PROVIDER_TOKEN',
}
assert forbidden.isdisjoint(os.environ), sorted(forbidden.intersection(os.environ))

custody = urllib.request.urlopen('http://${custody}:8080/health', timeout=2).read()
assert b'\"authority_effect\":\"none\"' in custody

relay_base = 'http://${relay}:8082'
assert json.loads(urllib.request.urlopen(relay_base + '/health', timeout=2).read())['ok'] is True

# Direct DNS and raw-IP provider routes must still be blocked.
for host in ('${provider}', os.environ['PROVIDER_IP']):
    try:
        connection = socket.create_connection((host, 8081), timeout=1)
    except OSError:
        continue
    else:
        connection.close()
        raise AssertionError('hostile worker unexpectedly reached provider: ' + host)

metadata = json.loads(urllib.request.urlopen(relay_base + '/metadata', timeout=2).read())
assert metadata['provider_capability'] is False
signed = json.loads(urllib.request.urlopen(relay_base + '/signed-request', timeout=2).read())
assert signed['provider_capability'] is False

webhook = json.loads(urllib.request.urlopen(relay_base + '/webhook', timeout=3).read())
assert webhook['provider_attempt']['reached'] is False
ambient = json.loads(urllib.request.urlopen(relay_base + '/ambient-helper', timeout=3).read())
assert ambient['ambient_provider_token_present'] is False
assert ambient['provider_attempt']['reached'] is False

for target in ('http://${provider}:8081/effect', 'http://${provider_ip}:8081/effect'):
    url = relay_base + '/ssrf?target=' + urllib.parse.quote(target, safe='')
    ssrf = json.loads(urllib.request.urlopen(url, timeout=3).read())
    assert ssrf['provider_attempt']['reached'] is False
PY

# Relay itself must hold none of the tested governance/provider capabilities.
docker exec "$relay" python - <<'PY'
import os
forbidden = {
    'PULPO_KERNEL_SECRET_HEX',
    'PULPO_CUSTODY_SECRET_HEX',
    'PULPO_AUTHORITY_PUBLIC_KEY_HEX',
    'NAMECOM_SANDBOX_EXECUTOR_TOKEN',
    'NAMECOM_SANDBOX_OBSERVER_TOKEN',
    'PROOF_PROVIDER_TOKEN',
}
assert forbidden.isdisjoint(os.environ), sorted(forbidden.intersection(os.environ))
PY

# After every hostile direct/relay attempt, provider effect count must still be zero.
docker exec "$custody" python - <<PY
import json
import urllib.request
count = json.loads(urllib.request.urlopen('http://${provider}:8081/count', timeout=2).read())['count']
assert count == 0, count
PY

# Positive control: the credential-bearing custody trust domain can reach the provider
# and use the exact local proof capability once. This is a route/capability positive
# control only; it is not claimed as a governed provider execution.
docker exec "$custody" python - <<PY
import json
import os
import urllib.request
request = urllib.request.Request(
    'http://${provider}:8081/effect',
    data=b'causal-closure-positive-control',
    headers={'X-Proof-Token': os.environ['PROOF_PROVIDER_TOKEN']},
    method='POST',
)
result = json.loads(urllib.request.urlopen(request, timeout=2).read())
assert result['ok'] is True
assert result['count'] == 1
count = json.loads(urllib.request.urlopen('http://${provider}:8081/count', timeout=2).read())['count']
assert count == 1
PY

echo "worker_provider_dns_route=BLOCKED"
echo "worker_provider_raw_ip_route=BLOCKED"
echo "metadata_token_relay_effect=BLOCKED"
echo "signed_request_relay_effect=BLOCKED"
echo "webhook_relay_effect=BLOCKED"
echo "ssrf_dns_relay_effect=BLOCKED"
echo "ssrf_raw_ip_relay_effect=BLOCKED"
echo "ambient_helper_relay_effect=BLOCKED"
echo "hostile_relay_provider_effect_count=0"
echo "causal_closure_mutation=DETECTED"
echo "custody_provider_positive_control=PASS"
echo "provider_effect_count_after_positive_control=1"
echo "capability_causal_closure_v0=PASS"
