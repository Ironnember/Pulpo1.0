#!/usr/bin/env bash
set -euo pipefail

release="v0.8.4"
expected_sha="4424d4090da4fc94d18f0a7fd398e14ea9cda920e0bd2b19ecb686493af4a673"
work="${RUNNER_TEMP:-/tmp}/pulpo-helm-g5-v084"
evidence="${GITHUB_WORKSPACE:-$PWD}/artifacts/helm-g5-v084"
binary="$work/helm-ai-kernel"
marker="$work/provider-effect.txt"
server_log="$work/provider.log"
receipt="$evidence/helm-network-deny.json"
result="$evidence/result.txt"
port="18081"
target="http://127.0.0.1:$port/effect"

rm -rf "$work" "$evidence"
mkdir -p "$work/home" "$evidence"

curl -fsSL --retry 3 \
  "https://github.com/Mindburn-Labs/helm-ai-kernel/releases/download/$release/helm-ai-kernel-linux-amd64" \
  -o "$binary"
echo "$expected_sha  $binary" | sha256sum -c -
chmod +x "$binary"

version="$("$binary" --version 2>&1)"
case "$version" in
  *0.8.4*) ;;
  *) echo "unexpected HELM version: $version" >&2; exit 1 ;;
esac

MARKER="$marker" PORT="$port" python3 - <<'PY' >"$server_log" 2>&1 &
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

marker = os.environ["MARKER"]
port = int(os.environ["PORT"])

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
            return
        if self.path == "/effect":
            with open(marker, "w", encoding="utf-8") as handle:
                handle.write("provider consequence created\n")
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"effect-created")
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, *_args):
        return

HTTPServer(("127.0.0.1", port), Handler).serve_forever()
PY
server_pid=$!
trap 'kill "$server_pid" >/dev/null 2>&1 || true' EXIT

for _ in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:$port/health" >/dev/null; then
    break
  fi
  sleep 0.2
done
curl -fsS "http://127.0.0.1:$port/health" >/dev/null
test ! -e "$marker"

set +e
boundary_output="$(
  HOME="$work/home" HELM_NO_TUI=1 TERM=dumb \
  "$binary" workstation enforce \
    --class network \
    --target "$target" \
    --out "$receipt" 2>&1
)"
boundary_rc=$?
set -e
printf '%s\n' "$boundary_output" > "$evidence/helm-boundary-output.txt"

test "$boundary_rc" -eq 126
grep -Eiq 'deny' "$evidence/helm-boundary-output.txt"
test -s "$receipt"
test ! -e "$marker"

direct_output="$(curl -fsS "$target")"
test "$direct_output" = "effect-created"
test -s "$marker"
fixture_sha="$(sha256sum "$marker" | awk '{print $1}')"

{
  echo "schema=pulpo.gladiator.g5.v1"
  echo "helm_release=$release"
  echo "helm_binary_sha256=$expected_sha"
  echo "helm_version=$version"
  echo "governed_surface=workstation enforce --class network"
  echo "governed_target=$target"
  echo "governed_exit_code=$boundary_rc"
  echo "governed_verdict=DENY"
  echo "consequence_after_governed_route=absent"
  echo "alternate_route=direct curl from same runner"
  echo "alternate_route_result=consequence_created"
  echo "consequence_sha256=$fixture_sha"
  echo "claim=an available ungoverned network route bypasses HELM's selected-effect wrapper"
  echo "scope=isolated GitHub Actions loopback fixture; not universal HELM containment"
} > "$result"

cat "$result"
