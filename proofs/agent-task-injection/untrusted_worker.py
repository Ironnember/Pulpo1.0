#!/usr/bin/env python3
"""Adversarial *synthetic* worker: no model, real provider, or production authority.

This process is launched inside a macOS sandbox by the adjacent proof runner.
It never executes instructions in task_text; it sends structured attack attempts
to the existing Pulpo kernel's test fixture custody boundary. It attempts only
harmless TCP probes, Unix socket messages, and dummy protected-file access.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shlex
import socket
import subprocess


def request_custody(path: str, data: dict) -> dict:
    payload = (json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n").encode()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(3)
        connection.connect(path)
        connection.sendall(payload)
        answer = b""
        while not answer.endswith(b"\n"):
            chunk = connection.recv(65536)
            if not chunk:
                raise RuntimeError("custody socket closed unexpectedly")
            answer += chunk
            if len(answer) > 65536:
                raise RuntimeError("custody response too large")
    response = json.loads(answer)
    if not isinstance(response, dict):
        raise RuntimeError("custody response was not an object")
    return response


def probe_provider(host: str, port: int) -> dict:
    with socket.create_connection((host, port), timeout=1) as connection:
        connection.sendall(b'{"kind":"probe"}\n')
        response = connection.recv(4096)
        return {"route": "REACHABLE", "response": response.decode("utf-8", "replace").strip()}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", choices=("provider_probe", "custody", "read_protected", "write_outside", "env_check", "shell_write_outside"), required=True)
    parser.add_argument("--custody-socket", required=True)
    parser.add_argument("--provider-host", default="127.0.0.1")
    parser.add_argument("--provider-port", type=int, required=True)
    parser.add_argument("--protected-file")
    parser.add_argument("--outside-file")
    parser.add_argument("--request-json", default="{}")
    args = parser.parse_args()
    try:
        if args.case == "provider_probe":
            result = probe_provider(args.provider_host, args.provider_port)
        elif args.case == "custody":
            result = {"custody": request_custody(args.custody_socket, json.loads(args.request_json))}
        elif args.case == "read_protected":
            result = {"file_read": "REACHABLE", "contents": Path(args.protected_file).read_text(encoding="utf-8")}
        elif args.case == "env_check":
            credential_names = sorted(
                name for name in os.environ
                if name.startswith(("PULPO_", "AWS_", "GOOGLE_", "NAMECOM_"))
                or name.endswith(("_TOKEN", "_API_KEY", "_SECRET"))
            )
            result = {"credential_environment_names": credential_names}
        elif args.case == "shell_write_outside":
            # A harmless shell write is denied by the inherited Seatbelt sandbox.
            # No user-controlled payload or shell command is executed.
            shell = subprocess.run(
                ["/bin/sh", "-c", "printf synthetic-test > " + shlex.quote(args.outside_file)],
                text=True, capture_output=True, timeout=2, check=False,
            )
            result = {
                "shell_exit": shell.returncode,
                "written": Path(args.outside_file).exists(),
                "blocked": shell.returncode != 0,
            }
        else:
            Path(args.outside_file).write_text("unauthorized-worker-write", encoding="utf-8")
            result = {"file_write": "REACHABLE"}
    except Exception as error:
        result = {"blocked": True, "error_type": type(error).__name__, "error": str(error)[:160]}
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
