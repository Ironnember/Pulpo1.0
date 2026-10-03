"""Fail-closed runtime proof for Pulpo inbound listener exposure.

This module does not open, close, or authorize network sockets. It observes
runtime listener state and compares it with an explicit operator-supplied
allowlist. An empty allowlist is the default.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import ipaddress
import json
import platform
import re
import subprocess
from typing import Iterable, Sequence


class NetworkExposureError(RuntimeError):
    """Runtime listener state could not be established safely."""


@dataclass(frozen=True, order=True)
class Listener:
    protocol: str
    address: str
    port: int

    def __post_init__(self) -> None:
        if self.protocol not in {"tcp", "udp"}:
            raise ValueError("unsupported listener protocol")
        if not isinstance(self.address, str) or not self.address:
            raise ValueError("listener address required")
        if isinstance(self.port, bool) or not isinstance(self.port, int) or not 0 <= self.port <= 65535:
            raise ValueError("listener port invalid")

    @property
    def loopback(self) -> bool:
        host = self.address.split("%", 1)[0]
        try:
            return ipaddress.ip_address(host).is_loopback
        except ValueError:
            return host.lower() == "localhost"

    @property
    def wildcard(self) -> bool:
        return self.address in {"0.0.0.0", "::", "*"}

    @property
    def externally_reachable_binding(self) -> bool:
        return self.wildcard or not self.loopback


@dataclass(frozen=True)
class ExposureReport:
    schema: str
    platform: str
    listeners: tuple[Listener, ...]
    allowed: tuple[Listener, ...]
    unexpected: tuple[Listener, ...]

    @property
    def passed(self) -> bool:
        return not self.unexpected

    def to_json(self) -> str:
        return json.dumps(
            {
                "schema": self.schema,
                "platform": self.platform,
                "passed": self.passed,
                "listeners": [_listener_json(item) for item in self.listeners],
                "allowed": [_listener_json(item) for item in self.allowed],
                "unexpected": [_listener_json(item) for item in self.unexpected],
            },
            sort_keys=True,
            separators=(",", ":"),
        )


def _listener_json(listener: Listener) -> dict[str, object]:
    value = asdict(listener)
    value["loopback"] = listener.loopback
    value["wildcard"] = listener.wildcard
    value["externally_reachable_binding"] = listener.externally_reachable_binding
    return value


def parse_allowlist(values: Sequence[str]) -> tuple[Listener, ...]:
    """Parse exact entries such as tcp:127.0.0.1:8080 or udp:[::1]:5353."""

    result: set[Listener] = set()
    for value in values:
        match = re.fullmatch(r"(tcp|udp):(?:\[([^\]]+)\]|([^:]+)):(\d{1,5})", value)
        if not match:
            raise NetworkExposureError(f"invalid allowlist entry: {value}")
        protocol, bracketed, plain, port_text = match.groups()
        port = int(port_text)
        if port > 65535:
            raise NetworkExposureError(f"invalid allowlist port: {value}")
        result.add(Listener(protocol, bracketed or plain, port))
    return tuple(sorted(result))


def _split_host_port(endpoint: str) -> tuple[str, int]:
    endpoint = endpoint.strip()
    if endpoint.startswith("["):
        close = endpoint.rfind("]:")
        if close < 0:
            raise NetworkExposureError(f"unparseable listener endpoint: {endpoint}")
        host = endpoint[1:close]
        port_text = endpoint[close + 2 :]
    else:
        host, separator, port_text = endpoint.rpartition(":")
        if not separator:
            raise NetworkExposureError(f"unparseable listener endpoint: {endpoint}")
    if port_text == "*":
        port = 0
    else:
        try:
            port = int(port_text)
        except ValueError as exc:
            raise NetworkExposureError(f"unparseable listener port: {endpoint}") from exc
    return host or "*", port


def parse_linux_ss(text: str) -> tuple[Listener, ...]:
    """Parse `ss -H -lntup` output into exact local listeners."""

    listeners: set[Listener] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        fields = line.split()
        if len(fields) < 5:
            raise NetworkExposureError(f"unparseable ss row: {line}")
        protocol = fields[0].lower()
        if protocol not in {"tcp", "udp"}:
            continue
        local = fields[4]
        host, port = _split_host_port(local)
        listeners.add(Listener(protocol, host, port))
    return tuple(sorted(listeners))


def parse_windows_json(text: str) -> tuple[Listener, ...]:
    """Parse normalized PowerShell listener JSON."""

    try:
        decoded = json.loads(text)
    except json.JSONDecodeError as exc:
        raise NetworkExposureError("windows listener output was not valid JSON") from exc
    if isinstance(decoded, dict):
        decoded = [decoded]
    if not isinstance(decoded, list):
        raise NetworkExposureError("windows listener output had invalid shape")
    listeners: set[Listener] = set()
    for item in decoded:
        if not isinstance(item, dict):
            raise NetworkExposureError("windows listener row had invalid shape")
        protocol = item.get("protocol")
        address = item.get("address")
        port = item.get("port")
        if protocol not in {"tcp", "udp"} or not isinstance(address, str):
            raise NetworkExposureError("windows listener row had invalid fields")
        if isinstance(port, bool) or not isinstance(port, int):
            raise NetworkExposureError("windows listener row had invalid port")
        listeners.add(Listener(protocol, address, port))
    return tuple(sorted(listeners))


def collect_listeners(system: str | None = None) -> tuple[Listener, ...]:
    """Collect host listeners without mutating firewall or socket state."""

    name = (system or platform.system()).lower()
    if name == "linux":
        try:
            completed = subprocess.run(
                ["ss", "-H", "-lntup"],
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (FileNotFoundError, subprocess.SubprocessError) as exc:
            raise NetworkExposureError("linux listener enumeration failed") from exc
        return parse_linux_ss(completed.stdout)

    if name == "windows":
        script = (
            "$tcp=Get-NetTCPConnection -State Listen | "
            "ForEach-Object { [pscustomobject]@{protocol='tcp';address=$_.LocalAddress;port=$_.LocalPort} };"
            "$udp=Get-NetUDPEndpoint | "
            "ForEach-Object { [pscustomobject]@{protocol='udp';address=$_.LocalAddress;port=$_.LocalPort} };"
            "@($tcp)+@($udp) | ConvertTo-Json -Compress"
        )
        try:
            completed = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                check=True,
                capture_output=True,
                text=True,
                timeout=15,
            )
        except (FileNotFoundError, subprocess.SubprocessError) as exc:
            raise NetworkExposureError("windows listener enumeration failed") from exc
        return parse_windows_json(completed.stdout or "[]")

    raise NetworkExposureError(f"unsupported platform for listener proof: {name}")


def evaluate_listeners(
    listeners: Iterable[Listener],
    *,
    allowed: Iterable[Listener] = (),
    system: str | None = None,
) -> ExposureReport:
    observed = tuple(sorted(set(listeners)))
    approved = tuple(sorted(set(allowed)))
    approved_set = set(approved)
    unexpected = tuple(item for item in observed if item not in approved_set)
    return ExposureReport(
        schema="pulpo.network-exposure.v1",
        platform=(system or platform.system()).lower(),
        listeners=observed,
        allowed=approved,
        unexpected=unexpected,
    )


def audit_network_exposure(
    *,
    allowed: Iterable[Listener] = (),
    system: str | None = None,
) -> ExposureReport:
    return evaluate_listeners(
        collect_listeners(system),
        allowed=allowed,
        system=system,
    )
