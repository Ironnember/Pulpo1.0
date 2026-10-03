"""Explicit outbound HTTPS trust policy for offboard/provider transports."""

from __future__ import annotations

import os
from pathlib import Path
import ssl
from urllib.request import (
    HTTPSHandler,
    HTTPRedirectHandler,
    ProxyHandler,
    Request,
    build_opener,
)


class TransportConfigurationError(RuntimeError):
    """The process has not supplied an explicit safe transport configuration."""


_AMBIENT_CA_VARS = (
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
)
_PROXY_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _ssl_context() -> ssl.SSLContext:
    configured = os.environ.get("PULPO_CA_BUNDLE")
    ambient = {name: os.environ.get(name) for name in _AMBIENT_CA_VARS if os.environ.get(name)}
    if ambient and not configured:
        raise TransportConfigurationError("ambient_ca_configuration_requires_pulpo_ca_bundle")
    if configured:
        bundle = Path(configured).expanduser()
        if not bundle.is_absolute() or not bundle.is_file():
            raise TransportConfigurationError("pulpo_ca_bundle_must_be_an_existing_absolute_file")
        if any(value != configured for value in ambient.values()):
            raise TransportConfigurationError("ambient_ca_configuration_conflicts_with_pulpo_ca_bundle")
        return ssl.create_default_context(cafile=str(bundle))
    return ssl.create_default_context()


def build_secure_opener():
    """Build an HTTPS opener that ignores ambient proxies and redirects."""

    return build_opener(
        ProxyHandler({}),
        NoRedirect(),
        HTTPSHandler(context=_ssl_context()),
    )


def secure_urlopen(request: Request, *, timeout: float):
    return build_secure_opener().open(request, timeout=timeout)


def sanitized_transport_environment(
    environment: dict[str, str],
    *,
    ca_bundle: str | None = None,
) -> dict[str, str]:
    """Remove ambient proxy/CA controls and restore only explicit CA policy."""

    runtime = dict(environment)
    for name in (*_PROXY_VARS, *_AMBIENT_CA_VARS):
        runtime.pop(name, None)
    if ca_bundle is not None:
        bundle = Path(ca_bundle).expanduser()
        if not bundle.is_absolute() or not bundle.is_file():
            raise TransportConfigurationError("pulpo_ca_bundle_must_be_an_existing_absolute_file")
        runtime["PULPO_CA_BUNDLE"] = str(bundle)
    else:
        runtime.pop("PULPO_CA_BUNDLE", None)
    return runtime
