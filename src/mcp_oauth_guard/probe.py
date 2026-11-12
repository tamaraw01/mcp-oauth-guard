"""Explicit-target OAuth 2.1, RFC 9728, RFC 8414, and WWW-Authenticate probe."""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlparse

from mcp_oauth_guard.models import Finding

RESOURCE_METADATA_RE = re.compile(r'resource_metadata="([^"]+)"')


class SSRFError(ValueError):
    """Raised when a target URL violates SSRF/private-network guardrails."""


def _is_blocked_ip(ip_str: str, allow_loopback: bool, allow_private: bool) -> bool:
    ip = ipaddress.ip_address(ip_str)
    if ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return True
    if ip.is_loopback:
        return not allow_loopback
    if ip.is_private or ip.is_reserved:
        return not allow_private
    return False


def validate_probe_url(
    url: str,
    *,
    allow_loopback: bool = False,
    allow_private: bool = False,
) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise SSRFError(f"Unsupported scheme '{parsed.scheme}'; only http/https allowed.")
    host = parsed.hostname
    if not host:
        raise SSRFError("Target URL is missing a hostname.")

    try:
        ipaddress.ip_address(host)
        ips = [host]
    except ValueError:
        if host.lower() == "localhost":
            ips = ["127.0.0.1"]
        else:
            try:
                infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
                ips = [info[4][0] for info in infos]
            except socket.gaierror:
                return url

    for ip in ips:
        if _is_blocked_ip(ip, allow_loopback=allow_loopback, allow_private=allow_private):
            raise SSRFError(f"Target host '{host}' resolves to blocked IP '{ip}'.")
    return url


def _http_get(url: str, timeout: float = 5.0) -> tuple[int, dict[str, str], str]:
    req = urllib.request.Request(url, method="GET", headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, headers, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        headers = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
        body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        return exc.code, headers, body


def _origin(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def probe_oauth_target(
    target_url: str,
    *,
    allow_loopback: bool = False,
    allow_private: bool = False,
    timeout: float = 5.0,
) -> dict[str, Any]:
    validate_probe_url(target_url, allow_loopback=allow_loopback, allow_private=allow_private)
    findings: list[Finding] = []
    origin = _origin(target_url)

    status, headers, _ = _http_get(target_url, timeout=timeout)
    www_auth = headers.get("www-authenticate", "")
    prm_url = f"{origin}/.well-known/oauth-protected-resource"
    if status == 401:
        match = RESOURCE_METADATA_RE.search(www_auth)
        if match:
            prm_url = match.group(1)
        else:
            findings.append(
                Finding(
                    code="MOG101",
                    severity="WARNING",
                    target=target_url,
                    message="401 response lacks WWW-Authenticate resource_metadata parameter (RFC 9728).",
                    remediation="Return Bearer resource_metadata=\"https://.../oauth-protected-resource\" on 401.",
                    source="probe",
                )
            )

    validate_probe_url(prm_url, allow_loopback=allow_loopback, allow_private=allow_private)
    prm_status, _, prm_body = _http_get(prm_url, timeout=timeout)
    rfc9728: dict[str, Any] = {}
    auth_servers: list[str] = []

    if prm_status != 200:
        findings.append(
            Finding(
                code="MOG102",
                severity="ERROR",
                target=prm_url,
                message=f"RFC 9728 protected-resource metadata returned HTTP {prm_status}.",
                remediation="Serve valid JSON at /.well-known/oauth-protected-resource.",
                source="probe",
            )
        )
    else:
        try:
            rfc9728 = json.loads(prm_body)
        except json.JSONDecodeError as exc:
            findings.append(
                Finding(
                    code="MOG102",
                    severity="ERROR",
                    target=prm_url,
                    message=f"Invalid JSON in RFC 9728 metadata: {exc}",
                    remediation="Return valid JSON for protected-resource metadata.",
                    source="probe",
                )
            )
        else:
            raw_servers = rfc9728.get("authorization_servers")
            if not isinstance(raw_servers, list) or not raw_servers:
                findings.append(
                    Finding(
                        code="MOG103",
                        severity="ERROR",
                        target=prm_url,
                        message="RFC 9728 metadata is missing non-empty authorization_servers.",
                        remediation="Include at least one authorization server URL in authorization_servers.",
                        source="probe",
                    )
                )
            else:
                auth_servers = [s for s in raw_servers if isinstance(s, str)]

    as_base = auth_servers[0].rstrip("/") if auth_servers else origin
    as_meta_url = f"{as_base}/.well-known/oauth-authorization-server"
    validate_probe_url(as_meta_url, allow_loopback=allow_loopback, allow_private=allow_private)
    as_status, _, as_body = _http_get(as_meta_url, timeout=timeout)
    rfc8414: dict[str, Any] = {}

    if as_status != 200:
        findings.append(
            Finding(
                code="MOG106",
                severity="ERROR",
                target=as_meta_url,
                message=f"RFC 8414 authorization-server metadata returned HTTP {as_status}.",
                remediation="Serve OAuth 2.1 metadata at /.well-known/oauth-authorization-server.",
                source="probe",
            )
        )
    else:
        try:
            rfc8414 = json.loads(as_body)
        except json.JSONDecodeError as exc:
            findings.append(
                Finding(
                    code="MOG106",
                    severity="ERROR",
                    target=as_meta_url,
                    message=f"Invalid JSON in RFC 8414 metadata: {exc}",
                    remediation="Return valid JSON for authorization-server metadata.",
                    source="probe",
                )
            )
        else:
            issuer = rfc8414.get("issuer", "")
            if issuer.rstrip("/") != as_base.rstrip("/"):
                findings.append(
                    Finding(
                        code="MOG104",
                        severity="ERROR",
                        target=as_meta_url,
                        message=f"RFC 8414 issuer '{issuer}' does not match expected '{as_base}'.",
                        remediation="Set metadata 'issuer' to match the authorization server base URL exactly (RFC 8414 Section 3.3).",
                        source="probe",
                    )
                )
            pkce = rfc8414.get("code_challenge_methods_supported") or []
            if "S256" not in pkce:
                findings.append(
                    Finding(
                        code="MOG105",
                        severity="ERROR",
                        target=as_meta_url,
                        message="RFC 8414 metadata does not advertise PKCE S256 in code_challenge_methods_supported.",
                        remediation="Enable PKCE S256 and advertise it in code_challenge_methods_supported (OAuth 2.1).",
                        source="probe",
                    )
                )
            if not rfc8414.get("token_endpoint") or not rfc8414.get("authorization_endpoint"):
                findings.append(
                    Finding(
                        code="MOG107",
                        severity="ERROR",
                        target=as_meta_url,
                        message="RFC 8414 metadata missing authorization_endpoint or token_endpoint.",
                        remediation="Include both authorization_endpoint and token_endpoint in RFC 8414 metadata.",
                        source="probe",
                    )
                )

    return {
        "target_url": target_url,
        "http_status": status,
        "www_authenticate": www_auth,
        "rfc9728_url": prm_url,
        "rfc9728": rfc9728,
        "rfc8414_url": as_meta_url,
        "rfc8414": rfc8414,
        "findings": [f.to_dict() for f in findings],
    }
