"""Static audit for MCP client configs and OAuth token storage files."""

from __future__ import annotations

import json
import os
import re
import stat
import time
from pathlib import Path
from typing import Mapping
from urllib.parse import urlparse

from mcp_oauth_guard.models import Finding

ENV_REF_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-(.*?))?\}")
SHELL_META_RE = re.compile(r"[|;&$`><]")
SECRET_KEY_RE = re.compile(r"(token|secret|password|api[_-]?key|client_secret)", re.IGNORECASE)

DEFAULT_CONFIG_CANDIDATES = (
    Path(".mcp.json"),
    Path.home() / ".claude.json",
    Path.home() / ".claude" / "settings.json",
    Path.home() / ".claude" / "mcp.json",
    Path.home() / ".config" / "Claude" / "claude_desktop_config.json",
    Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
    Path.home() / ".codex" / ".credentials.json",
)


def _expand_env_template(value: str, env: Mapping[str, str]) -> str:
    def _replace(match: re.Match[str]) -> str:
        name = match.group(1)
        default = match.group(2) if match.group(2) is not None else ""
        return env.get(name, default)

    return ENV_REF_RE.sub(_replace, value)


def _is_env_ref_only(value: str) -> bool:
    stripped = value.strip()
    return bool(ENV_REF_RE.search(stripped)) and ENV_REF_RE.sub("", stripped).strip() == ""


def _check_redirect_uri(uri: str, target: str, server: str) -> list[Finding]:
    findings: list[Finding] = []
    parsed = urlparse(uri)
    host = (parsed.hostname or "").lower()
    if host == "localhost":
        findings.append(
            Finding(
                code="MOG005",
                severity="ERROR",
                target=f"{target}:{server}",
                message=f"redirect_uri '{uri}' uses 'localhost' instead of 127.0.0.1 (RFC 8252 Section 7.3).",
                remediation="Use http://127.0.0.1:<port>/callback for loopback OAuth redirects.",
            )
        )
    elif host == "127.0.0.1" and parsed.port is None:
        findings.append(
            Finding(
                code="MOG005",
                severity="ERROR",
                target=f"{target}:{server}",
                message=f"redirect_uri '{uri}' omits an explicit port on 127.0.0.1 (breaks CIMD port binding).",
                remediation="Bind an explicit ephemeral or configured port in redirect_uri.",
            )
        )
    return findings


def _audit_server_entry(
    server_name: str,
    cfg: dict,
    target: str,
    env: Mapping[str, str],
) -> list[Finding]:
    findings: list[Finding] = []
    srv_target = f"{target}:{server_name}"
    headers = cfg.get("headers")
    if isinstance(headers, dict):
        for key, raw_val in headers.items():
            if not isinstance(raw_val, str):
                continue
            if key.lower() == "authorization":
                expanded = _expand_env_template(raw_val, env).strip()
                if expanded == "" or expanded.lower() == "bearer":
                    # Any Authorization header on type:http disables OAuth fallback in Claude Code (#69758).
                    findings.append(
                        Finding(
                            code="MOG001",
                            severity="ERROR",
                            target=srv_target,
                            message="headers.Authorization expands to empty or bare 'Bearer', disabling OAuth fallback.",
                            remediation="Remove headers.Authorization when using OAuth, or ensure the referenced env var is non-empty.",
                        )
                    )
                elif not ENV_REF_RE.search(raw_val) and expanded.lower().startswith("bearer "):
                    findings.append(
                        Finding(
                            code="MOG003",
                            severity="ERROR",
                            target=srv_target,
                            message="Plaintext Bearer token hardcoded in headers.Authorization.",
                            remediation="Move credentials to environment variables, OS keychain, or a validated headersHelper.",
                        )
                    )

    srv_env = cfg.get("env")
    if isinstance(srv_env, dict):
        for env_key, env_val in srv_env.items():
            if not isinstance(env_val, str):
                continue
            if "GITHUB" in env_key.upper() and env_val.startswith("gho_"):
                findings.append(
                    Finding(
                        code="MOG002",
                        severity="WARNING",
                        target=srv_target,
                        message=f"{env_key} uses a 'gho_' OAuth token where a 'ghp_' PAT is typically expected.",
                        remediation="Verify token scope and prefix ('ghp_' PAT vs 'gho_' OAuth token) for the target MCP server.",
                    )
                )
            elif SECRET_KEY_RE.search(env_key) and env_val and not _is_env_ref_only(env_val):
                findings.append(
                    Finding(
                        code="MOG003",
                        severity="ERROR",
                        target=srv_target,
                        message=f"Plaintext secret stored in env.{env_key}.",
                        remediation="Reference an environment variable (${VAR}) or secret manager instead of a literal.",
                    )
                )

    helper = cfg.get("headersHelper")
    if isinstance(helper, str) and helper.strip():
        if SHELL_META_RE.search(helper) or helper.startswith("./") or helper.startswith("../"):
            findings.append(
                Finding(
                    code="MOG004",
                    severity="WARNING",
                    target=srv_target,
                    message=f"headersHelper '{helper}' uses relative path or shell metacharacters.",
                    remediation="Use an absolute path to a dedicated executable without shell pipes or chaining.",
                )
            )

    oauth = cfg.get("oauth")
    if isinstance(oauth, dict):
        redirect_uri = oauth.get("redirect_uri") or oauth.get("redirectUri")
        if isinstance(redirect_uri, str):
            findings.extend(_check_redirect_uri(redirect_uri, target, server_name))
        if isinstance(oauth.get("clientSecret"), str) or isinstance(oauth.get("client_secret"), str):
            val = oauth.get("clientSecret") or oauth.get("client_secret") or ""
            if val and not _is_env_ref_only(val):
                findings.append(
                    Finding(
                        code="MOG003",
                        severity="ERROR",
                        target=srv_target,
                        message="Plaintext client_secret found in oauth config.",
                        remediation="Use public client + PKCE (S256) or reference an env var for client_secret.",
                    )
                )

    return findings


def _audit_token_storage(data: dict, path: Path) -> list[Finding]:
    findings: list[Finding] = []
    target = str(path)
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            findings.append(
                Finding(
                    code="MOG007",
                    severity="WARNING",
                    target=target,
                    message=f"Credential file permissions are {oct(mode)}; group/other bits are set.",
                    remediation="Restrict credential file permissions to 0600 (chmod 600).",
                )
            )
    except OSError:
        pass

    has_token_fields = any(k in data for k in ("access_token", "refresh_token", "expires_at", "expiresAt"))
    if has_token_fields:
        exp = data.get("expires_at") or data.get("expiresAt")
        if isinstance(exp, (int, float)) and exp < time.time() and not data.get("refresh_token"):
            findings.append(
                Finding(
                    code="MOG007",
                    severity="ERROR",
                    target=target,
                    message="Stored access token is expired and has no refresh_token.",
                    remediation="Re-authenticate and ensure offline_access / refresh_token is persisted.",
                )
            )
        if "version" not in data and "cas_version" not in data:
            findings.append(
                Finding(
                    code="MOG007",
                    severity="INFO",
                    target=target,
                    message="Token store lacks a CAS version field for cross-process concurrency safety.",
                    remediation="Wrap credential writes with file locking and a monotonic version counter.",
                )
            )
    return findings


def discover_default_paths(root: Path | None = None) -> list[Path]:
    base = root or Path.cwd()
    found: list[Path] = []
    local_mcp = base / ".mcp.json"
    if local_mcp.is_file():
        found.append(local_mcp)
    for candidate in DEFAULT_CONFIG_CANDIDATES[1:]:
        if candidate.is_file() and candidate not in found:
            found.append(candidate)
    return found


def audit_paths(paths: list[Path], env: Mapping[str, str] | None = None) -> list[Finding]:
    active_env = os.environ if env is None else env
    findings: list[Finding] = []
    seen_servers: dict[str, list[str]] = {}

    for path in paths:
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            findings.append(
                Finding(
                    code="MOG000",
                    severity="ERROR",
                    target=str(path),
                    message=f"Failed to parse JSON config: {exc}",
                    remediation="Fix JSON syntax before running MCP clients.",
                )
            )
            continue

        if not isinstance(data, dict):
            continue

        servers = data.get("mcpServers")
        if isinstance(servers, dict):
            for name, srv_cfg in servers.items():
                if isinstance(srv_cfg, dict):
                    seen_servers.setdefault(name, []).append(str(path))
                    findings.extend(_audit_server_entry(name, srv_cfg, str(path), active_env))

        findings.extend(_audit_token_storage(data, path))

    for name, locs in seen_servers.items():
        if len(locs) > 1:
            findings.append(
                Finding(
                    code="MOG006",
                    severity="WARNING",
                    target=", ".join(locs),
                    message=f"MCP server '{name}' is defined in multiple config files.",
                    remediation="Consolidate server definition into a single config root to avoid credential/auth drift.",
                )
            )

    return findings
