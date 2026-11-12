# mcp-oauth-guard

Zero-dependency Python 3.11+ CLI for auditing MCP OAuth 2.1 configs, probing RFC 9728 / RFC 8414 discovery metadata, and testing parallel token-refresh and authorization-code race conditions locally.

Note: This project (`tamaraw01/mcp-oauth-guard`) is an independent MIT CLI and is not affiliated with `aretaslabtech/McpOauthGuard`.

## Packaged Releases

- Packaged ZIP release (`$0+` MIT): [Download mcp-oauth-guard on Gumroad](https://aditama1.gumroad.com/l/mcp-oauth-guard)
- Guard modules, token stores & CI workflows: [MCP OAuth and Concurrency Guardrails Kit ($39 / $79 / $149)](https://aditama1.gumroad.com/l/mcp-oauth-guardrails-kit) (use code `OAUTH20` for 20% off Pro `$79` or Team `$149`)

| Tier | Price | What Is Included |
|---|---:|---|
| **[mcp-oauth-guard](https://aditama1.gumroad.com/l/mcp-oauth-guard)** | **$0+** | This MIT CLI (`audit`, `probe`, `race`, `doctor`) as a packaged ZIP |
| **[Starter](https://aditama1.gumroad.com/l/mcp-oauth-guardrails-kit)** | **$39** | Bundled CLI, Python + TypeScript SSRF / `redirect_uri` / Host-header guards, 5 client config templates, GitHub Actions + `pre-commit` recipes, `install.py` + `check.py` (37 files) |
| **[Pro (Recommended)](https://aditama1.gumroad.com/l/mcp-oauth-guardrails-kit)** | **$79** | Everything in Starter + `fcntl`-locked CAS token stores, single-flight `401` refresh middleware, non-sticky RFC 9728 discovery cache, multiprocessing race tests (42 files, `$63.20` with `OAUTH20`) |
| **[Team](https://aditama1.gumroad.com/l/mcp-oauth-guardrails-kit)** | **$149** | Everything in Pro + workspace-scoped credential isolation, Entra ID & Okta `clientId` templates without DCR, org CI matrix workflow, 5-seat commercial license (49 files, `$119.20` with `OAUTH20`) |

Every paid tier has a 14-day refund policy.

## Quick Start

```bash
python3 -m pip install -e .
mcp-oauth-guard doctor
```

Or run directly from the extracted release archive without installing dependencies:

```bash
bash scripts/check.sh
PYTHONPATH=src python3 -m mcp_oauth_guard audit --root .
```

## Subcommands

### 1. `audit`: Static Config & Token-Storage Audit

Scans `.mcp.json`, `~/.claude.json`, `~/.claude/settings.json`, `~/.claude/mcp.json`, `claude_desktop_config.json`, and `~/.codex/.credentials.json` (or explicit `--path` files):

- `MOG001`: `headers.Authorization` expanding to empty or bare `Bearer` on HTTP MCP servers (disables OAuth fallback).
- `MOG002`: `gho_` vs `ghp_` GitHub token prefix mismatch in `env`.
- `MOG003`: Plaintext `Bearer` tokens, secrets, or `client_secret` literals in config JSON.
- `MOG004`: `headersHelper` commands using relative paths or shell metacharacters.
- `MOG005`: `redirect_uri` using `localhost` instead of `127.0.0.1` (RFC 8252) or missing an explicit port.
- `MOG006`: Duplicate MCP server definitions across multiple config roots.
- `MOG007`: Permissive token-file permissions (`chmod 600` check), expired access tokens without `refresh_token`, or missing CAS version fields.

### 2. `probe`: Explicit-Target RFC 9728 & RFC 8414 Metadata Probe

Probes a single explicit URL (no network scanning) and blocks private/link-local/metadata IPs by default:

```bash
PYTHONPATH=src python3 -m mcp_oauth_guard probe --url https://mcp.example.com/mcp
PYTHONPATH=src python3 -m mcp_oauth_guard probe --url http://127.0.0.1:8080/mcp --allow-loopback
```

Checks `WWW-Authenticate` `resource_metadata`, `/.well-known/oauth-protected-resource`, `/.well-known/oauth-authorization-server`, exact `issuer` matching, and PKCE `S256` support.

### 3. `race`: Local Concurrency Race Simulator

Reproduces parallel authorization-code reuse (`MOG201`) and concurrent rotating refresh-token family revocation (`MOG202`) against an in-process mock OAuth 2.1 server:

```bash
PYTHONPATH=src python3 -m mcp_oauth_guard race --mode vulnerable --concurrency 8
PYTHONPATH=src python3 -m mcp_oauth_guard race --mode guarded --concurrency 8
```

To test your own local server, pass `--url http://127.0.0.1:<port>/token`. Non-loopback URLs require `--i-own-this-server`.

### 4. `doctor`: 1-Command Environment Check

Runs local config discovery plus the guarded race self-test and prints a pass/fail scorecard.

## Exit Codes

- `0`: No `ERROR` or `CRITICAL` findings (add `--strict` to also fail on `WARNING`).
- `1`: One or more findings met the failure threshold.
- `2`: Invalid usage, unreachable target, or SSRF-blocked URL.

## License

MIT. See `LICENSE`.
