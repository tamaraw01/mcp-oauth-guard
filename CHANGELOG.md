# Changelog

## 1.0.0 (2026-11-12)

- Initial release of `mcp-oauth-guard` (MIT, Python 3.11+ stdlib only).
- Added `audit` subcommand for `.mcp.json`, `~/.claude.json`, `~/.claude/settings.json`, `claude_desktop_config.json`, and token storage files (`MOG000`-`MOG007`).
- Added `probe` subcommand for explicit-target RFC 9728 / RFC 8414 metadata and `WWW-Authenticate` checks with SSRF private-IP blocking (`MOG101`-`MOG107`).
- Added `race` subcommand with in-process mock OAuth 2.1 server (`vulnerable` and `guarded` modes) for parallel authorization-code reuse and rotating refresh-token race testing (`MOG201`-`MOG202`).
- Added `doctor` health-check subcommand and `--format json` CI exit codes (`0`, `1`, `2`).
