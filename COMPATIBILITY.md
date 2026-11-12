# Compatibility Matrix

## Specifications Checked

- OAuth 2.1 / PKCE (`S256` required in `code_challenge_methods_supported`)
- RFC 9728 (`/.well-known/oauth-protected-resource` and `WWW-Authenticate: Bearer resource_metadata=...`)
- RFC 8414 (`/.well-known/oauth-authorization-server` and Section 3.3 exact `issuer` match)
- RFC 8252 Section 7.3 (`127.0.0.1:<port>` loopback `redirect_uri`, flagging `localhost` and portless URIs)

## Runtime Environment

| Component | Supported | Notes |
|---|---|---|
| Python | 3.11, 3.12, 3.13 | Stdlib only; zero third-party runtime dependencies |
| OS | Linux, macOS, Windows (WSL / Git Bash) | `scripts/check.sh` requires Bash; CLI runs under any Python 3.11+ |
| Packaging | Source checkout, `pip install -e .`, release ZIP | Verified in clean `HOME` with `PYTHONNOUSERSITE=1` |
