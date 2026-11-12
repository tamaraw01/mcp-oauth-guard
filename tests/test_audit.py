import json
import os
import tempfile
import unittest
from pathlib import Path

from mcp_oauth_guard.audit import audit_paths


class TestStaticAudit(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write_json(self, rel: str, data: dict, mode: int | None = None) -> Path:
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data, indent=2), encoding="utf-8")
        if mode is not None:
            os.chmod(p, mode)
        return p

    def test_flags_empty_bearer_header_and_plaintext_secret(self) -> None:
        cfg = self._write_json(
            ".mcp.json",
            {
                "mcpServers": {
                    "linear": {
                        "type": "http",
                        "url": "https://mcp.linear.app/mcp",
                        "headers": {"Authorization": "Bearer ${LINEAR_TOKEN:-}"},
                    },
                    "internal": {
                        "type": "http",
                        "url": "https://api.example.com/mcp",
                        "headers": {"Authorization": "Bearer sk_live_plaintext_12345"},
                    },
                }
            },
        )
        findings = audit_paths([cfg], env={})
        codes = {f.code for f in findings}
        self.assertIn("MOG001", codes)
        self.assertIn("MOG003", codes)

    def test_flags_gho_ghp_prefix_mismatch_and_localhost_redirect(self) -> None:
        cfg = self._write_json(
            "claude_desktop_config.json",
            {
                "mcpServers": {
                    "github": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-github"],
                        "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "gho_example_oauth_token"},
                    },
                    "oauth_app": {
                        "type": "http",
                        "url": "https://mcp.example.com/mcp",
                        "oauth": {"redirect_uri": "http://localhost:8080/callback"},
                    },
                }
            },
        )
        findings = audit_paths([cfg], env={})
        codes = {f.code for f in findings}
        self.assertIn("MOG002", codes)
        self.assertIn("MOG005", codes)

    def test_flags_headers_helper_risk_and_permissive_token_file(self) -> None:
        cfg = self._write_json(
            ".claude.json",
            {
                "mcpServers": {
                    "remote": {
                        "type": "http",
                        "url": "https://mcp.example.com/mcp",
                        "headersHelper": "./scripts/get-token.sh | cat",
                    }
                }
            },
        )
        creds = self._write_json(
            ".credentials.json",
            {"refresh_token": "rt_abc123", "expires_at": 1000},
            mode=0o644,
        )
        findings = audit_paths([cfg, creds], env={})
        codes = {f.code for f in findings}
        self.assertIn("MOG004", codes)
        self.assertIn("MOG007", codes)

    def test_clean_config_returns_zero_findings(self) -> None:
        cfg = self._write_json(
            ".mcp.json",
            {
                "mcpServers": {
                    "docs": {
                        "type": "http",
                        "url": "https://mcp.example.com/mcp",
                        "oauth": {
                            "clientId": "client_123",
                            "redirect_uri": "http://127.0.0.1:43115/callback",
                        },
                    }
                }
            },
            mode=0o600,
        )
        findings = audit_paths([cfg], env={})
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
