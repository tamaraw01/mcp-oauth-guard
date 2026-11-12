import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from mcp_oauth_guard.probe import SSRFError, probe_oauth_target, validate_probe_url


class _MockOAuthHandler(BaseHTTPRequestHandler):
    issuer_override: str | None = None
    pkce_methods: list[str] = ["S256"]

    def log_message(self, format: str, *args: object) -> None:
        return

    def do_GET(self) -> None:
        host = self.headers.get("Host", "127.0.0.1")
        base = f"http://{host}"
        if self.path == "/mcp":
            self.send_response(401)
            self.send_header(
                "WWW-Authenticate",
                f'Bearer resource_metadata="{base}/.well-known/oauth-protected-resource"',
            )
            self.end_headers()
            return
        if self.path == "/.well-known/oauth-protected-resource":
            body = json.dumps(
                {
                    "resource": f"{base}/mcp",
                    "authorization_servers": [base],
                    "scopes_supported": ["mcp:read"],
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/.well-known/oauth-authorization-server":
            issuer = self.issuer_override or base
            body = json.dumps(
                {
                    "issuer": issuer,
                    "authorization_endpoint": f"{base}/authorize",
                    "token_endpoint": f"{base}/token",
                    "code_challenge_methods_supported": self.pkce_methods,
                    "client_id_metadata_document_supported": True,
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()


class TestOAuthProbe(unittest.TestCase):
    def test_ssrf_blocks_metadata_and_private_ips(self) -> None:
        with self.assertRaises(SSRFError):
            validate_probe_url("http://169.254.169.254/latest/meta-data/")
        with self.assertRaises(SSRFError):
            validate_probe_url("http://10.0.0.1/.well-known/oauth-authorization-server")
        with self.assertRaises(SSRFError):
            validate_probe_url("file:///etc/passwd")

    def test_probe_valid_local_server_passes(self) -> None:
        class ValidHandler(_MockOAuthHandler):
            issuer_override = None
            pkce_methods = ["S256"]

        srv = ThreadingHTTPServer(("127.0.0.1", 0), ValidHandler)
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            report = probe_oauth_target(f"http://127.0.0.1:{port}/mcp", allow_loopback=True)
            errors = [f for f in report["findings"] if f["severity"] in ("ERROR", "CRITICAL")]
            self.assertEqual(errors, [])
            self.assertEqual(report["rfc9728"]["resource"], f"http://127.0.0.1:{port}/mcp")
            self.assertTrue(report["rfc8414"]["client_id_metadata_document_supported"])
        finally:
            srv.shutdown()
            srv.server_close()

    def test_probe_flags_issuer_mismatch_and_missing_pkce(self) -> None:
        class BrokenHandler(_MockOAuthHandler):
            issuer_override = "https://wrong-issuer.example.com"
            pkce_methods = ["plain"]

        srv = ThreadingHTTPServer(("127.0.0.1", 0), BrokenHandler)
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            report = probe_oauth_target(f"http://127.0.0.1:{port}/mcp", allow_loopback=True)
            codes = {f["code"] for f in report["findings"]}
            self.assertIn("MOG104", codes)
            self.assertIn("MOG105", codes)
        finally:
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    unittest.main()
