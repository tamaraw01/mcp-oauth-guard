import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class TestCli(unittest.TestCase):
    def setUp(self) -> None:
        self.cli_root = Path(__file__).resolve().parent.parent
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _run(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "mcp_oauth_guard", *args],
            cwd=self.cli_root,
            env={"PYTHONPATH": str(self.cli_root / "src"), "PATH": ""},
            capture_output=True,
            text=True,
        )

    def test_audit_json_and_exit_codes(self) -> None:
        bad = self.root / ".mcp.json"
        bad.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "linear": {
                            "type": "http",
                            "url": "https://mcp.linear.app/mcp",
                            "headers": {"Authorization": "Bearer ${MISSING_TOKEN:-}"},
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        res = self._run("audit", "--path", str(bad), "--format", "json")
        self.assertEqual(res.returncode, 1)
        payload = json.loads(res.stdout)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["findings"][0]["code"], "MOG001")

    def test_race_vulnerable_vs_guarded_exit_codes(self) -> None:
        vuln = self._run("race", "--mode", "vulnerable", "--concurrency", "4", "--format", "json")
        self.assertEqual(vuln.returncode, 1)
        vuln_data = json.loads(vuln.stdout)
        self.assertGreaterEqual(len(vuln_data["findings"]), 1)

        guarded = self._run("race", "--mode", "guarded", "--concurrency", "4", "--format", "json")
        self.assertEqual(guarded.returncode, 0)
        guarded_data = json.loads(guarded.stdout)
        self.assertTrue(guarded_data["ok"])

    def test_probe_blocks_ssrf_with_exit_2(self) -> None:
        res = self._run("probe", "--url", "http://169.254.169.254/latest/meta-data/", "--format", "json")
        self.assertEqual(res.returncode, 2)

    def test_doctor_passes_in_clean_env(self) -> None:
        res = self._run("doctor", "--root", str(self.root), "--format", "json")
        self.assertEqual(res.returncode, 0, res.stderr)
        data = json.loads(res.stdout)
        self.assertTrue(data["ok"])
        self.assertTrue(data["self_test_passed"])


if __name__ == "__main__":
    unittest.main()
