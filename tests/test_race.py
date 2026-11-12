import unittest

from mcp_oauth_guard.race import run_race_simulation


class TestRaceSimulator(unittest.TestCase):
    def test_vulnerable_mode_detects_auth_code_reuse_and_refresh_race(self) -> None:
        report = run_race_simulation(mode="vulnerable", concurrency=6)
        codes = {f["code"] for f in report["findings"]}
        self.assertIn("MOG201", codes)
        self.assertIn("MOG202", codes)
        self.assertGreater(report["auth_code_race"]["success_count"], 1)
        self.assertTrue(report["refresh_race"]["family_revoked"])

    def test_guarded_mode_passes_with_zero_findings(self) -> None:
        report = run_race_simulation(mode="guarded", concurrency=6)
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["auth_code_race"]["success_count"], 1)
        self.assertFalse(report["refresh_race"]["family_revoked"])

    def test_refuses_remote_url_without_explicit_authorization(self) -> None:
        with self.assertRaises(ValueError):
            run_race_simulation(target_url="https://example.com/oauth/token", concurrency=4)


if __name__ == "__main__":
    unittest.main()
