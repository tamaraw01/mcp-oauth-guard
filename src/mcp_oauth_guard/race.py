"""Local OAuth 2.1 concurrency race-condition simulator."""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from mcp_oauth_guard.models import Finding


class _MockTokenState:
    def __init__(self, guarded: bool) -> None:
        self.guarded = guarded
        self.lock = threading.Lock()
        self.auth_codes: set[str] = {"code_race_test_1"}
        self.active_refresh_token = "rt_initial_1"
        self.used_refresh_tokens: set[str] = set()
        self.family_revoked = False
        self.rotation_counter = 0
        self.single_flight_cache: dict[str, dict[str, str]] = {}

    def exchange_code(self, code: str) -> tuple[int, dict[str, Any]]:
        if self.guarded:
            with self.lock:
                if code not in self.auth_codes:
                    return 400, {"error": "invalid_grant", "error_description": "authorization code already used"}
                self.auth_codes.remove(code)
                return 200, {"access_token": "at_code_1", "token_type": "Bearer", "expires_in": 300}

        # Non-atomic read-then-delete models GHSA-7w99-5wm4-3g79.
        if code not in self.auth_codes:
            return 400, {"error": "invalid_grant", "error_description": "authorization code already used"}
        time.sleep(0.03)
        self.auth_codes.discard(code)
        return 200, {"access_token": "at_code_unserialized", "token_type": "Bearer", "expires_in": 300}

    def refresh(self, refresh_token: str) -> tuple[int, dict[str, Any]]:
        if self.guarded:
            with self.lock:
                if refresh_token in self.single_flight_cache:
                    return 200, dict(self.single_flight_cache[refresh_token])
                if self.family_revoked or refresh_token != self.active_refresh_token:
                    return 400, {"error": "invalid_grant", "error_description": "stale refresh token"}
                self.rotation_counter += 1
                new_rt = f"rt_rotated_{self.rotation_counter}"
                payload = {
                    "access_token": f"at_rotated_{self.rotation_counter}",
                    "refresh_token": new_rt,
                    "token_type": "Bearer",
                    "expires_in": 300,
                }
                self.used_refresh_tokens.add(refresh_token)
                self.active_refresh_token = new_rt
                self.single_flight_cache[refresh_token] = payload
                return 200, dict(payload)

        if self.family_revoked:
            return 400, {"error": "invalid_grant", "error_description": "token family revoked"}
        if refresh_token in self.used_refresh_tokens:
            self.family_revoked = True
            return 400, {
                "error": "invalid_grant",
                "error_description": "rotating refresh token reuse detected; family revoked",
            }
        if refresh_token != self.active_refresh_token:
            return 400, {"error": "invalid_grant", "error_description": "unknown refresh token"}

        # Simulate concurrent window before rotation commits.
        time.sleep(0.03)
        if refresh_token in self.used_refresh_tokens or refresh_token != self.active_refresh_token:
            self.family_revoked = True
            return 400, {
                "error": "invalid_grant",
                "error_description": "rotating refresh token reuse detected; family revoked",
            }
        self.used_refresh_tokens.add(refresh_token)
        self.rotation_counter += 1
        new_rt = f"rt_rotated_{self.rotation_counter}"
        self.active_refresh_token = new_rt
        return 200, {
            "access_token": f"at_rotated_{self.rotation_counter}",
            "refresh_token": new_rt,
            "token_type": "Bearer",
            "expires_in": 300,
        }


def _make_handler(state: _MockTokenState) -> type[BaseHTTPRequestHandler]:
    class _TokenHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            return

        def do_POST(self) -> None:
            if self.path != "/token":
                self.send_response(404)
                self.end_headers()
                return
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length).decode("utf-8", errors="replace")
            params = urllib.parse.parse_qs(raw)
            grant = (params.get("grant_type") or [""])[0]
            if grant == "authorization_code":
                code = (params.get("code") or [""])[0]
                status, body = state.exchange_code(code)
            elif grant == "refresh_token":
                rt = (params.get("refresh_token") or [""])[0]
                status, body = state.refresh(rt)
            else:
                status, body = 400, {"error": "unsupported_grant_type"}

            encoded = json.dumps(body).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

    return _TokenHandler


def _post_form(url: str, data: dict[str, str], timeout: float = 5.0) -> tuple[int, dict[str, Any]]:
    encoded = urllib.parse.urlencode(data).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=encoded,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace") if exc.fp else "{}"
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = {"error": raw}
        return exc.code, parsed


def _run_parallel_post(url: str, form: dict[str, str], concurrency: int) -> list[tuple[int, dict[str, Any]]]:
    barrier = threading.Barrier(concurrency)

    def _worker(_: int) -> tuple[int, dict[str, Any]]:
        barrier.wait(timeout=5.0)
        return _post_form(url, form)

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        return list(pool.map(_worker, range(concurrency)))


def run_race_simulation(
    *,
    mode: str = "vulnerable",
    concurrency: int = 8,
    target_url: str | None = None,
    allow_remote: bool = False,
    auth_code: str = "code_race_test_1",
    refresh_token: str = "rt_initial_1",
) -> dict[str, Any]:
    if concurrency < 2:
        raise ValueError("concurrency must be >= 2")

    srv: ThreadingHTTPServer | None = None
    state: _MockTokenState | None = None

    if target_url is not None:
        parsed = urllib.parse.urlparse(target_url)
        host = (parsed.hostname or "").lower()
        if host not in ("127.0.0.1", "::1", "localhost") and not allow_remote:
            raise ValueError(
                f"Refusing race test against non-loopback '{target_url}' without allow_remote=True."
            )
        token_url = target_url
    else:
        if mode not in ("vulnerable", "guarded"):
            raise ValueError(f"Unsupported simulation mode '{mode}'; expected 'vulnerable' or 'guarded'.")
        state = _MockTokenState(guarded=(mode == "guarded"))
        srv = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(state))
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        token_url = f"http://127.0.0.1:{port}/token"

    try:
        code_results = _run_parallel_post(
            token_url,
            {"grant_type": "authorization_code", "code": auth_code},
            concurrency,
        )
        refresh_results = _run_parallel_post(
            token_url,
            {"grant_type": "refresh_token", "refresh_token": refresh_token},
            concurrency,
        )
    finally:
        if srv is not None:
            srv.shutdown()
            srv.server_close()

    code_success = sum(1 for st, body in code_results if st == 200 and "access_token" in body)
    refresh_success = [body for st, body in refresh_results if st == 200 and "access_token" in body]
    refresh_invalid_grant = sum(
        1 for st, body in refresh_results if st >= 400 and body.get("error") == "invalid_grant"
    )
    distinct_rotated = len({b.get("refresh_token") for b in refresh_success if b.get("refresh_token")})
    family_revoked = bool(state.family_revoked) if state is not None else (refresh_invalid_grant > 0 and len(refresh_success) <= 1)

    findings: list[Finding] = []
    if code_success > 1:
        findings.append(
            Finding(
                code="MOG201",
                severity="CRITICAL",
                target=token_url,
                message=f"Parallel authorization_code exchange succeeded {code_success}/{concurrency} times (single-use violation).",
                remediation="Make authorization code read-and-delete atomic (compare-and-swap or transactional DELETE ... RETURNING).",
                source="race",
            )
        )
    if family_revoked or distinct_rotated > 1:
        findings.append(
            Finding(
                code="MOG202",
                severity="CRITICAL",
                target=token_url,
                message=(
                    f"Concurrent rotating refresh_token race triggered {refresh_invalid_grant} invalid_grant errors "
                    f"(family_revoked={family_revoked}, distinct_rotated={distinct_rotated})."
                ),
                remediation="Serialize token refresh across processes with file/DB locking and single-flight deduplication.",
                source="race",
            )
        )

    return {
        "mode": "external" if target_url else mode,
        "token_url": token_url,
        "concurrency": concurrency,
        "auth_code_race": {
            "attempts": concurrency,
            "success_count": code_success,
        },
        "refresh_race": {
            "attempts": concurrency,
            "success_count": len(refresh_success),
            "invalid_grant_count": refresh_invalid_grant,
            "distinct_rotated_tokens": distinct_rotated,
            "family_revoked": family_revoked,
        },
        "findings": [f.to_dict() for f in findings],
    }
