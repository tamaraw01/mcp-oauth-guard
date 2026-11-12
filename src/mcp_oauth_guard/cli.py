"""CLI entrypoint for mcp-oauth-guard."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from mcp_oauth_guard import __version__
from mcp_oauth_guard.audit import audit_paths, discover_default_paths
from mcp_oauth_guard.models import SEVERITY_ORDER
from mcp_oauth_guard.probe import SSRFError, probe_oauth_target
from mcp_oauth_guard.race import run_race_simulation


def _exit_code(findings: list[dict[str, Any]], strict: bool = False) -> int:
    for item in findings:
        sev = item.get("severity", "")
        if sev in ("CRITICAL", "ERROR"):
            return 1
        if strict and sev == "WARNING":
            return 1
    return 0


def _print_scorecard(title: str, findings: list[dict[str, Any]], extra: dict[str, Any] | None = None) -> None:
    counts = {"CRITICAL": 0, "ERROR": 0, "WARNING": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1

    status = "PASS" if (counts["CRITICAL"] == 0 and counts["ERROR"] == 0) else "FAIL"
    print(f"mcp-oauth-guard {__version__} | {title} | {status}")
    print(
        f"Summary: CRITICAL={counts['CRITICAL']} ERROR={counts['ERROR']} "
        f"WARNING={counts['WARNING']} INFO={counts['INFO']}"
    )
    if extra:
        for key, val in extra.items():
            print(f"  {key}: {val}")
    if findings:
        print("")
        ordered = sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.get("severity", "INFO"), 9))
        for item in ordered:
            print(f"[{item['severity']}] {item['code']} ({item['target']})")
            print(f"  {item['message']}")
            print(f"  Fix: {item['remediation']}")


def _cmd_audit(args: argparse.Namespace) -> int:
    if args.path:
        paths = [Path(p).expanduser() for p in args.path]
    else:
        root = Path(args.root).expanduser() if args.root else Path.cwd()
        paths = discover_default_paths(root=root)

    findings = [f.to_dict() for f in audit_paths(paths)]
    ok = _exit_code(findings, strict=args.strict) == 0
    payload = {
        "ok": ok,
        "command": "audit",
        "scanned_paths": [str(p) for p in paths],
        "findings": findings,
    }
    if args.format == "json":
        print(json.dumps(payload, indent=2))
    else:
        _print_scorecard("Static Config & Token Audit", findings, {"scanned_files": len(paths)})
    return 0 if ok else 1


def _cmd_probe(args: argparse.Namespace) -> int:
    try:
        report = probe_oauth_target(
            args.url,
            allow_loopback=args.allow_loopback,
            allow_private=args.allow_private,
            timeout=args.timeout,
        )
    except SSRFError as exc:
        err = {"ok": False, "command": "probe", "error": str(exc)}
        if args.format == "json":
            print(json.dumps(err, indent=2))
        else:
            print(f"Blocked target URL: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        err = {"ok": False, "command": "probe", "error": str(exc)}
        if args.format == "json":
            print(json.dumps(err, indent=2))
        else:
            print(f"Probe failed: {exc}", file=sys.stderr)
        return 2

    findings = report["findings"]
    ok = _exit_code(findings, strict=args.strict) == 0
    report["ok"] = ok
    report["command"] = "probe"
    if args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        _print_scorecard(
            "OAuth 2.1 Discovery Probe",
            findings,
            {"target": args.url, "http_status": report["http_status"]},
        )
    return 0 if ok else 1


def _cmd_race(args: argparse.Namespace) -> int:
    try:
        report = run_race_simulation(
            mode=args.mode,
            concurrency=args.concurrency,
            target_url=args.url,
            allow_remote=args.i_own_this_server,
            auth_code=args.auth_code,
            refresh_token=args.refresh_token,
        )
    except ValueError as exc:
        err = {"ok": False, "command": "race", "error": str(exc)}
        if args.format == "json":
            print(json.dumps(err, indent=2))
        else:
            print(f"Invalid race target: {exc}", file=sys.stderr)
        return 2

    findings = report["findings"]
    ok = _exit_code(findings, strict=args.strict) == 0
    report["ok"] = ok
    report["command"] = "race"
    if args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        ac = report["auth_code_race"]
        rf = report["refresh_race"]
        _print_scorecard(
            f"Concurrency Race Simulator ({report['mode']})",
            findings,
            {
                "auth_code_success": f"{ac['success_count']}/{ac['attempts']}",
                "refresh_invalid_grant": rf["invalid_grant_count"],
                "family_revoked": rf["family_revoked"],
            },
        )
    return 0 if ok else 1


def _cmd_doctor(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser() if args.root else Path.cwd()
    paths = discover_default_paths(root=root)
    audit_findings = [f.to_dict() for f in audit_paths(paths)]
    guarded_report = run_race_simulation(mode="guarded", concurrency=4)
    self_test_passed = len(guarded_report["findings"]) == 0
    ok = self_test_passed and (_exit_code(audit_findings, strict=args.strict) == 0)
    payload = {
        "ok": ok,
        "command": "doctor",
        "python_version": sys.version.split()[0],
        "self_test_passed": self_test_passed,
        "scanned_paths": [str(p) for p in paths],
        "findings": audit_findings,
    }
    if args.format == "json":
        print(json.dumps(payload, indent=2))
    else:
        _print_scorecard(
            "Environment & Guardrails Doctor",
            audit_findings,
            {
                "python": payload["python_version"],
                "guarded_race_self_test": "PASS" if self_test_passed else "FAIL",
                "scanned_files": len(paths),
            },
        )
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-oauth-guard",
        description="Audit MCP OAuth configs, probe RFC 9728/8414 metadata, and simulate token race conditions.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="subcommand", required=True)

    p_audit = sub.add_parser("audit", help="Static audit of .mcp.json, Claude, and token storage files.")
    p_audit.add_argument("--path", action="append", help="Explicit config or credential file path (repeatable).")
    p_audit.add_argument("--root", help="Workspace root for .mcp.json discovery.")
    p_audit.add_argument("--strict", action="store_true", help="Exit 1 on WARNING findings as well as ERROR/CRITICAL.")
    p_audit.add_argument("--format", choices=("text", "json"), default="text")
    p_audit.set_defaults(func=_cmd_audit)

    p_probe = sub.add_parser("probe", help="Probe explicit MCP OAuth target URL (RFC 9728 / RFC 8414).")
    p_probe.add_argument("--url", required=True, help="Explicit MCP or authorization server URL.")
    p_probe.add_argument("--allow-loopback", action="store_true", help="Allow 127.0.0.1 / localhost targets.")
    p_probe.add_argument("--allow-private", action="store_true", help="Allow RFC1918 private IP targets.")
    p_probe.add_argument("--timeout", type=float, default=5.0)
    p_probe.add_argument("--strict", action="store_true")
    p_probe.add_argument("--format", choices=("text", "json"), default="text")
    p_probe.set_defaults(func=_cmd_probe)

    p_race = sub.add_parser("race", help="Run parallel auth-code reuse and rotating refresh-token race tests.")
    p_race.add_argument("--mode", choices=("vulnerable", "guarded"), default="vulnerable")
    p_race.add_argument("--concurrency", type=int, default=8)
    p_race.add_argument("--url", help="Explicit local/authorized /token endpoint URL.")
    p_race.add_argument("--i-own-this-server", action="store_true", help="Required to test a non-loopback --url.")
    p_race.add_argument("--auth-code", default="code_race_test_1")
    p_race.add_argument("--refresh-token", default="rt_initial_1")
    p_race.add_argument("--strict", action="store_true")
    p_race.add_argument("--format", choices=("text", "json"), default="text")
    p_race.set_defaults(func=_cmd_race)

    p_doc = sub.add_parser("doctor", help="Verify runtime environment, guarded race self-test, and local configs.")
    p_doc.add_argument("--root", help="Workspace root for .mcp.json discovery.")
    p_doc.add_argument("--strict", action="store_true")
    p_doc.add_argument("--format", choices=("text", "json"), default="text")
    p_doc.set_defaults(func=_cmd_doctor)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)
