from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from skill_safe.diffing import build_diff_report
from skill_safe.engine import ScanOptions, build_scan_report
from skill_safe.explain import load_report_payload, render_explanation
from skill_safe.ingest import IngestError
from skill_safe.models import ScanReport
from skill_safe.policy import supported_policy_profiles
from skill_safe.reporting import render_diff_report, render_report



def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _run_scan(args)
    if args.command == "diff":
        return _run_diff(args)
    if args.command == "explain":
        return _run_explain(args)
    parser.print_help()
    return 1



def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="skill-safe", description="Security scanner for third-party skills")
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser("scan", help="Scan a skill target")
    scan.add_argument("target", help="Directory or archive containing the skill")
    _add_common_analysis_args(scan)

    diff = subparsers.add_parser("diff", help="Compare two skill versions")
    diff.add_argument("old_target", help="Previous directory or archive containing the skill")
    diff.add_argument("new_target", help="New directory or archive containing the skill")
    _add_common_analysis_args(diff, formats=("text", "json"))

    explain = subparsers.add_parser("explain", help="Explain a scan or diff JSON report")
    explain.add_argument("report", help="Path to a scan/diff JSON report")
    explain.add_argument("--format", choices=("text", "json"), default="text")
    explain.add_argument("--output", help="Write the explanation to this file")
    explain.add_argument("--lang", choices=["auto", "zh", "en"], default="auto")
    return parser


def _add_common_analysis_args(parser: argparse.ArgumentParser, formats: tuple[str, ...] = ("text", "json", "sarif")) -> None:
    parser.add_argument("--config", help="Path to a skill-safe config file")
    parser.add_argument("--source-type", choices=["auto", "dir", "archive", "git"], default="auto")
    parser.add_argument("--format", choices=formats, default="text")
    parser.add_argument("--output", help="Write the report to this file")
    parser.add_argument("--policy", help="Reserved for future custom policy support")
    parser.add_argument("--policy-profile", choices=supported_policy_profiles(), default="default")
    parser.add_argument("--offline", action="store_true", help="Reserved for future remote enrichment disabling")
    parser.add_argument("--dynamic", action="store_true", help="Enable dynamic observation mode")
    parser.add_argument("--lang", choices=["auto", "zh", "en"], default="auto")
    parser.add_argument("--llm-mode", choices=["off", "local", "remote"], help="Optional LLM mode")
    parser.add_argument("--llm-provider", help="Optional LLM provider name")
    parser.add_argument("--llm-base-url", help="Optional LLM base URL")
    parser.add_argument("--llm-model", help="Optional LLM model name")
    parser.add_argument("--llm-api-key-env", help="Environment variable name for the LLM API key")



def _run_scan(args: argparse.Namespace) -> int:
    try:
        report = build_scan_report(args.target, _scan_options_from_args(args))
    except (FileNotFoundError, ValueError, IngestError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    rendered = render_report(report, args.format)
    if args.output:
        output_path = Path(args.output)
        output_path.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0


def _run_diff(args: argparse.Namespace) -> int:
    try:
        options = _scan_options_from_args(args)
        old_report = build_scan_report(args.old_target, options)
        new_report = build_scan_report(args.new_target, options)
    except (FileNotFoundError, ValueError, IngestError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    output_language = _resolve_output_language(args, old_report, new_report)
    old_report.output_language = output_language
    new_report.output_language = output_language
    diff_report = build_diff_report(old_report, new_report, output_language)
    rendered = render_diff_report(diff_report, args.format)
    if args.output:
        output_path = Path(args.output)
        output_path.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0


def _run_explain(args: argparse.Namespace) -> int:
    try:
        payload = load_report_payload(args.report)
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    output_language = _resolve_report_language(args.lang, payload)
    rendered = render_explanation(payload, output_language, args.format)
    if args.output:
        output_path = Path(args.output)
        output_path.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0


def _scan_options_from_args(args: argparse.Namespace) -> ScanOptions:
    return ScanOptions(
        config_path=getattr(args, "config", None),
        source_type=getattr(args, "source_type", "auto"),
        policy=getattr(args, "policy", None),
        policy_profile=getattr(args, "policy_profile", "default"),
        offline=getattr(args, "offline", False),
        dynamic=getattr(args, "dynamic", False),
        lang=getattr(args, "lang", "auto"),
        llm_mode=getattr(args, "llm_mode", None),
        llm_provider=getattr(args, "llm_provider", None),
        llm_base_url=getattr(args, "llm_base_url", None),
        llm_model=getattr(args, "llm_model", None),
        llm_api_key_env=getattr(args, "llm_api_key_env", None),
    )


def _resolve_output_language(args: argparse.Namespace, old_report: ScanReport, new_report: ScanReport) -> str:
    if args.lang in {"zh", "en"}:
        return args.lang
    if old_report.output_language == new_report.output_language:
        return old_report.output_language
    return "zh"


def _resolve_report_language(requested: str, payload: dict[str, object]) -> str:
    if requested in {"zh", "en"}:
        return requested
    report_language = payload.get("output_language")
    if report_language in {"zh", "en"}:
        return str(report_language)
    return "zh"


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
