from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from skill_safe.admission import build_provenance, build_summary, build_trust_profile, decide_findings
from skill_safe.config import get_config_value, load_config, merge_taxonomy_overrides
from skill_safe.diffing import build_diff_report
from skill_safe.dynamic import run_dynamic_observation
from skill_safe.explain import load_report_payload, render_explanation
from skill_safe.ingest import IngestError, ingest_target
from skill_safe.i18n import detect_language
from skill_safe.llm_config import resolve_llm_config
from skill_safe.models import ScanReport
from skill_safe.policy import (
    apply_environment_policy,
    apply_policy_profile,
    apply_taxonomy_overrides,
    supported_policy_profiles,
)
from skill_safe.reporting import render_diff_report, render_report
from skill_safe.scanners import run_static_analysis
from skill_safe.scoring import score_findings
from skill_safe.semantic import run_semantic_review



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
        report = _build_scan_report(args.target, args)
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
        old_report = _build_scan_report(args.old_target, args)
        new_report = _build_scan_report(args.new_target, args)
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


def _build_scan_report(target: str, args: argparse.Namespace) -> ScanReport:
    config = load_config(args.config, cwd=Path(target).resolve() if Path(target).exists() else Path.cwd())
    source_type = args.source_type
    if source_type == "auto":
        source_type = get_config_value(config, "scan", "source_type", default="auto")
    skill = ingest_target(target, source_type)

    llm_config = resolve_llm_config(args, config)
    gatekeeper_findings = run_static_analysis(skill)
    findings = list(gatekeeper_findings)
    findings.extend(run_semantic_review(skill, gatekeeper_findings=gatekeeper_findings))
    policy_profile = args.policy_profile
    if policy_profile == "default":
        policy_profile = get_config_value(config, "policy", "profile", default="default")
    findings = apply_policy_profile(findings, policy_profile)
    findings = apply_environment_policy(findings, config)
    findings = apply_taxonomy_overrides(findings, merge_taxonomy_overrides(config))
    findings.sort(key=lambda item: item.confidence, reverse=True)
    output_language = detect_language(skill.natural_language_blob(), _resolve_lang_mode(args, config))
    scores = score_findings(findings)
    artifacts = {
        "manifest_present": skill.manifest is not None,
        "file_count": len(skill.files),
        "permission_hints": skill.permission_hints,
        "entrypoints": skill.entrypoints,
        "urls": skill.urls,
        "policy": args.policy,
        "policy_profile": policy_profile,
        "config_path": args.config,
        "offline": args.offline,
        "llm_config": llm_config.public_dict(),
        "publisher_identity": _publisher_identity(skill),
        "repository_url": _repository_url(skill),
        "release_ref": None,
        "content_hash": _manifest_hash(skill),
    }
    runtime_trace = run_dynamic_observation(skill, enabled=getattr(args, "dynamic", False))
    return ScanReport(
        schema_version="1.0",
        target=target,
        source=skill.source,
        output_language=output_language,
        decision=decide_findings(findings),
        summary=build_summary(findings),
        scores=scores,
        trust_profile=build_trust_profile(artifacts, findings, scores.supply_chain_trust),
        provenance=build_provenance(artifacts, findings),
        findings=findings,
        flows=[],
        runtime_trace=runtime_trace,
        artifacts=artifacts,
    )


def _resolve_lang_mode(args: argparse.Namespace, config: dict[str, object]) -> str:
    lang_mode = args.lang
    if lang_mode == "auto":
        lang_mode = get_config_value(config, "language", "mode", default="auto")
    return lang_mode


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



def _publisher_identity(skill) -> str | None:
    manifest = skill.manifest or {}
    return manifest.get("publisher") or manifest.get("author")



def _repository_url(skill) -> str | None:
    manifest = skill.manifest or {}
    for key in ("repository", "homepage", "url"):
        value = manifest.get(key)
        if isinstance(value, str):
            return value
    return None



def _manifest_hash(skill) -> str | None:
    for file in skill.files:
        if file.path in {"skill.json", "manifest.json", ".codex-plugin/plugin.json", "package.json", "pyproject.toml"}:
            return file.sha256
    return None


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
