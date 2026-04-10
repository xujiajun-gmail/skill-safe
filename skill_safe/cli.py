from __future__ import annotations

import argparse
import sys
from pathlib import Path

from skill_safe.admission import build_provenance, build_summary, build_trust_profile, decide_findings
from skill_safe.config import get_config_value, load_config, merge_taxonomy_overrides
from skill_safe.dynamic import run_dynamic_observation
from skill_safe.ingest import IngestError, ingest_target
from skill_safe.i18n import detect_language
from skill_safe.llm_config import resolve_llm_config
from skill_safe.models import Decision, ScanReport
from skill_safe.policy import (
    apply_environment_policy,
    apply_policy_profile,
    apply_taxonomy_overrides,
    supported_policy_profiles,
)
from skill_safe.reporting import render_report
from skill_safe.scanners import run_static_analysis
from skill_safe.scoring import score_findings
from skill_safe.semantic import run_semantic_review



def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _run_scan(args)
    parser.print_help()
    return 1



def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="skill-safe", description="Security scanner for third-party skills")
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser("scan", help="Scan a skill target")
    scan.add_argument("target", help="Directory or archive containing the skill")
    scan.add_argument("--config", help="Path to a skill-safe config file")
    scan.add_argument("--source-type", choices=["auto", "dir", "archive", "git"], default="auto")
    scan.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    scan.add_argument("--output", help="Write the report to this file")
    scan.add_argument("--policy", help="Reserved for future custom policy support")
    scan.add_argument("--policy-profile", choices=supported_policy_profiles(), default="default")
    scan.add_argument("--offline", action="store_true", help="Reserved for future remote enrichment disabling")
    scan.add_argument("--dynamic", action="store_true", help="Enable dynamic observation mode")
    scan.add_argument("--lang", choices=["auto", "zh", "en"], default="auto")
    scan.add_argument("--llm-mode", choices=["off", "local", "remote"], help="Optional LLM mode")
    scan.add_argument("--llm-provider", help="Optional LLM provider name")
    scan.add_argument("--llm-base-url", help="Optional LLM base URL")
    scan.add_argument("--llm-model", help="Optional LLM model name")
    scan.add_argument("--llm-api-key-env", help="Environment variable name for the LLM API key")
    return parser



def _run_scan(args: argparse.Namespace) -> int:
    try:
        config = load_config(args.config, cwd=Path(args.target).resolve() if Path(args.target).exists() else Path.cwd())
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    try:
        source_type = args.source_type
        if source_type == "auto":
            source_type = get_config_value(config, "scan", "source_type", default="auto")
        skill = ingest_target(args.target, source_type)
    except IngestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

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
    lang_mode = args.lang
    if lang_mode == "auto":
        lang_mode = get_config_value(config, "language", "mode", default="auto")
    output_language = detect_language(skill.natural_language_blob(), lang_mode)
    scores = score_findings(findings)
    decision = decide_findings(findings)
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
    runtime_trace = run_dynamic_observation(skill, enabled=args.dynamic)
    report = ScanReport(
        schema_version="1.0",
        target=args.target,
        source=skill.source,
        output_language=output_language,
        decision=decision,
        summary=build_summary(findings),
        scores=scores,
        trust_profile=build_trust_profile(artifacts, findings, scores.supply_chain_trust),
        provenance=build_provenance(artifacts, findings),
        findings=findings,
        flows=[],
        runtime_trace=runtime_trace,
        artifacts=artifacts,
    )
    rendered = render_report(report, args.format)
    if args.output:
        output_path = Path(args.output)
        output_path.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0



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
