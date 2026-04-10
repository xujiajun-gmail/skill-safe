from __future__ import annotations

import argparse
import sys
from pathlib import Path

from skill_safe.admission import build_provenance, build_summary, build_trust_profile, decide_findings
from skill_safe.dynamic import run_dynamic_observation
from skill_safe.ingest import IngestError, ingest_target
from skill_safe.i18n import detect_language
from skill_safe.models import Decision, ScanReport
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
    scan.add_argument("--source-type", choices=["auto", "dir", "archive", "git"], default="auto")
    scan.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    scan.add_argument("--output", help="Write the report to this file")
    scan.add_argument("--policy", help="Reserved for future custom policy support")
    scan.add_argument("--offline", action="store_true", help="Reserved for future remote enrichment disabling")
    scan.add_argument("--dynamic", action="store_true", help="Enable dynamic observation mode")
    scan.add_argument("--lang", choices=["auto", "zh", "en"], default="auto")
    return parser



def _run_scan(args: argparse.Namespace) -> int:
    try:
        skill = ingest_target(args.target, args.source_type)
    except IngestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    findings = run_static_analysis(skill)
    findings.extend(run_semantic_review(skill))
    findings.sort(key=lambda item: item.confidence, reverse=True)
    output_language = detect_language(skill.natural_language_blob(), args.lang)
    scores = score_findings(findings)
    decision = decide_findings(findings)
    artifacts = {
        "manifest_present": skill.manifest is not None,
        "file_count": len(skill.files),
        "permission_hints": skill.permission_hints,
        "entrypoints": skill.entrypoints,
        "urls": skill.urls,
        "policy": args.policy,
        "offline": args.offline,
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
