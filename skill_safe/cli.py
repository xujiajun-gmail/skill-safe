from __future__ import annotations

import argparse
import sys
from pathlib import Path

from skill_safe.dynamic import run_dynamic_observation
from skill_safe.ingest import IngestError, ingest_target
from skill_safe.models import ScanReport
from skill_safe.reporting import build_summary, render_report
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
    scores = score_findings(findings)
    report = ScanReport(
        target=args.target,
        source=skill.source,
        summary=build_summary(findings),
        scores=scores,
        findings=findings,
        artifacts={
            "manifest_present": skill.manifest is not None,
            "file_count": len(skill.files),
            "permission_hints": skill.permission_hints,
            "entrypoints": skill.entrypoints,
            "urls": skill.urls,
            "policy": args.policy,
            "offline": args.offline,
        },
        sandbox_observations=run_dynamic_observation(skill, enabled=args.dynamic),
    )
    rendered = render_report(report, args.format)
    if args.output:
        output_path = Path(args.output)
        output_path.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
