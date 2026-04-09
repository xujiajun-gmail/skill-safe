from __future__ import annotations

import json
from collections import Counter
from typing import Any

from skill_safe.models import Finding, ScanReport



def build_summary(findings: list[Finding]) -> dict[str, Any]:
    severities = Counter(f.severity.value for f in findings)
    categories = Counter(f.category for f in findings)
    return {
        "finding_count": len(findings),
        "severity_breakdown": dict(sorted(severities.items())),
        "category_breakdown": dict(sorted(categories.items())),
    }



def render_report(report: ScanReport, output_format: str) -> str:
    if output_format == "json":
        return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)
    if output_format == "sarif":
        return json.dumps(_to_sarif(report), indent=2, ensure_ascii=False)
    return _to_text(report)



def _to_text(report: ScanReport) -> str:
    lines = [
        f"Target: {report.target}",
        f"Source type: {report.source.source_type}",
        f"Overall risk: {report.scores.overall}",
        f"Findings: {report.summary['finding_count']}",
        "Scores:",
        f"  malice_likelihood: {report.scores.malice_likelihood}",
        f"  exploitability: {report.scores.exploitability}",
        f"  blast_radius: {report.scores.blast_radius}",
        f"  privilege_excess: {report.scores.privilege_excess}",
        f"  supply_chain_trust: {report.scores.supply_chain_trust}",
        "",
    ]
    for finding in report.findings:
        lines.append(f"- [{finding.severity.value.upper()}] {finding.title} ({finding.id})")
        lines.append(f"  category: {finding.category}; confidence: {finding.confidence:.2f}")
        lines.append(f"  impact: {finding.impact}")
        for ev in finding.evidence[:3]:
            location = f"{ev.file}:{ev.line}" if ev.line else ev.file
            excerpt = f" — {ev.excerpt}" if ev.excerpt else ""
            lines.append(f"    * {location}{excerpt}")
        lines.append(f"  remediation: {finding.remediation}")
        lines.append("")
    if report.sandbox_observations:
        lines.append("Sandbox observations:")
        for key, value in report.sandbox_observations.items():
            lines.append(f"  {key}: {value}")
    return "\n".join(lines).strip() + "\n"



def _to_sarif(report: ScanReport) -> dict[str, Any]:
    rules = []
    results = []
    seen_rules = set()
    for finding in report.findings:
        if finding.id not in seen_rules:
            rules.append(
                {
                    "id": finding.id,
                    "name": finding.title,
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.impact},
                    "properties": {
                        "category": finding.category,
                        "tags": finding.tags,
                    },
                }
            )
            seen_rules.add(finding.id)
        for evidence in finding.evidence or [None]:
            result = {
                "ruleId": finding.id,
                "level": _sarif_level(finding.severity.value),
                "message": {"text": finding.impact},
                "properties": {
                    "confidence": finding.confidence,
                    "remediation": finding.remediation,
                },
            }
            if evidence is not None:
                result["locations"] = [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": evidence.file},
                            "region": {"startLine": evidence.line or 1},
                        }
                    }
                ]
            results.append(result)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "skill-safe",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }



def _sarif_level(severity: str) -> str:
    return {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }[severity]
