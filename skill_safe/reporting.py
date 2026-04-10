from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

from skill_safe import __version__
from skill_safe.i18n import render_message
from skill_safe.models import Decision, Finding, ScanReport



def render_report(report: ScanReport, output_format: str) -> str:
    if output_format == "json":
        return json.dumps(report_to_dict(report), indent=2, ensure_ascii=False)
    if output_format == "sarif":
        return json.dumps(_to_sarif(report), indent=2, ensure_ascii=False)
    return _to_text(report)


def render_diff_report(report: dict[str, Any], output_format: str) -> str:
    if output_format == "json":
        return json.dumps(report, indent=2, ensure_ascii=False)
    return _diff_to_text(report)



def report_to_dict(report: ScanReport) -> dict[str, Any]:
    language = report.output_language
    return {
        "schema_version": report.schema_version,
        "tool": {"name": "skill-safe", "version": __version__},
        "target": report.target,
        "source": asdict(report.source),
        "output_language": language,
        "decision": report.decision.value,
        "decision_reason": render_message(language, f"decision.{report.decision.value}"),
        "summary": report.summary,
        "scores": asdict(report.scores),
        "trust_profile": asdict(report.trust_profile),
        "provenance": report.provenance,
        "findings": [_finding_to_dict(finding, language) for finding in report.findings],
        "flows": report.flows,
        "runtime_trace": report.runtime_trace,
        "artifacts": report.artifacts,
        "llm": report.llm.to_dict(),
    }



def _finding_to_dict(finding: Finding, language: str) -> dict[str, Any]:
    return {
        "id": finding.id,
        "taxonomy_id": finding.taxonomy_id,
        "stage": finding.stage.value,
        "alignment_status": finding.alignment_status.value if finding.alignment_status else None,
        "severity": finding.severity.value,
        "category": finding.category,
        "confidence": finding.confidence,
        "decision_hint": finding.decision_hint.value,
        "title": render_message(language, f"{finding.taxonomy_id}.title"),
        "impact": render_message(language, f"{finding.taxonomy_id}.impact"),
        "remediation": render_message(language, f"{finding.taxonomy_id}.remediation"),
        "evidence": [evidence.to_dict() for evidence in finding.evidence],
        "tags": finding.tags,
        "llm": finding.llm.to_dict(),
    }



def _to_text(report: ScanReport) -> str:
    language = report.output_language
    lines = [
        f"{render_message(language, 'text.target')}: {report.target}",
        f"{render_message(language, 'text.source_type')}: {report.source.source_type}",
        f"{render_message(language, 'text.output_language')}: {language}",
        f"{render_message(language, 'text.decision')}: {report.decision.value}",
        f"{render_message(language, 'decision.' + report.decision.value)}",
        f"{render_message(language, 'text.findings')}: {report.summary['finding_count']}",
        f"{render_message(language, 'text.flows')}: {len(report.flows)}",
        f"{render_message(language, 'text.scores')}: ",
        f"  malice_likelihood: {report.scores.malice_likelihood}",
        f"  exploitability: {report.scores.exploitability}",
        f"  blast_radius: {report.scores.blast_radius}",
        f"  privilege_excess: {report.scores.privilege_excess}",
        f"  supply_chain_trust: {report.scores.supply_chain_trust}",
        f"{render_message(language, 'text.trust_profile')}: ",
        f"  publisher_confidence: {report.trust_profile.publisher_confidence}",
        f"  provenance_status: {report.trust_profile.provenance_status}",
        f"  permission_transparency: {report.trust_profile.permission_transparency}",
        f"  version_stability: {report.trust_profile.version_stability}",
        "",
    ]
    for finding in report.findings:
        lines.append(
            f"- [{finding.severity.value.upper()}] {render_message(language, f'{finding.taxonomy_id}.title')} ({finding.id})"
        )
        lines.append(f"  {render_message(language, 'text.taxonomy')}: {finding.taxonomy_id}")
        lines.append(f"  {render_message(language, 'text.stage')}: {finding.stage.value}")
        lines.append(f"  {render_message(language, 'text.confidence')}: {finding.confidence:.2f}")
        lines.append(f"  {render_message(language, 'text.impact')}: {render_message(language, f'{finding.taxonomy_id}.impact')}")
        for ev in finding.evidence[:3]:
            location = f"{ev.file}:{ev.line}" if ev.line else ev.file
            excerpt = f" — {ev.excerpt}" if ev.excerpt else ""
            lines.append(f"    * {location}{excerpt}")
        lines.append(f"  {render_message(language, 'text.remediation')}: {render_message(language, f'{finding.taxonomy_id}.remediation')}")
        lines.append("")
    if report.flows:
        lines.append(f"{render_message(language, 'text.flows')}:")
        for flow in report.flows:
            lines.append(
                f"- {flow['id']} [{', '.join(flow['triggered_taxonomy_ids'])}] -> {flow['sink_type']}: {flow['summary']}"
            )
        lines.append("")
    if report.runtime_trace:
        lines.append(f"{render_message(language, 'text.sandbox')}: ")
        for key, value in report.runtime_trace.items():
            lines.append(f"  {key}: {value}")
    return "\n".join(lines).strip() + "\n"



def _to_sarif(report: ScanReport) -> dict[str, Any]:
    language = report.output_language
    rules = []
    results = []
    seen_rules = set()
    for finding in report.findings:
        if finding.taxonomy_id not in seen_rules:
            rules.append(
                {
                    "id": finding.taxonomy_id,
                    "name": render_message(language, f"{finding.taxonomy_id}.title"),
                    "shortDescription": {"text": render_message(language, f"{finding.taxonomy_id}.title")},
                    "fullDescription": {"text": render_message(language, f"{finding.taxonomy_id}.impact")},
                    "properties": {
                        "taxonomy_id": finding.taxonomy_id,
                        "stage": finding.stage.value,
                        "tags": finding.tags,
                    },
                }
            )
            seen_rules.add(finding.taxonomy_id)
        for evidence in finding.evidence or [None]:
            result = {
                "ruleId": finding.taxonomy_id,
                "level": _sarif_level(finding.severity.value),
                "message": {"text": render_message(language, f"{finding.taxonomy_id}.impact")},
                "properties": {
                    "finding_id": finding.id,
                    "confidence": finding.confidence,
                    "decision_hint": finding.decision_hint.value,
                    "remediation": render_message(language, f"{finding.taxonomy_id}.remediation"),
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


def _diff_to_text(report: dict[str, Any]) -> str:
    language = report.get("output_language", "zh")
    diff = report["diff"]
    lines = [
        f"{render_message(language, 'diff.old_target')}: {diff['old_target']}",
        f"{render_message(language, 'diff.new_target')}: {diff['new_target']}",
        f"{render_message(language, 'diff.old_decision')}: {diff['old_decision']}",
        f"{render_message(language, 'diff.new_decision')}: {diff['new_decision']}",
        f"{render_message(language, 'diff.decision_changed')}: {str(diff['decision_changed']).lower()}",
        f"{render_message(language, 'diff.added_taxonomy_ids')}: {', '.join(diff['added_taxonomy_ids']) or '-'}",
        f"{render_message(language, 'diff.removed_taxonomy_ids')}: {', '.join(diff['removed_taxonomy_ids']) or '-'}",
        f"{render_message(language, 'diff.permission_drift')}:",
    ]
    for key, value in diff["permission_drift"].items():
        if value["changed"]:
            lines.append(f"  - {key}: {_text_value(value['old'])} -> {_text_value(value['new'])}")
    if all(not value["changed"] for value in diff["permission_drift"].values()):
        lines.append("  - none")
    lines.append(f"{render_message(language, 'diff.trust_profile_drift')}:")
    for key, value in diff["trust_profile_drift"].items():
        if value["changed"]:
            lines.append(f"  - {key}: {_text_value(value['old'])} -> {_text_value(value['new'])}")
    if all(not value["changed"] for value in diff["trust_profile_drift"].values()):
        lines.append("  - none")
    return "\n".join(lines).strip() + "\n"


def _text_value(value: Any) -> str:
    if isinstance(value, bool):
        return str(value).lower()
    return str(value)
