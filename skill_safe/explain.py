from __future__ import annotations

import json
from typing import Any

from skill_safe.i18n import render_message


def load_report_payload(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError("Explain input must be a JSON object report.")
    return payload


def render_explanation(payload: dict[str, Any], language: str, output_format: str = "text") -> str:
    explanation = build_explanation(payload, language)
    if output_format == "json":
        return json.dumps(explanation, indent=2, ensure_ascii=False)
    return _explanation_to_text(explanation)


def build_explanation(payload: dict[str, Any], language: str) -> dict[str, Any]:
    if "diff" in payload:
        return _build_diff_explanation(payload, language)
    return _build_scan_explanation(payload, language)


def _build_scan_explanation(payload: dict[str, Any], language: str) -> dict[str, Any]:
    summary = payload.get("summary", {})
    findings = payload.get("findings", [])
    flows = payload.get("flows", [])
    top_findings = findings[:3]
    finding_lines = []
    for finding in top_findings:
        finding_lines.append(
            {
                "taxonomy_id": finding.get("taxonomy_id"),
                "title": finding.get("title") or render_message(language, f"{finding.get('taxonomy_id')}.title"),
                "why_it_matters": finding.get("impact") or render_message(language, f"{finding.get('taxonomy_id')}.impact"),
                "what_to_do": finding.get("remediation") or render_message(language, f"{finding.get('taxonomy_id')}.remediation"),
            }
        )

    notable_evidence = []
    for finding in top_findings:
        for item in finding.get("evidence", [])[:2]:
            notable_evidence.append(
                {
                    "taxonomy_id": finding.get("taxonomy_id"),
                    "file": item.get("file"),
                    "line": item.get("line"),
                    "excerpt": item.get("excerpt"),
                }
            )
    return {
        "kind": "scan",
        "output_language": language,
        "target": payload.get("target"),
        "decision": payload.get("decision"),
        "headline": render_message(language, f"explain.scan.headline.{payload.get('decision', 'review')}"),
        "summary": {
            "finding_count": summary.get("finding_count", 0),
            "top_taxonomy_ids": _top_keys(summary.get("taxonomy_breakdown", {}), limit=5),
        },
        "narrative": [
            render_message(
                language,
                "explain.scan.narrative.findings",
                count=summary.get("finding_count", 0),
            ),
            render_message(
                language,
                "explain.scan.narrative.flows",
                count=len(flows),
            ),
            render_message(
                language,
                "explain.scan.narrative.decision",
                decision=payload.get("decision", "review"),
                reason=payload.get("decision_reason", ""),
            ),
        ],
        "key_findings": finding_lines,
        "key_flows": [
            {
                "id": flow.get("id"),
                "triggered_taxonomy_ids": flow.get("triggered_taxonomy_ids", []),
                "summary": flow.get("summary"),
            }
            for flow in flows[:3]
        ],
        "notable_evidence": notable_evidence,
        "recommended_actions": _scan_actions(payload, language),
    }


def _build_diff_explanation(payload: dict[str, Any], language: str) -> dict[str, Any]:
    diff = payload.get("diff", {})
    changed_permissions = [key for key, value in diff.get("permission_drift", {}).items() if value.get("changed")]
    changed_trust = [key for key, value in diff.get("trust_profile_drift", {}).items() if value.get("changed")]
    return {
        "kind": "diff",
        "output_language": language,
        "target": diff.get("new_target"),
        "decision": diff.get("new_decision"),
        "headline": render_message(
            language,
            "explain.diff.headline.changed" if diff.get("decision_changed") else "explain.diff.headline.stable",
        ),
        "summary": {
            "added_taxonomy_ids": diff.get("added_taxonomy_ids", []),
            "removed_taxonomy_ids": diff.get("removed_taxonomy_ids", []),
            "decision_changed": diff.get("decision_changed", False),
        },
        "narrative": [
            render_message(
                language,
                "explain.diff.narrative.decision",
                old=diff.get("old_decision", "allow"),
                new=diff.get("new_decision", "allow"),
            ),
            render_message(
                language,
                "explain.diff.narrative.taxonomy",
                added=", ".join(diff.get("added_taxonomy_ids", [])) or "-",
                removed=", ".join(diff.get("removed_taxonomy_ids", [])) or "-",
            ),
        ],
        "key_changes": {
            "permissions": changed_permissions,
            "trust_profile": changed_trust,
        },
        "recommended_actions": _diff_actions(payload, language),
    }


def _scan_actions(payload: dict[str, Any], language: str) -> list[str]:
    decision = payload.get("decision")
    taxonomy = set(payload.get("summary", {}).get("taxonomy_breakdown", {}))
    actions: list[str] = []
    if decision == "block":
        actions.append(render_message(language, "explain.action.blocked"))
    if "EX-001" in taxonomy or "EX-004" in taxonomy:
        actions.append(render_message(language, "explain.action.isolate"))
    if any(key in taxonomy for key in ("DA-001", "DA-002", "DA-003")):
        actions.append(render_message(language, "explain.action.rotate"))
    if not actions:
        actions.append(render_message(language, "explain.action.review"))
    return actions


def _diff_actions(payload: dict[str, Any], language: str) -> list[str]:
    diff = payload.get("diff", {})
    actions: list[str] = []
    if diff.get("decision_changed"):
        actions.append(render_message(language, "explain.action.reaudit"))
    if diff.get("added_taxonomy_ids"):
        actions.append(render_message(language, "explain.action.recheck_permissions"))
    if any(value.get("changed") for value in diff.get("permission_drift", {}).values()):
        actions.append(render_message(language, "explain.action.compare_permissions"))
    if not actions:
        actions.append(render_message(language, "explain.action.review"))
    return actions


def _top_keys(counter_like: dict[str, Any], limit: int) -> list[str]:
    items = sorted(counter_like.items(), key=lambda item: (item[1], item[0]), reverse=True)
    return [key for key, _ in items[:limit]]


def _explanation_to_text(explanation: dict[str, Any]) -> str:
    language = explanation.get("output_language", "zh")
    lines = [
        f"{render_message(language, 'explain.kind')}: {explanation.get('kind')}",
        f"{render_message(language, 'text.target')}: {explanation.get('target')}",
        f"{render_message(language, 'text.decision')}: {explanation.get('decision')}",
        f"{render_message(language, 'explain.headline')}: {explanation.get('headline')}",
        "",
    ]
    if explanation.get("narrative"):
        lines.append(f"{render_message(language, 'explain.narrative')}:")
        for item in explanation["narrative"]:
            lines.append(f"- {item}")
        lines.append("")
    if explanation.get("key_findings"):
        lines.append(f"{render_message(language, 'explain.key_findings')}:")
        for item in explanation["key_findings"]:
            lines.append(f"- {item['taxonomy_id']}: {item['title']}")
            lines.append(f"  {item['why_it_matters']}")
            lines.append(f"  {item['what_to_do']}")
        lines.append("")
    if explanation.get("key_flows"):
        lines.append(f"{render_message(language, 'explain.key_flows')}:")
        for item in explanation["key_flows"]:
            lines.append(f"- {item['id']}: {', '.join(item['triggered_taxonomy_ids'])}")
            lines.append(f"  {item['summary']}")
        lines.append("")
    if explanation.get("key_changes"):
        lines.append(f"{render_message(language, 'explain.key_changes')}:")
        for key, value in explanation["key_changes"].items():
            rendered = ", ".join(value) if value else "-"
            lines.append(f"- {key}: {rendered}")
        lines.append("")
    if explanation.get("recommended_actions"):
        lines.append(f"{render_message(language, 'explain.recommended_actions')}:")
        for item in explanation["recommended_actions"]:
            lines.append(f"- {item}")
    return "\n".join(lines).strip() + "\n"
