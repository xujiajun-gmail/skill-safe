from __future__ import annotations

from typing import Any

from skill_safe.models import Decision, Evidence, Finding, Severity, SkillIR, Stage


def run_flow_analysis(skill: SkillIR, findings: list[Finding]) -> tuple[list[Finding], list[dict[str, Any]]]:
    flow_findings: list[Finding] = []
    flows: list[dict[str, Any]] = []

    prompt_sources = [finding for finding in findings if finding.taxonomy_id in {"PI-001", "PI-002"}]
    shell_sinks = [finding for finding in findings if finding.taxonomy_id in {"EX-001", "EX-002", "PR-003"}]
    context_sinks = [finding for finding in findings if finding.taxonomy_id in {"MP-001", "DA-003"}]
    action_sinks = [finding for finding in findings if finding.taxonomy_id in {"EX-004", "PR-002", "MP-002"}]
    secret_sources = [finding for finding in findings if finding.taxonomy_id in {"DA-001", "DA-003"} and _is_secret_source(finding)]
    external_sinks = [finding for finding in findings if _is_external_sink(finding)]

    if prompt_sources and shell_sinks:
        flow_findings.append(
            _make_flow_finding(
                taxonomy_id="CH-001",
                severity=Severity.critical,
                decision=Decision.block,
                evidence=_merge_evidence(prompt_sources, shell_sinks),
                tags=["flow", "shell", "untrusted-input"],
                suffix="untrusted-string-to-shell",
            )
        )
        flows.append(
            _make_flow_entry(
                flow_id="flow.ch001.untrusted-string-to-shell",
                source_type="tool_output" if any(f.taxonomy_id == "PI-002" for f in prompt_sources) else "prompt_text",
                source_skill=_skill_name(skill),
                transform="Untrusted text can cross a prompt/tool boundary and reach shell execution surfaces.",
                sink_type="shell",
                sink_target=_sink_target(shell_sinks),
                triggered_taxonomy_ids=["CH-001", *_unique_taxonomy_ids(prompt_sources + shell_sinks)],
                summary="Potential chain: untrusted string can influence command execution.",
            )
        )

    if prompt_sources and context_sinks:
        flow_findings.append(
            _make_flow_finding(
                taxonomy_id="CH-002",
                severity=Severity.high,
                decision=Decision.review,
                evidence=_merge_evidence(prompt_sources, context_sinks),
                tags=["flow", "prompt", "context"],
                suffix="untrusted-string-to-context",
            )
        )
        flows.append(
            _make_flow_entry(
                flow_id="flow.ch002.untrusted-string-to-context",
                source_type="tool_output" if any(f.taxonomy_id == "PI-002" for f in prompt_sources) else "prompt_text",
                source_skill=_skill_name(skill),
                transform="Untrusted text can be promoted into memory, system notes, or long-lived context.",
                sink_type="context",
                sink_target=_sink_target(context_sinks),
                triggered_taxonomy_ids=["CH-002", *_unique_taxonomy_ids(prompt_sources + context_sinks)],
                summary="Potential chain: untrusted content can become persistent context or hidden instructions.",
            )
        )

    if prompt_sources and action_sinks:
        flow_findings.append(
            _make_flow_finding(
                taxonomy_id="CH-003",
                severity=Severity.high,
                decision=Decision.review,
                evidence=_merge_evidence(prompt_sources, action_sinks),
                tags=["flow", "sensitive-action", "untrusted-input"],
                suffix="untrusted-string-to-parameter",
            )
        )
        flows.append(
            _make_flow_entry(
                flow_id="flow.ch003.untrusted-string-to-parameter",
                source_type="tool_output" if any(f.taxonomy_id == "PI-002" for f in prompt_sources) else "prompt_text",
                source_skill=_skill_name(skill),
                transform="Untrusted text can influence sensitive action parameters such as delete targets, network destinations, or workspace writes.",
                sink_type="sensitive_action",
                sink_target=_sink_target(action_sinks),
                triggered_taxonomy_ids=["CH-003", *_unique_taxonomy_ids(prompt_sources + action_sinks)],
                summary="Potential chain: untrusted content can steer destructive or boundary-crossing actions.",
            )
        )

    if secret_sources and external_sinks:
        flow_findings.append(
            _make_flow_finding(
                taxonomy_id="CH-004",
                severity=Severity.critical,
                decision=Decision.block,
                evidence=_merge_evidence(secret_sources, external_sinks),
                tags=["flow", "secrets", "exfiltration"],
                suffix="secret-to-egress",
            )
        )
        flows.append(
            _make_flow_entry(
                flow_id="flow.ch004.secret-to-egress",
                source_type="secret_material",
                source_skill=_skill_name(skill),
                transform="Sensitive material can be read locally and then forwarded to an external sink.",
                sink_type="external_sink",
                sink_target=_sink_target(external_sinks),
                triggered_taxonomy_ids=["CH-004", *_unique_taxonomy_ids(secret_sources + external_sinks)],
                summary="Potential chain: secrets read locally can leave the host through network or upload paths.",
            )
        )

    return _dedupe_flow_findings(flow_findings), _dedupe_flows(flows)


def apply_flow_decisions(flows: list[dict[str, Any]], findings: list[Finding]) -> list[dict[str, Any]]:
    decision_by_taxonomy = {}
    for finding in findings:
        current = decision_by_taxonomy.get(finding.taxonomy_id, Decision.allow)
        if _decision_rank(finding.decision_hint) > _decision_rank(current):
            decision_by_taxonomy[finding.taxonomy_id] = finding.decision_hint
    updated: list[dict[str, Any]] = []
    for flow in flows:
        triggered = flow.get("triggered_taxonomy_ids", [])
        blocked = any(
            decision_by_taxonomy.get(taxonomy_id, Decision.allow) in {Decision.block, Decision.sandbox_only}
            for taxonomy_id in triggered
        )
        updated.append({**flow, "blocked_by_policy": blocked})
    return updated


def _make_flow_finding(
    taxonomy_id: str,
    severity: Severity,
    decision: Decision,
    evidence: list[Evidence],
    tags: list[str],
    suffix: str,
) -> Finding:
    return Finding(
        id=f"flow.{taxonomy_id.lower()}.{suffix}",
        taxonomy_id=taxonomy_id,
        stage=Stage.flow,
        severity=severity,
        category="flow",
        confidence=0.78,
        decision_hint=decision,
        evidence=evidence[:6] or [Evidence(file="<flow>", detail="Flow-level risk inferred from chained signals.")],
        tags=tags,
    )


def _make_flow_entry(
    flow_id: str,
    source_type: str,
    source_skill: str,
    transform: str,
    sink_type: str,
    sink_target: str,
    triggered_taxonomy_ids: list[str],
    summary: str,
) -> dict[str, Any]:
    return {
        "id": flow_id,
        "source_type": source_type,
        "source_skill": source_skill,
        "transform": transform,
        "sink_type": sink_type,
        "sink_target": sink_target,
        "triggered_taxonomy_ids": triggered_taxonomy_ids,
        "blocked_by_policy": False,
        "summary": summary,
    }


def _merge_evidence(left: list[Finding], right: list[Finding]) -> list[Evidence]:
    merged: list[Evidence] = []
    for finding in [*left, *right]:
        for item in finding.evidence:
            merged.append(item)
            if len(merged) >= 6:
                return merged
    return merged


def _skill_name(skill: SkillIR) -> str:
    manifest = skill.manifest or {}
    return str(manifest.get("name") or manifest.get("display_name") or skill.root.name)


def _sink_target(findings: list[Finding]) -> str:
    for finding in findings:
        for item in finding.evidence:
            if item.excerpt:
                return item.excerpt
    for finding in findings:
        if finding.evidence:
            return finding.evidence[0].detail
    return "<unknown>"


def _unique_taxonomy_ids(findings: list[Finding]) -> list[str]:
    return sorted({finding.taxonomy_id for finding in findings})


def _is_external_sink(finding: Finding) -> bool:
    if finding.taxonomy_id == "PR-002":
        return False
    tags = set(finding.tags)
    if {"egress", "upload"} & tags or {"egress", "post"} & tags:
        return True
    if finding.taxonomy_id == "DA-001" and "external-network" in tags:
        return True
    for item in finding.evidence:
        excerpt = (item.excerpt or "").lower()
        if excerpt.startswith(("http://", "https://")) and not any(
            token in excerpt for token in ("127.0.0.1", "localhost", "169.254.169.254", "192.168.", "10.")
        ):
            return True
    return False


def _is_secret_source(finding: Finding) -> bool:
    tags = set(finding.tags)
    return bool(tags & {"credentials", "ssh", "wallet", "memory", "persona", "env"})


def _dedupe_flow_findings(findings: list[Finding]) -> list[Finding]:
    unique: dict[str, Finding] = {}
    for finding in findings:
        unique[finding.id] = finding
    return list(unique.values())


def _dedupe_flows(flows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: dict[str, dict[str, Any]] = {}
    for flow in flows:
        unique[flow["id"]] = flow
    return list(unique.values())


def _decision_rank(decision: Decision) -> int:
    return {
        Decision.allow: 0,
        Decision.review: 1,
        Decision.sandbox_only: 2,
        Decision.block: 3,
    }[decision]
