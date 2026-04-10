from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from skill_safe.models import Decision, Evidence, Finding, Severity, SkillIR, Stage


@dataclass(frozen=True, slots=True)
class CapabilityNode:
    node_id: str
    role: str
    capability_type: str
    taxonomy_id: str
    finding_id: str
    label: str
    finding: Finding


@dataclass(frozen=True, slots=True)
class CapabilityEdge:
    edge_id: str
    source_node_id: str
    sink_node_id: str
    transform: str
    triggered_taxonomy_ids: tuple[str, ...]
    summary: str


def run_flow_analysis(skill: SkillIR, findings: list[Finding]) -> tuple[list[Finding], list[dict[str, Any]]]:
    graph = build_capability_graph(skill, findings)
    flow_findings: list[Finding] = []
    flows: list[dict[str, Any]] = []
    node_by_id = {node.node_id: node for node in graph["nodes"]}

    for edge in graph["edges"]:
        source = node_by_id[edge.source_node_id]
        sink = node_by_id[edge.sink_node_id]
        taxonomy_id, severity, decision, tags, sink_type = _edge_profile(edge)
        evidence = _merge_evidence(source.finding, sink.finding)
        flow_findings.append(
            Finding(
                id=f"flow.{taxonomy_id.lower()}.{source.capability_type}-to-{sink.capability_type}",
                taxonomy_id=taxonomy_id,
                stage=Stage.flow,
                severity=severity,
                category="flow",
                confidence=0.8,
                decision_hint=decision,
                evidence=evidence[:6] or [Evidence(file="<flow>", detail="Graph-based chained risk inferred.")],
                tags=tags,
            )
        )
        flows.append(
            {
                "id": edge.edge_id,
                "source_type": source.capability_type,
                "source_skill": _skill_name(skill),
                "source_node": _node_to_dict(source),
                "sink_node": _node_to_dict(sink),
                "transform": edge.transform,
                "sink_type": sink_type,
                "sink_target": sink.label,
                "triggered_taxonomy_ids": list(edge.triggered_taxonomy_ids),
                "blocked_by_policy": False,
                "summary": edge.summary,
                "path": [source.node_id, sink.node_id],
                "path_labels": [source.label, sink.label],
            }
        )

    return _dedupe_flow_findings(flow_findings), _dedupe_flows(flows)


def build_capability_graph(skill: SkillIR, findings: list[Finding]) -> dict[str, list[Any]]:
    nodes = _extract_nodes(skill, findings)
    edges: list[CapabilityEdge] = []
    sources = [node for node in nodes if node.role == "source"]
    sinks = [node for node in nodes if node.role == "sink"]
    supports = [node for node in nodes if node.role == "support"]
    for source in sources:
        for sink in sinks:
            edge = _connect_nodes(skill, source, sink, supports)
            if edge is not None:
                edges.append(edge)
    return {"nodes": nodes, "edges": _dedupe_edges(edges)}


def apply_flow_decisions(flows: list[dict[str, Any]], findings: list[Finding]) -> list[dict[str, Any]]:
    decision_by_taxonomy: dict[str, Decision] = {}
    for finding in findings:
        current = decision_by_taxonomy.get(finding.taxonomy_id, Decision.allow)
        if _decision_rank(finding.decision_hint) > _decision_rank(current):
            decision_by_taxonomy[finding.taxonomy_id] = finding.decision_hint
    updated: list[dict[str, Any]] = []
    for flow in flows:
        blocked = any(
            decision_by_taxonomy.get(taxonomy_id, Decision.allow) in {Decision.block, Decision.sandbox_only}
            for taxonomy_id in flow.get("triggered_taxonomy_ids", [])
        )
        updated.append({**flow, "blocked_by_policy": blocked})
    return updated


def _extract_nodes(skill: SkillIR, findings: list[Finding]) -> list[CapabilityNode]:
    nodes: list[CapabilityNode] = []
    repo_urls = set(_provenance_urls(skill))
    for finding in findings:
        source = _source_node(finding)
        if source is not None:
            nodes.append(source)
        sink = _sink_node(finding, repo_urls)
        if sink is not None:
            nodes.append(sink)
    return _dedupe_nodes(nodes)


def _source_node(finding: Finding) -> CapabilityNode | None:
    tags = set(finding.tags)
    if finding.taxonomy_id in {"PI-001", "PI-002"}:
        capability_type = "tool_output" if "tool-poisoning" in tags else "prompt_text"
        return _make_node("source", capability_type, finding)
    if finding.taxonomy_id in {"DA-001", "DA-003"} and tags & {"credentials", "ssh", "wallet", "memory", "persona", "env"}:
        return _make_node("source", "secret_material", finding)
    return None


def _sink_node(finding: Finding, repo_urls: set[str]) -> CapabilityNode | None:
    tags = set(finding.tags)
    if finding.taxonomy_id == "EX-003" and "shell" in tags:
        return _make_node("support", "shell_capability", finding)
    if finding.taxonomy_id in {"EX-001", "EX-002"}:
        return _make_node("sink", "shell", finding)
    if finding.taxonomy_id == "PR-003":
        return _make_node("sink", "shell", finding)
    if finding.taxonomy_id == "MP-001" and tags & {"write", "persist"}:
        return _make_node("sink", "context_write", finding)
    if finding.taxonomy_id in {"EX-004", "MP-002", "PR-002"}:
        return _make_node("sink", "sensitive_action", finding)
    if finding.taxonomy_id == "DA-001" and _is_external_egress(finding, repo_urls):
        return _make_node("sink", "external_egress", finding)
    return None


def _make_node(role: str, capability_type: str, finding: Finding) -> CapabilityNode:
    label = _node_label(finding)
    return CapabilityNode(
        node_id=f"{role}.{capability_type}.{finding.id}",
        role=role,
        capability_type=capability_type,
        taxonomy_id=finding.taxonomy_id,
        finding_id=finding.id,
        label=label,
        finding=finding,
    )


def _node_label(finding: Finding) -> str:
    for item in finding.evidence:
        if item.excerpt:
            return item.excerpt
    if finding.evidence:
        return finding.evidence[0].detail
    return finding.id


def _node_to_dict(node: CapabilityNode) -> dict[str, Any]:
    return {
        "node_id": node.node_id,
        "role": node.role,
        "capability_type": node.capability_type,
        "taxonomy_id": node.taxonomy_id,
        "finding_id": node.finding_id,
        "label": node.label,
        "evidence_refs": _evidence_refs(node.finding),
    }


def _connect_nodes(
    skill: SkillIR,
    source: CapabilityNode,
    sink: CapabilityNode,
    supports: list[CapabilityNode],
) -> CapabilityEdge | None:
    if source.capability_type in {"tool_output", "prompt_text"} and sink.capability_type == "shell":
        return _make_edge(
            "flow.ch001.untrusted-string-to-shell",
            source,
            sink,
            transform="Untrusted text can cross a prompt/tool boundary and reach shell execution surfaces.",
            triggered=_triggered_ids(source, sink, "CH-001", supports),
            summary="Potential chain: untrusted string can influence command execution.",
        )
    if source.capability_type in {"tool_output", "prompt_text"} and sink.capability_type == "context_write":
        return _make_edge(
            "flow.ch002.untrusted-string-to-context",
            source,
            sink,
            transform="Untrusted text can be promoted into memory, system notes, or long-lived context.",
            triggered=_triggered_ids(source, sink, "CH-002", supports),
            summary="Potential chain: untrusted content can become persistent context or hidden instructions.",
        )
    if source.capability_type in {"tool_output", "prompt_text"} and sink.capability_type == "sensitive_action":
        return _make_edge(
            "flow.ch003.untrusted-string-to-parameter",
            source,
            sink,
            transform="Untrusted text can influence sensitive action parameters such as delete targets, network destinations, or workspace writes.",
            triggered=_triggered_ids(source, sink, "CH-003", supports),
            summary="Potential chain: untrusted content can steer destructive or boundary-crossing actions.",
        )
    if source.capability_type == "secret_material" and sink.capability_type == "external_egress":
        return _make_edge(
            "flow.ch004.secret-to-egress",
            source,
            sink,
            transform="Sensitive material can be read locally and then forwarded to an external sink.",
            triggered=_triggered_ids(source, sink, "CH-004", supports),
            summary="Potential chain: secrets read locally can leave the host through network or upload paths.",
        )
    return None


def _make_edge(
    edge_id: str,
    source: CapabilityNode,
    sink: CapabilityNode,
    transform: str,
    triggered: tuple[str, ...],
    summary: str,
) -> CapabilityEdge:
    return CapabilityEdge(
        edge_id=edge_id,
        source_node_id=source.node_id,
        sink_node_id=sink.node_id,
        transform=transform,
        triggered_taxonomy_ids=triggered,
        summary=summary,
    )


def _triggered_ids(
    source: CapabilityNode,
    sink: CapabilityNode,
    chain_taxonomy: str,
    supports: list[CapabilityNode],
) -> tuple[str, ...]:
    taxonomy_ids = {chain_taxonomy, source.taxonomy_id, sink.taxonomy_id}
    if sink.capability_type in {"shell", "sensitive_action"}:
        for node in supports:
            if node.capability_type == "shell_capability":
                taxonomy_ids.add(node.taxonomy_id)
    return tuple(sorted(taxonomy_ids))


def _edge_profile(edge: CapabilityEdge) -> tuple[str, Severity, Decision, list[str], str]:
    if edge.edge_id == "flow.ch001.untrusted-string-to-shell":
        return "CH-001", Severity.critical, Decision.block, ["flow", "shell", "untrusted-input"], "shell"
    if edge.edge_id == "flow.ch002.untrusted-string-to-context":
        return "CH-002", Severity.high, Decision.review, ["flow", "prompt", "context"], "context"
    if edge.edge_id == "flow.ch003.untrusted-string-to-parameter":
        return "CH-003", Severity.high, Decision.review, ["flow", "sensitive-action", "untrusted-input"], "sensitive_action"
    return "CH-004", Severity.critical, Decision.block, ["flow", "secrets", "exfiltration"], "external_sink"


def _provenance_urls(skill: SkillIR) -> list[str]:
    manifest = skill.manifest or {}
    urls: list[str] = []
    for key in ("repository", "homepage", "url"):
        value = manifest.get(key)
        if isinstance(value, str):
            urls.append(value.strip().lower())
    return urls


def _is_external_egress(finding: Finding, repo_urls: set[str]) -> bool:
    tags = set(finding.tags)
    if {"egress", "upload"} & tags or {"egress", "post"} & tags:
        return True
    for item in finding.evidence:
        excerpt = (item.excerpt or "").strip().lower()
        if not excerpt.startswith(("http://", "https://")):
            continue
        if excerpt in repo_urls:
            continue
        if any(token in excerpt for token in ("127.0.0.1", "localhost", "169.254.169.254", "192.168.", "10.")):
            continue
        return True
    return False


def _merge_evidence(left: Finding, right: Finding) -> list[Evidence]:
    merged: list[Evidence] = []
    for finding in (left, right):
        for item in finding.evidence:
            merged.append(item)
            if len(merged) >= 6:
                return merged
    return merged


def _evidence_refs(finding: Finding) -> list[str]:
    refs: list[str] = []
    for item in finding.evidence:
        if item.line is not None:
            refs.append(f"{item.file}:{item.line}")
        else:
            refs.append(item.file)
    return refs[:6]


def _skill_name(skill: SkillIR) -> str:
    manifest = skill.manifest or {}
    return str(manifest.get("name") or manifest.get("display_name") or skill.root.name)


def _dedupe_nodes(nodes: list[CapabilityNode]) -> list[CapabilityNode]:
    unique: dict[str, CapabilityNode] = {}
    for node in nodes:
        unique[node.node_id] = node
    return list(unique.values())


def _dedupe_edges(edges: list[CapabilityEdge]) -> list[CapabilityEdge]:
    unique: dict[str, CapabilityEdge] = {}
    for edge in edges:
        if edge.edge_id not in unique:
            unique[edge.edge_id] = edge
    return list(unique.values())


def _dedupe_flow_findings(findings: list[Finding]) -> list[Finding]:
    unique: dict[str, Finding] = {}
    for finding in findings:
        unique[finding.id] = finding
    return list(unique.values())


def _dedupe_flows(flows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: dict[str, dict[str, Any]] = {}
    for flow in flows:
        if flow["id"] not in unique:
            unique[flow["id"]] = flow
    return list(unique.values())


def _decision_rank(decision: Decision) -> int:
    return {
        Decision.allow: 0,
        Decision.review: 1,
        Decision.sandbox_only: 2,
        Decision.block: 3,
    }[decision]
