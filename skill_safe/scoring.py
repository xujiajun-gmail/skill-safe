from __future__ import annotations

from collections import Counter

from skill_safe.models import Finding, ScoreCard, Severity

SEVERITY_POINTS = {
    Severity.info: 2,
    Severity.low: 8,
    Severity.medium: 18,
    Severity.high: 30,
    Severity.critical: 45,
}



def score_findings(findings: list[Finding]) -> ScoreCard:
    category_counts = Counter(finding.category for finding in findings)
    severity_points = sum(SEVERITY_POINTS[finding.severity] for finding in findings)
    malice = min(100, severity_points + 10 * category_counts.get("semantic", 0) + 8 * category_counts.get("prompt_safety", 0))
    exploitability = min(100, severity_points + 12 * category_counts.get("execution", 0) + 10 * category_counts.get("network", 0))
    blast_radius = min(100, severity_points + 12 * category_counts.get("exfiltration", 0) + 10 * category_counts.get("secrets", 0))
    privilege_excess = min(100, 15 * category_counts.get("permissions", 0) + 12 * category_counts.get("execution", 0) + 8 * category_counts.get("network", 0))
    supply_chain_trust = max(0, 100 - (12 * category_counts.get("supply_chain", 0) + 5 * len(findings)))
    overall = _overall_label(malice, exploitability, blast_radius, privilege_excess, supply_chain_trust)
    return ScoreCard(
        malice_likelihood=malice,
        exploitability=exploitability,
        blast_radius=blast_radius,
        privilege_excess=privilege_excess,
        supply_chain_trust=supply_chain_trust,
        overall=overall,
    )



def _overall_label(
    malice_likelihood: int,
    exploitability: int,
    blast_radius: int,
    privilege_excess: int,
    supply_chain_trust: int,
) -> str:
    danger = max(malice_likelihood, exploitability, blast_radius, privilege_excess, 100 - supply_chain_trust)
    if danger >= 85:
        return "critical"
    if danger >= 65:
        return "high"
    if danger >= 40:
        return "medium"
    return "low"
