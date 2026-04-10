from __future__ import annotations

from collections import Counter
from typing import Any

from skill_safe.models import Decision, Finding, Severity, TrustProfile


DECISION_PRIORITY = {
    Decision.allow: 0,
    Decision.review: 1,
    Decision.sandbox_only: 2,
    Decision.block: 3,
}



def decide_findings(findings: list[Finding]) -> Decision:
    decision = Decision.allow
    for finding in findings:
        if DECISION_PRIORITY[finding.decision_hint] > DECISION_PRIORITY[decision]:
            decision = finding.decision_hint
    return decision



def build_provenance(artifacts: dict[str, Any], findings: list[Finding]) -> dict[str, Any]:
    urls = artifacts.get("urls", [])
    permission_hints = artifacts.get("permission_hints", [])
    taxonomy_ids = sorted({finding.taxonomy_id for finding in findings})
    return {
        "publisher_identity": artifacts.get("publisher_identity"),
        "repository_url": artifacts.get("repository_url"),
        "release_ref": artifacts.get("release_ref"),
        "signature_status": "unknown",
        "content_hash": artifacts.get("content_hash"),
        "urls": urls,
        "permission_hints": permission_hints,
        "triggered_taxonomy_ids": taxonomy_ids,
    }



def build_trust_profile(artifacts: dict[str, Any], findings: list[Finding], supply_chain_trust: int) -> TrustProfile:
    taxonomy_ids = {finding.taxonomy_id for finding in findings}
    permission_hints = artifacts.get("permission_hints", [])
    has_identity = bool(artifacts.get("publisher_identity"))
    has_repo = bool(artifacts.get("repository_url"))
    publisher_confidence = "unknown"
    if has_identity or has_repo:
        publisher_confidence = "medium"
    if has_identity and has_repo and "SC-004" not in taxonomy_ids:
        publisher_confidence = "high"
    provenance_status = "missing"
    if artifacts.get("manifest_present") and (has_identity or has_repo):
        provenance_status = "partial"
    if artifacts.get("manifest_present") and has_identity and has_repo and "SC-004" not in taxonomy_ids:
        provenance_status = "present"
    permission_transparency = "clear"
    joined = " ".join(str(item).lower() for item in permission_hints)
    if any(token in joined for token in ("shell", "full filesystem", "unrestricted network", "root", "sudo")):
        permission_transparency = "broad"
    elif permission_hints:
        permission_transparency = "partial"
    version_stability = "unknown"
    if any("unpinned-reference" in finding.id for finding in findings):
        version_stability = "floating"
    elif artifacts.get("manifest_present") and "SC-004" not in taxonomy_ids:
        version_stability = "stable"
    return TrustProfile(
        publisher_confidence=publisher_confidence,
        provenance_status=provenance_status,
        permission_transparency=permission_transparency,
        version_stability=version_stability,
        continuous_monitoring_status="not_configured",
        security_score=max(0, min(100, supply_chain_trust)),
    )



def build_summary(findings: list[Finding]) -> dict[str, Any]:
    severities = Counter(f.severity.value for f in findings)
    categories = Counter(f.category for f in findings)
    taxonomy = Counter(f.taxonomy_id for f in findings)
    stages = Counter(f.stage.value for f in findings)
    decisions = Counter(f.decision_hint.value for f in findings)
    return {
        "finding_count": len(findings),
        "severity_breakdown": dict(sorted(severities.items())),
        "category_breakdown": dict(sorted(categories.items())),
        "taxonomy_breakdown": dict(sorted(taxonomy.items())),
        "stage_breakdown": dict(sorted(stages.items())),
        "decision_hint_breakdown": dict(sorted(decisions.items())),
    }
