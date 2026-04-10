from __future__ import annotations

from typing import Any

from skill_safe import __version__
from skill_safe.models import ScanReport


def build_diff_report(old_report: ScanReport, new_report: ScanReport, output_language: str) -> dict[str, Any]:
    old_taxonomy_ids = _taxonomy_ids(old_report)
    new_taxonomy_ids = _taxonomy_ids(new_report)
    old_permission_profile = _permission_profile(old_report)
    new_permission_profile = _permission_profile(new_report)

    return {
        "schema_version": old_report.schema_version,
        "tool": {"name": "skill-safe", "version": __version__},
        "output_language": output_language,
        "diff": {
            "old_target": old_report.target,
            "new_target": new_report.target,
            "added_taxonomy_ids": sorted(new_taxonomy_ids - old_taxonomy_ids),
            "removed_taxonomy_ids": sorted(old_taxonomy_ids - new_taxonomy_ids),
            "decision_changed": old_report.decision != new_report.decision,
            "old_decision": old_report.decision.value,
            "new_decision": new_report.decision.value,
            "permission_drift": _permission_drift(old_permission_profile, new_permission_profile),
            "trust_profile_drift": _trust_profile_drift(old_report.trust_profile, new_report.trust_profile),
            "finding_count_drift": {
                "old": old_report.summary.get("finding_count", 0),
                "new": new_report.summary.get("finding_count", 0),
                "changed": old_report.summary.get("finding_count", 0) != new_report.summary.get("finding_count", 0),
            },
        },
        "old_summary": old_report.summary,
        "new_summary": new_report.summary,
        "old_trust_profile": {
            "publisher_confidence": old_report.trust_profile.publisher_confidence,
            "provenance_status": old_report.trust_profile.provenance_status,
            "permission_transparency": old_report.trust_profile.permission_transparency,
            "version_stability": old_report.trust_profile.version_stability,
            "continuous_monitoring_status": old_report.trust_profile.continuous_monitoring_status,
            "security_score": old_report.trust_profile.security_score,
        },
        "new_trust_profile": {
            "publisher_confidence": new_report.trust_profile.publisher_confidence,
            "provenance_status": new_report.trust_profile.provenance_status,
            "permission_transparency": new_report.trust_profile.permission_transparency,
            "version_stability": new_report.trust_profile.version_stability,
            "continuous_monitoring_status": new_report.trust_profile.continuous_monitoring_status,
            "security_score": new_report.trust_profile.security_score,
        },
    }


def _taxonomy_ids(report: ScanReport) -> set[str]:
    return {finding.taxonomy_id for finding in report.findings}


def _permission_profile(report: ScanReport) -> dict[str, bool]:
    permission_hints = " ".join(str(item).lower() for item in report.artifacts.get("permission_hints", []))
    taxonomy_ids = _taxonomy_ids(report)
    findings = report.findings
    return {
        "shell": "shell" in permission_hints or any("shell" in finding.tags for finding in findings),
        "network": bool(report.artifacts.get("urls")) or "network" in permission_hints,
        "filesystem": any(token in permission_hints for token in ("filesystem", "write any file", "read all files")),
        "startup_hooks": any(finding.taxonomy_id == "PR-003" for finding in findings),
        "memory_write": any(
            finding.taxonomy_id == "MP-001" and ("write" in finding.tags or "persist" in finding.tags)
            for finding in findings
        ),
        "sensitive_data_access": any(taxonomy_id.startswith("DA-") for taxonomy_id in taxonomy_ids),
    }


def _permission_drift(old_profile: dict[str, bool], new_profile: dict[str, bool]) -> dict[str, dict[str, bool]]:
    drift: dict[str, dict[str, bool]] = {}
    for key in sorted(set(old_profile) | set(new_profile)):
        old_value = old_profile.get(key, False)
        new_value = new_profile.get(key, False)
        drift[key] = {"old": old_value, "new": new_value, "changed": old_value != new_value}
    return drift


def _trust_profile_drift(old_profile: Any, new_profile: Any) -> dict[str, dict[str, Any]]:
    fields = (
        "publisher_confidence",
        "provenance_status",
        "permission_transparency",
        "version_stability",
        "continuous_monitoring_status",
        "security_score",
    )
    drift: dict[str, dict[str, Any]] = {}
    for field in fields:
        old_value = getattr(old_profile, field)
        new_value = getattr(new_profile, field)
        drift[field] = {"old": old_value, "new": new_value, "changed": old_value != new_value}
    return drift
