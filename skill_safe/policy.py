from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

from skill_safe.models import Decision, Finding

DEFAULT_POLICY_PROFILES: dict[str, dict[str, Decision]] = {
    "default": {},
    "strict": {
        "AL-001": Decision.block,
        "AL-003": Decision.block,
        "EX-004": Decision.block,
        "PI-001": Decision.block,
        "PI-002": Decision.block,
        "SC-001": Decision.block,
        "SC-002": Decision.block,
        "SC-004": Decision.review,
        "PR-003": Decision.block,
    },
    "permissive": {
        "AL-001": Decision.review,
        "AL-003": Decision.review,
        "PI-001": Decision.review,
        "PI-002": Decision.review,
        "SC-002": Decision.review,
    },
}

DECISION_PRIORITY = {
    Decision.allow: 0,
    Decision.review: 1,
    Decision.sandbox_only: 2,
    Decision.block: 3,
}


@dataclass(frozen=True, slots=True)
class EnvironmentToggleRule:
    key: str
    taxonomy_id: str
    tags: tuple[str, ...] = ()
    when_disallowed: Decision = Decision.block
    when_allowed: Decision | None = Decision.review


ENVIRONMENT_TOGGLE_RULES: tuple[EnvironmentToggleRule, ...] = (
    EnvironmentToggleRule("allow_shell", "EX-003", tags=("shell",)),
    EnvironmentToggleRule("allow_localhost", "PR-002", tags=("localhost",)),
    EnvironmentToggleRule("allow_private_network", "PR-002", tags=("private-network",)),
    EnvironmentToggleRule("allow_metadata_access", "PR-002", tags=("metadata",)),
    EnvironmentToggleRule("allow_startup_hooks", "PR-003", tags=("hook", "startup")),
    EnvironmentToggleRule("allow_memory_file_write", "MP-001", tags=("memory",)),
)


def apply_policy_profile(findings: list[Finding], profile: str = "default") -> list[Finding]:
    overrides = DEFAULT_POLICY_PROFILES.get(profile, DEFAULT_POLICY_PROFILES["default"])
    return apply_taxonomy_overrides(findings, {key: value.value for key, value in overrides.items()})


def apply_taxonomy_overrides(findings: list[Finding], overrides: dict[str, str]) -> list[Finding]:
    if not overrides:
        return findings
    updated: list[Finding] = []
    for finding in findings:
        override_value = overrides.get(finding.taxonomy_id)
        if override_value is None:
            updated.append(finding)
            continue
        try:
            override = Decision(override_value)
        except ValueError:
            updated.append(finding)
            continue
        updated.append(replace(finding, decision_hint=override))
    return updated


def apply_environment_policy(findings: list[Finding], config: dict[str, Any]) -> list[Finding]:
    policy = config.get("policy", {})
    if not isinstance(policy, dict):
        return findings
    updated: list[Finding] = []
    for finding in findings:
        decision = finding.decision_hint
        for rule in ENVIRONMENT_TOGGLE_RULES:
            if not _matches_environment_rule(finding, rule):
                continue
            is_allowed = _read_policy_boolean(policy, rule.key, default=False)
            target = rule.when_allowed if is_allowed else rule.when_disallowed
            if target is None:
                continue
            decision = _merge_decision(decision, target, relax=is_allowed)
        if decision is finding.decision_hint:
            updated.append(finding)
            continue
        updated.append(replace(finding, decision_hint=decision))
    return updated


def supported_policy_profiles() -> tuple[str, ...]:
    return tuple(DEFAULT_POLICY_PROFILES.keys())


def _matches_environment_rule(finding: Finding, rule: EnvironmentToggleRule) -> bool:
    if finding.taxonomy_id != rule.taxonomy_id:
        return False
    if not rule.tags:
        return True
    finding_tags = set(finding.tags)
    return any(tag in finding_tags for tag in rule.tags)


def _read_policy_boolean(policy: dict[str, Any], key: str, default: bool) -> bool:
    value = policy.get(key, default)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
    return default


def _merge_decision(current: Decision, candidate: Decision, *, relax: bool) -> Decision:
    if relax:
        if DECISION_PRIORITY[current] > DECISION_PRIORITY[candidate]:
            return candidate
        return current
    if DECISION_PRIORITY[candidate] > DECISION_PRIORITY[current]:
        return candidate
    return current
