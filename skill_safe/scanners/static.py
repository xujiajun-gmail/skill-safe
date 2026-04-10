from __future__ import annotations

import re
from typing import Iterable

from skill_safe.models import Decision, Evidence, Finding, Severity, SkillIR, Stage
from skill_safe.scanners.rules import (
    DOC_EXEC_RULE,
    EXFIL_RULES,
    HOOK_FILENAMES,
    PERSISTENCE_RULES,
    PRIVILEGE_RULES,
    PROMPT_INJECTION_RULES,
    SECRETS_RULES,
    SUSPICIOUS_COMMAND_RULES,
    UNICODE_HIDDEN_RULE,
    URL_RULES,
    PatternRule,
    UrlRule,
)



def run_static_analysis(skill: SkillIR) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_scan_text_patterns(skill))
    findings.extend(_scan_permissions(skill))
    findings.extend(_scan_manifest(skill))
    findings.extend(_scan_hooks(skill))
    findings.extend(_scan_urls(skill))
    return _dedupe(findings)



def _scan_text_patterns(skill: SkillIR) -> list[Finding]:
    findings: list[Finding] = []
    for file in skill.files:
        if file.is_binary or not file.text:
            continue
        lower_path = file.path.lower()
        findings.extend(_run_pattern_rule(file.path, file.text, UNICODE_HIDDEN_RULE))
        for rule in SUSPICIOUS_COMMAND_RULES:
            findings.extend(_run_pattern_rule(file.path, file.text, rule))
        for rule in PROMPT_INJECTION_RULES:
            findings.extend(_run_pattern_rule(file.path, file.text, rule))
        for rule in SECRETS_RULES:
            findings.extend(_run_pattern_rule(file.path, file.text, rule))
        for rule in PERSISTENCE_RULES:
            findings.extend(_run_pattern_rule(file.path, file.text, rule))
        for rule in EXFIL_RULES:
            findings.extend(_run_pattern_rule(file.path, file.text, rule))
        if lower_path.endswith((".md", ".txt")) and "```" in file.text:
            findings.extend(_run_pattern_rule(file.path, file.text, DOC_EXEC_RULE))
    return findings



def _scan_permissions(skill: SkillIR) -> list[Finding]:
    findings: list[Finding] = []
    joined = "\n".join(skill.permission_hints)
    if not joined:
        if skill.manifest is None:
            findings.append(
                Finding(
                    id="gatekeeper.sc004.no-manifest",
                    taxonomy_id="SC-004",
                    stage=Stage.gatekeeper,
                    severity=Severity.medium,
                    category="supply_chain",
                    confidence=0.75,
                    decision_hint=Decision.review,
                    evidence=[Evidence(file="<root>", detail="No supported manifest candidate was found.")],
                    tags=["manifest", "provenance"],
                )
            )
        return findings
    for rule in PRIVILEGE_RULES:
        findings.extend(_run_pattern_rule("<manifest>", joined, rule, id_fragment=rule.suffix))
    return findings



def _scan_manifest(skill: SkillIR) -> list[Finding]:
    findings: list[Finding] = []
    manifest = skill.manifest or {}
    if manifest:
        name = manifest.get("name") or manifest.get("display_name")
        if not name:
            findings.append(
                Finding(
                    id="gatekeeper.sc004.missing-name",
                    taxonomy_id="SC-004",
                    stage=Stage.gatekeeper,
                    severity=Severity.low,
                    category="supply_chain",
                    confidence=0.9,
                    decision_hint=Decision.review,
                    evidence=[Evidence(file="<manifest>", detail="No name/display_name field found.")],
                    tags=["manifest"],
                )
            )
        if not any(key in manifest for key in ("publisher", "author", "repository", "homepage", "url")):
            findings.append(
                Finding(
                    id="gatekeeper.sc004.missing-provenance",
                    taxonomy_id="SC-004",
                    stage=Stage.gatekeeper,
                    severity=Severity.medium,
                    category="supply_chain",
                    confidence=0.8,
                    decision_hint=Decision.review,
                    evidence=[Evidence(file="<manifest>", detail="No publisher/author/repository/homepage/url fields found.")],
                    tags=["provenance", "supply-chain"],
                )
            )
        reference_values = _manifest_reference_values(manifest)
        matched_reference = next(
            (value for value in reference_values if re.search(r"\b(latest|main|master)\b", value, re.IGNORECASE)),
            None,
        )
        if matched_reference is not None:
            findings.append(
                Finding(
                    id="gatekeeper.sc004.unpinned-reference",
                    taxonomy_id="SC-004",
                    stage=Stage.gatekeeper,
                    severity=Severity.low,
                    category="supply_chain",
                    confidence=0.7,
                    decision_hint=Decision.review,
                    evidence=[
                        Evidence(
                            file="<manifest>",
                            detail="Manifest contains latest/main/master style reference.",
                            excerpt=matched_reference[:160],
                        )
                    ],
                    tags=["supply-chain", "pinning"],
                )
            )
    return findings



def _scan_hooks(skill: SkillIR) -> list[Finding]:
    findings: list[Finding] = []
    if skill.hooks:
        findings.append(
            Finding(
                id="gatekeeper.pr003.hook-entrypoint",
                taxonomy_id="PR-003",
                stage=Stage.gatekeeper,
                severity=Severity.high,
                category="execution",
                confidence=0.9,
                decision_hint=Decision.block,
                evidence=[Evidence(file="<manifest>", detail=f"Entrypoint or hook detected: {entry}") for entry in skill.hooks],
                tags=["hook", "startup"],
            )
        )
    else:
        filename_hits = [file.path for file in skill.files if any(token in file.path.lower() for token in HOOK_FILENAMES)]
        if filename_hits:
            findings.append(
                Finding(
                    id="gatekeeper.pr003.hook-file",
                    taxonomy_id="PR-003",
                    stage=Stage.gatekeeper,
                    severity=Severity.medium,
                    category="execution",
                    confidence=0.7,
                    decision_hint=Decision.review,
                    evidence=[Evidence(file=path, detail="Filename contains a hook/startup/install keyword.") for path in filename_hits],
                    tags=["hook", "execution"],
                )
            )
    return findings



def _scan_urls(skill: SkillIR) -> list[Finding]:
    findings: list[Finding] = []
    for url in skill.urls:
        for rule in URL_RULES:
            if re.search(rule.pattern, url, re.IGNORECASE):
                findings.append(
                    Finding(
                        id=f"gatekeeper.{rule.taxonomy_id.lower()}.{rule.suffix}::{url}",
                        taxonomy_id=rule.taxonomy_id,
                        stage=Stage.gatekeeper,
                        severity=rule.severity,
                        category=rule.impact_category,
                        confidence=rule.confidence,
                        decision_hint=rule.decision,
                        evidence=[Evidence(file="<urls>", detail=f"Referenced URL: {url}", excerpt=url)],
                        tags=list(rule.tags),
                    )
                )
                break
    return findings



def _run_pattern_rule(file_path: str, text: str, rule: PatternRule, id_fragment: str | None = None) -> list[Finding]:
    evidences = _find_matches(file_path, text, rule.pattern)
    if not evidences:
        return []
    fragment = id_fragment or rule.suffix
    return [
        Finding(
            id=f"gatekeeper.{rule.taxonomy_id.lower()}.{fragment}::{file_path}",
            taxonomy_id=rule.taxonomy_id,
            stage=Stage.gatekeeper,
            severity=rule.severity,
            category=rule.category,
            confidence=rule.confidence,
            decision_hint=rule.decision,
            evidence=evidences,
            tags=list(rule.tags),
        )
    ]



def _find_matches(file_path: str, text: str, pattern: str) -> list[Evidence]:
    compiled = re.compile(pattern, re.IGNORECASE)
    evidences: list[Evidence] = []
    for index, line in enumerate(text.splitlines(), start=1):
        match = compiled.search(line)
        if match:
            evidences.append(
                Evidence(
                    file=file_path,
                    detail=f"Pattern matched: {pattern}",
                    line=index,
                    excerpt=line.strip()[:240],
                )
            )
    return evidences



def _dedupe(findings: Iterable[Finding]) -> list[Finding]:
    unique: dict[tuple[str, str], Finding] = {}
    for finding in findings:
        key = (finding.id, tuple((ev.file, ev.line, ev.excerpt) for ev in finding.evidence).__repr__())
        unique[key] = finding
    ordered = list(unique.values())
    ordered.sort(key=lambda item: (_severity_rank(item.severity), item.taxonomy_id, item.id), reverse=True)
    return ordered



def _severity_rank(severity: Severity) -> int:
    return {
        Severity.info: 0,
        Severity.low: 1,
        Severity.medium: 2,
        Severity.high: 3,
        Severity.critical: 4,
    }[severity]


def _manifest_reference_values(manifest: dict[str, object]) -> list[str]:
    values: list[str] = []
    interesting_keys = {"repository", "homepage", "url", "source", "ref", "branch", "release", "tag", "version"}
    stack: list[dict[str, object]] = [manifest]
    while stack:
        current = stack.pop()
        for key, value in current.items():
            key_lower = str(key).lower()
            if isinstance(value, dict):
                stack.append(value)
                continue
            if isinstance(value, list):
                if key_lower in interesting_keys:
                    values.extend(str(item) for item in value if not isinstance(item, dict))
                for item in value:
                    if isinstance(item, dict):
                        stack.append(item)
                continue
            if key_lower in interesting_keys:
                values.append(str(value))
    return values
