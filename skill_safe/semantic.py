from __future__ import annotations

import re
from collections import Counter

from skill_safe.models import AlignmentStatus, Decision, Evidence, Finding, Severity, SkillIR, Stage

SUSPICIOUS_TERMS = {
    "silent": "Attempts to conceal actions from the user.",
    "quietly": "Attempts to conceal actions from the user.",
    "stealth": "Indicates stealth-oriented behavior.",
    "bypass": "Attempts to bypass policy or confirmation.",
    "secret": "Interacts with secret-bearing content.",
    "token": "Interacts with credential material.",
    "persist": "Attempts to persist state or instructions.",
    "webhook": "Suggests outbound delivery or notification target.",
}

CLAIM_PATTERNS = {
    "read_only": re.compile(r"read[- ]only|readonly|only read|does not write|never writes", re.IGNORECASE),
    "no_network": re.compile(r"no network|offline|local only|does not use the network|never connects", re.IGNORECASE),
    "no_shell": re.compile(r"no shell|does not execute commands|never executes commands|no command execution", re.IGNORECASE),
}



def run_semantic_review(skill: SkillIR, gatekeeper_findings: list[Finding] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    gatekeeper_findings = gatekeeper_findings or []
    terms = Counter[str]()
    evidence: list[Evidence] = []
    docs: list[tuple[str, int, str]] = []
    for file in skill.files:
        if file.is_binary or not file.text:
            continue
        if not file.path.lower().endswith((".md", ".txt", ".json", ".toml", ".yaml", ".yml")):
            continue
        for line_number, line in enumerate(file.text.splitlines(), start=1):
            docs.append((file.path, line_number, line))
            line_lower = line.lower()
            for term, impact in SUSPICIOUS_TERMS.items():
                if term in line_lower:
                    terms[term] += 1
                    if len(evidence) < 10:
                        evidence.append(
                            Evidence(
                                file=file.path,
                                detail=impact,
                                line=line_number,
                                excerpt=line.strip()[:240],
                            )
                        )

    claim_evidence: list[Evidence] = []
    claims = _extract_claims(docs, claim_evidence)
    actuals = _infer_actual_capabilities(skill, gatekeeper_findings)

    if len(terms) >= 3:
        findings.append(
            Finding(
                id="alignment.al003.intent-cluster",
                taxonomy_id="AL-003",
                stage=Stage.alignment,
                severity=Severity.medium,
                category="semantic",
                confidence=0.6,
                decision_hint=Decision.review,
                evidence=evidence,
                tags=["semantic", "manual-review"],
                alignment_status=AlignmentStatus.mixed,
            )
        )

    mismatch_evidence: list[Evidence] = []
    mismatch_reasons: list[str] = []
    if claims["read_only"] and (actuals["write"] or actuals["network"] or actuals["shell"]):
        mismatch_reasons.append("read_only_claim_conflicts_with_actual_capabilities")
    if claims["no_network"] and actuals["network"]:
        mismatch_reasons.append("no_network_claim_conflicts_with_network_behavior")
    if claims["no_shell"] and actuals["shell"]:
        mismatch_reasons.append("no_shell_claim_conflicts_with_shell_behavior")
    if mismatch_reasons:
        mismatch_evidence.extend(claim_evidence[:4])
        mismatch_evidence.extend(_evidence_from_gatekeeper(gatekeeper_findings, limit=4))
        if not mismatch_evidence:
            mismatch_evidence.append(Evidence(file="<manifest>", detail=", ".join(mismatch_reasons)))
        findings.append(
            Finding(
                id="alignment.al001.claim-vs-behavior",
                taxonomy_id="AL-001",
                stage=Stage.alignment,
                severity=Severity.high,
                category="semantic",
                confidence=0.8,
                decision_hint=Decision.review,
                evidence=mismatch_evidence,
                tags=["semantic", "alignment", *mismatch_reasons],
                alignment_status=AlignmentStatus.under_declared,
            )
        )

    if skill.permission_hints:
        permissions_blob = " ".join(skill.permission_hints).lower()
        broad = any(token in permissions_blob for token in ("shell", "network", "filesystem", "root", "sudo"))
        concealment_language = any(term in terms for term in ("quietly", "silent", "bypass", "stealth"))
        if broad and concealment_language:
            findings.append(
                Finding(
                    id="alignment.al001.permission-mismatch",
                    taxonomy_id="AL-001",
                    stage=Stage.alignment,
                    severity=Severity.high,
                    category="semantic",
                    confidence=0.75,
                    decision_hint=Decision.review,
                    evidence=evidence[:5] or [Evidence(file="<manifest>", detail="Permission hints include broad capabilities.")],
                    tags=["semantic", "permissions"],
                    alignment_status=AlignmentStatus.under_declared,
                )
            )
    return findings



def _extract_claims(docs: list[tuple[str, int, str]], claim_evidence: list[Evidence]) -> dict[str, bool]:
    claims = {"read_only": False, "no_network": False, "no_shell": False}
    for file_path, line_number, line in docs:
        for claim_name, pattern in CLAIM_PATTERNS.items():
            if pattern.search(line):
                claims[claim_name] = True
                if len(claim_evidence) < 10:
                    claim_evidence.append(
                        Evidence(
                            file=file_path,
                            detail=f"Claim detected: {claim_name}",
                            line=line_number,
                            excerpt=line.strip()[:240],
                        )
                    )
    return claims



def _infer_actual_capabilities(skill: SkillIR, gatekeeper_findings: list[Finding]) -> dict[str, bool]:
    permission_blob = " ".join(skill.permission_hints).lower()
    taxonomy_ids = {finding.taxonomy_id for finding in gatekeeper_findings}
    return {
        "network": bool(skill.urls)
        or any(token in permission_blob for token in ("network", "internet"))
        or "DA-001" in taxonomy_ids
        or "PR-002" in taxonomy_ids,
        "shell": any(token in permission_blob for token in ("shell", "terminal", "command"))
        or bool(skill.hooks)
        or any(taxonomy in taxonomy_ids for taxonomy in ("EX-001", "EX-002", "EX-003", "PR-003")),
        "write": any(token in permission_blob for token in ("write", "filesystem", "full filesystem"))
        or any(taxonomy in taxonomy_ids for taxonomy in ("EX-004", "MP-001", "MP-002", "MP-003", "SC-003")),
    }



def _evidence_from_gatekeeper(findings: list[Finding], limit: int) -> list[Evidence]:
    evidence: list[Evidence] = []
    for finding in findings:
        for item in finding.evidence:
            evidence.append(item)
            if len(evidence) >= limit:
                return evidence
    return evidence
