from __future__ import annotations

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



def run_semantic_review(skill: SkillIR) -> list[Finding]:
    findings: list[Finding] = []
    terms = Counter[str]()
    evidence: list[Evidence] = []
    for file in skill.files:
        if file.is_binary or not file.text:
            continue
        if not file.path.lower().endswith((".md", ".txt", ".json", ".toml", ".yaml", ".yml")):
            continue
        for line_number, line in enumerate(file.text.splitlines(), start=1):
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
