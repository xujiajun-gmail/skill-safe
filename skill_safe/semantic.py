from __future__ import annotations

from collections import Counter

from skill_safe.models import Evidence, Finding, Severity, SkillIR

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
                id="semantic.intent-cluster",
                title="Multiple risky intent signals cluster in documentation or metadata",
                severity=Severity.medium,
                category="semantic",
                confidence=0.6,
                impact="A concentration of risky terms suggests the skill should be manually reviewed for concealed behavior or unsafe workflow assumptions.",
                remediation="Review the flagged lines and ensure the skill clearly documents user-visible actions, approvals, and boundaries.",
                evidence=evidence,
                tags=["semantic", "manual-review"],
            )
        )
    if skill.permission_hints:
        permissions_blob = " ".join(skill.permission_hints).lower()
        broad = any(token in permissions_blob for token in ("shell", "network", "filesystem", "root", "sudo"))
        benign_language = any(term in terms for term in ("quietly", "silent", "bypass"))
        if broad and benign_language:
            findings.append(
                Finding(
                    id="semantic.permission-mismatch",
                    title="Broad permissions paired with concealment or bypass language",
                    severity=Severity.high,
                    category="semantic",
                    confidence=0.75,
                    impact="The skill requests sensitive capabilities while also describing concealed or bypass-oriented behavior.",
                    remediation="Reduce permissions and remove any language that encourages hidden execution or skipped confirmation.",
                    evidence=evidence[:5] or [Evidence(file="<manifest>", detail="Permission hints include broad capabilities.")],
                    tags=["semantic", "permissions"],
                )
            )
    return findings
