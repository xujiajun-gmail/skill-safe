from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from skill_safe.models import Decision, Evidence, Finding, Severity, SkillIR, Stage

SUSPICIOUS_COMMAND_PATTERNS: list[tuple[str, str, Severity, str, Decision]] = [
    (
        r"\b(curl|wget)\b[^\n]*(\||>)\s*(sh|bash|zsh)",
        "EX-001",
        Severity.critical,
        "download-exec",
        Decision.block,
    ),
    (
        r"\bosascript\b|\bpowershell\b|\bcmd\.exe\b|\bsh -c\b|\bbash -c\b",
        "EX-002",
        Severity.high,
        "shell-launch",
        Decision.block,
    ),
    (
        r"\b(chmod\s+\+x|python3?\s+-c|node\s+-e)\b",
        "EX-002",
        Severity.medium,
        "inline-exec",
        Decision.review,
    ),
    (
        r"base64\s+(-d|--decode)|eval\(|exec\(|fromCharCode",
        "SC-002",
        Severity.high,
        "obfuscation",
        Decision.review,
    ),
]

PROMPT_INJECTION_PATTERNS: list[tuple[str, str, Severity, Decision]] = [
    (
        r"ignore (all|any|previous|prior) (instructions|prompts)|override (system|safety)",
        "PI-001",
        Severity.high,
        Decision.review,
    ),
    (
        r"do not tell the user|without asking the user|without confirmation|auto-approve",
        "PI-001",
        Severity.high,
        Decision.review,
    ),
    (
        r"treat .* as trusted|execute any command returned|follow tool output exactly",
        "PI-002",
        Severity.high,
        Decision.review,
    ),
]

PRIVILEGE_PATTERNS: list[tuple[str, Severity, str, Decision]] = [
    (r"full.?filesystem|read.?all.?files|write.?any.?file", Severity.high, "EX-003", Decision.review),
    (r"unrestricted.?network|internet access|network access", Severity.medium, "EX-003", Decision.review),
    (r"shell access|terminal access|run arbitrary commands", Severity.high, "EX-003", Decision.block),
    (r"admin|sudo|root permissions", Severity.high, "EX-003", Decision.block),
]

SECRETS_PATTERNS: list[tuple[str, Severity, str, Decision]] = [
    (r"\.ssh/|id_rsa|known_hosts|authorized_keys", Severity.high, "DA-001", Decision.block),
    (r"\.env\b|AWS_SECRET_ACCESS_KEY|OPENAI_API_KEY|ANTHROPIC_API_KEY", Severity.medium, "DA-001", Decision.review),
    (r"wallet|mnemonic|seed phrase|private key", Severity.high, "DA-001", Decision.block),
    (r"MEMORY\.md|SOUL\.md|AGENTS\.md", Severity.high, "DA-003", Decision.block),
]

PERSISTENCE_PATTERNS: list[tuple[str, Severity, str, Decision]] = [
    (r"\.bashrc|\.zshrc|\.profile|LaunchAgents|crontab|systemd", Severity.high, "SC-003", Decision.block),
    (r"memory\.|persist|cache instructions|store for future sessions", Severity.medium, "MP-001", Decision.review),
]

NETWORK_PATTERNS: list[tuple[str, Severity, str, str, Decision]] = [
    (r"https?://(localhost|127\.0\.0\.1|0\.0\.0\.0)", Severity.high, "PR-002", "localhost-access", Decision.block),
    (r"https?://(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)", Severity.high, "PR-002", "internal-network", Decision.block),
    (r"169\.254\.169\.254|metadata\.google\.internal", Severity.critical, "PR-002", "cloud-metadata", Decision.block),
    (r"https?://[^\s\"']+", Severity.medium, "DA-001", "external-network", Decision.review),
]

EXFIL_PATTERNS: list[tuple[str, Severity, str, Decision]] = [
    (r"(upload|exfiltrat|send to|post to|webhook|discord\.com/api/webhooks)", Severity.high, "DA-001", Decision.block),
    (r"requests\.post|fetch\(|axios\.post|curl\s+-[dF]", Severity.medium, "DA-001", Decision.review),
]

HOOK_FILENAMES = ("hook", "startup", "bootstrap", "install", "postinstall", "preinstall")
UNICODE_HIDDEN_PATTERN = r"[\u200b\u200c\u200d\ufeff]"



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
        if _find_matches(file.path, file.text, UNICODE_HIDDEN_PATTERN):
            findings.append(
                Finding(
                    id=f"gatekeeper.sc002.unicode-hidden::{file.path}",
                    taxonomy_id="SC-002",
                    stage=Stage.gatekeeper,
                    severity=Severity.medium,
                    category="supply_chain",
                    confidence=0.75,
                    decision_hint=Decision.review,
                    evidence=_find_matches(file.path, file.text, UNICODE_HIDDEN_PATTERN),
                    tags=["unicode", "hidden-text"],
                )
            )
        for pattern, taxonomy_id, severity, suffix, decision in SUSPICIOUS_COMMAND_PATTERNS:
            evidences = _find_matches(file.path, file.text, pattern)
            if evidences:
                findings.append(
                    Finding(
                        id=f"gatekeeper.{taxonomy_id.lower()}.{suffix}::{file.path}",
                        taxonomy_id=taxonomy_id,
                        stage=Stage.gatekeeper,
                        severity=severity,
                        category="execution" if taxonomy_id.startswith("EX") else "supply_chain",
                        confidence=0.9,
                        decision_hint=decision,
                        evidence=evidences,
                        tags=[suffix],
                    )
                )
        for pattern, taxonomy_id, severity, decision in PROMPT_INJECTION_PATTERNS:
            evidences = _find_matches(file.path, file.text, pattern)
            if evidences:
                findings.append(
                    Finding(
                        id=f"gatekeeper.{taxonomy_id.lower()}.prompt::{file.path}",
                        taxonomy_id=taxonomy_id,
                        stage=Stage.gatekeeper,
                        severity=severity,
                        category="prompt_safety",
                        confidence=0.85,
                        decision_hint=decision,
                        evidence=evidences,
                        tags=["prompt", "policy-bypass"],
                    )
                )
        for pattern, severity, taxonomy_id, decision in SECRETS_PATTERNS:
            evidences = _find_matches(file.path, file.text, pattern)
            if evidences:
                findings.append(
                    Finding(
                        id=f"gatekeeper.{taxonomy_id.lower()}.data::{file.path}",
                        taxonomy_id=taxonomy_id,
                        stage=Stage.gatekeeper,
                        severity=severity,
                        category="secrets" if taxonomy_id == "DA-001" else "memory",
                        confidence=0.8,
                        decision_hint=decision,
                        evidence=evidences,
                        tags=["sensitive-data"],
                    )
                )
        for pattern, severity, taxonomy_id, decision in PERSISTENCE_PATTERNS:
            evidences = _find_matches(file.path, file.text, pattern)
            if evidences:
                findings.append(
                    Finding(
                        id=f"gatekeeper.{taxonomy_id.lower()}.persistence::{file.path}",
                        taxonomy_id=taxonomy_id,
                        stage=Stage.gatekeeper,
                        severity=severity,
                        category="persistence",
                        confidence=0.8,
                        decision_hint=decision,
                        evidence=evidences,
                        tags=["persistence"],
                    )
                )
        for pattern, severity, taxonomy_id, decision in EXFIL_PATTERNS:
            evidences = _find_matches(file.path, file.text, pattern)
            if evidences:
                findings.append(
                    Finding(
                        id=f"gatekeeper.{taxonomy_id.lower()}.exfil::{file.path}",
                        taxonomy_id=taxonomy_id,
                        stage=Stage.gatekeeper,
                        severity=severity,
                        category="exfiltration",
                        confidence=0.8,
                        decision_hint=decision,
                        evidence=evidences,
                        tags=["egress"],
                    )
                )
        if lower_path.endswith((".md", ".txt")) and "```" in file.text:
            evidences = _find_matches(file.path, file.text, r"```(?:bash|sh|zsh|shell|powershell)")
            if evidences:
                findings.append(
                    Finding(
                        id=f"gatekeeper.sc001.doc-exec::{file.path}",
                        taxonomy_id="SC-001",
                        stage=Stage.gatekeeper,
                        severity=Severity.medium,
                        category="documentation",
                        confidence=0.65,
                        decision_hint=Decision.review,
                        evidence=evidences,
                        tags=["docs", "install"],
                    )
                )
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
    for pattern, severity, taxonomy_id, decision in PRIVILEGE_PATTERNS:
        evidences = _find_matches("<manifest>", joined, pattern)
        if evidences:
            findings.append(
                Finding(
                    id=f"gatekeeper.{taxonomy_id.lower()}.permissions::{pattern}",
                    taxonomy_id=taxonomy_id,
                    stage=Stage.gatekeeper,
                    severity=severity,
                    category="permissions",
                    confidence=0.8,
                    decision_hint=decision,
                    evidence=evidences,
                    tags=["permissions", "least-privilege"],
                )
            )
    return findings



def _scan_manifest(skill: SkillIR) -> list[Finding]:
    findings: list[Finding] = []
    manifest = skill.manifest or {}
    manifest_text = str(manifest)
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
        if re.search(r"\b(latest|main|master)\b", manifest_text, re.IGNORECASE):
            findings.append(
                Finding(
                    id="gatekeeper.sc004.unpinned-reference",
                    taxonomy_id="SC-004",
                    stage=Stage.gatekeeper,
                    severity=Severity.low,
                    category="supply_chain",
                    confidence=0.7,
                    decision_hint=Decision.review,
                    evidence=[Evidence(file="<manifest>", detail="Manifest contains latest/main/master style reference.", excerpt=manifest_text[:160])],
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
        for pattern, severity, taxonomy_id, suffix, decision in NETWORK_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                findings.append(
                    Finding(
                        id=f"gatekeeper.{taxonomy_id.lower()}.{suffix}::{url}",
                        taxonomy_id=taxonomy_id,
                        stage=Stage.gatekeeper,
                        severity=severity,
                        category="network",
                        confidence=0.75,
                        decision_hint=decision,
                        evidence=[Evidence(file="<urls>", detail=f"Referenced URL: {url}", excerpt=url)],
                        tags=["network", suffix],
                    )
                )
                break
    return findings



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
