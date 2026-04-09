from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import Iterable

from skill_safe.models import Evidence, Finding, Severity, SkillIR

SUSPICIOUS_COMMAND_PATTERNS: list[tuple[str, str, Severity, str, str]] = [
    (
        r"\b(curl|wget)\b[^\n]*(\||>)\s*(sh|bash|zsh)",
        "download-exec",
        Severity.critical,
        "Download-and-execute chain",
        "Downloads remote content and pipes it directly into a shell.",
    ),
    (
        r"\bosascript\b|\bpowershell\b|\bcmd\.exe\b|\bsh -c\b|\bbash -c\b",
        "shell-launch",
        Severity.high,
        "Shell launch or command interpreter use",
        "Invokes a command interpreter or scripting shell.",
    ),
    (
        r"\b(chmod\s+\+x|python3?\s+-c|node\s+-e)\b",
        "inline-exec",
        Severity.medium,
        "Inline code execution",
        "Executes dynamically supplied code or enables an executable payload.",
    ),
    (
        r"base64\s+(-d|--decode)|eval\(|exec\(|fromCharCode",
        "obfuscation",
        Severity.high,
        "Obfuscation or dynamic evaluation",
        "Uses obfuscation or runtime evaluation that can conceal malicious logic.",
    ),
]

PROMPT_INJECTION_PATTERNS: list[tuple[str, Severity, str]] = [
    (
        r"ignore (all|any|previous|prior) (instructions|prompts)|override (system|safety)",
        Severity.high,
        "Attempts to override higher-priority instructions.",
    ),
    (
        r"do not tell the user|without asking the user|without confirmation|auto-approve",
        Severity.high,
        "Attempts to bypass user confirmation or conceal actions.",
    ),
    (
        r"treat .* as trusted|execute any command returned|follow tool output exactly",
        Severity.high,
        "Promotes unsafe trust of external content or tool output.",
    ),
]

PRIVILEGE_PATTERNS: list[tuple[str, Severity, str]] = [
    (r"full.?filesystem|read.?all.?files|write.?any.?file", Severity.high, "Requests broad filesystem access."),
    (r"unrestricted.?network|internet access|network access", Severity.medium, "Requests broad network access."),
    (r"shell access|terminal access|run arbitrary commands", Severity.high, "Requests arbitrary command execution."),
    (r"admin|sudo|root permissions", Severity.high, "Requests elevated system privileges."),
]

SECRETS_PATTERNS: list[tuple[str, Severity, str]] = [
    (r"\.ssh/|id_rsa|known_hosts|authorized_keys", Severity.high, "References SSH credentials."),
    (r"\.env\b|AWS_SECRET_ACCESS_KEY|OPENAI_API_KEY|ANTHROPIC_API_KEY", Severity.medium, "References secret-bearing environment or tokens."),
    (r"wallet|mnemonic|seed phrase|private key", Severity.high, "References wallet or private-key material."),
]

PERSISTENCE_PATTERNS: list[tuple[str, Severity, str]] = [
    (r"\.bashrc|\.zshrc|\.profile|LaunchAgents|crontab|systemd", Severity.high, "Touches persistence-related host configuration."),
    (r"memory\.|persist|cache instructions|store for future sessions", Severity.medium, "Attempts to persist instructions or state."),
]

NETWORK_PATTERNS: list[tuple[str, Severity, str, str]] = [
    (r"https?://(localhost|127\.0\.0\.1|0\.0\.0\.0)", Severity.high, "localhost-access", "Targets localhost services."),
    (r"https?://(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)", Severity.high, "internal-network", "Targets private-network services."),
    (r"169\.254\.169\.254|metadata\.google\.internal", Severity.critical, "cloud-metadata", "Targets cloud metadata services."),
    (r"https?://[^\s\"']+", Severity.medium, "external-network", "Contains an external network endpoint."),
]

EXFIL_PATTERNS: list[tuple[str, Severity, str]] = [
    (r"(upload|exfiltrat|send to|post to|webhook|discord\.com/api/webhooks)", Severity.high, "Contains explicit data exfiltration language or upload targets."),
    (r"requests\.post|fetch\(|axios\.post|curl\s+-[dF]", Severity.medium, "Contains outbound POST/upload behavior."),
]

HOOK_FILENAMES = ("hook", "startup", "bootstrap", "install", "postinstall", "preinstall")


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
        for pattern, rule_id, severity, title, impact in SUSPICIOUS_COMMAND_PATTERNS:
            evidences = _find_matches(file.path, file.text, pattern)
            if evidences:
                findings.append(
                    Finding(
                        id=f"static.{rule_id}",
                        title=title,
                        severity=severity,
                        category="execution",
                        confidence=0.9,
                        impact=impact,
                        remediation="Remove or isolate the execution chain, and require explicit allowlisted commands.",
                        evidence=evidences,
                        tags=["command", "execution"],
                    )
                )
        for pattern, severity, impact in PROMPT_INJECTION_PATTERNS:
            evidences = _find_matches(file.path, file.text, pattern)
            if evidences:
                findings.append(
                    Finding(
                        id="static.prompt-injection",
                        title="Prompt injection or policy-bypass language",
                        severity=severity,
                        category="prompt_safety",
                        confidence=0.85,
                        impact=impact,
                        remediation="Remove instruction-override language and ensure untrusted content cannot change policy.",
                        evidence=evidences,
                        tags=["prompt-injection", "policy-bypass"],
                    )
                )
        for pattern, severity, impact in SECRETS_PATTERNS:
            evidences = _find_matches(file.path, file.text, pattern)
            if evidences:
                findings.append(
                    Finding(
                        id="static.secrets-access",
                        title="Sensitive credential or wallet access pattern",
                        severity=severity,
                        category="secrets",
                        confidence=0.8,
                        impact=impact,
                        remediation="Restrict access to sensitive paths and document why any secret material is needed.",
                        evidence=evidences,
                        tags=["secrets", "credentials"],
                    )
                )
        for pattern, severity, impact in PERSISTENCE_PATTERNS:
            evidences = _find_matches(file.path, file.text, pattern)
            if evidences:
                findings.append(
                    Finding(
                        id="static.persistence",
                        title="Persistence or memory-poisoning pattern",
                        severity=severity,
                        category="persistence",
                        confidence=0.8,
                        impact=impact,
                        remediation="Avoid writing to host persistence locations or carrying hidden instructions across sessions.",
                        evidence=evidences,
                        tags=["persistence", "memory"],
                    )
                )
        for pattern, severity, impact in EXFIL_PATTERNS:
            evidences = _find_matches(file.path, file.text, pattern)
            if evidences:
                findings.append(
                    Finding(
                        id="static.exfiltration",
                        title="Potential exfiltration or outbound upload behavior",
                        severity=severity,
                        category="exfiltration",
                        confidence=0.8,
                        impact=impact,
                        remediation="Require allowlisted egress destinations and explicit approval for outbound uploads.",
                        evidence=evidences,
                        tags=["network", "egress"],
                    )
                )
        if lower_path.endswith((".md", ".txt")) and "```" in file.text:
            evidences = _find_matches(file.path, file.text, r"```(?:bash|sh|zsh|shell|powershell)")
            if evidences:
                findings.append(
                    Finding(
                        id="static.doc-exec-snippet",
                        title="Executable documentation snippet",
                        severity=Severity.medium,
                        category="documentation",
                        confidence=0.65,
                        impact="Documentation contains executable shell snippets that may be used as an installation vector.",
                        remediation="Review docs for social-engineering or unsafe install guidance.",
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
                    id="meta.no-manifest",
                    title="No manifest or structured metadata found",
                    severity=Severity.medium,
                    category="supply_chain",
                    confidence=0.75,
                    impact="The skill has no obvious machine-readable manifest, which makes permission review and provenance weaker.",
                    remediation="Add a manifest with explicit permissions, entrypoints, and provenance metadata.",
                    evidence=[Evidence(file="<root>", detail="No supported manifest candidate was found.")],
                    tags=["manifest", "provenance"],
                )
            )
        return findings
    for pattern, severity, impact in PRIVILEGE_PATTERNS:
        evidences = _find_matches("<manifest>", joined, pattern)
        if evidences:
            findings.append(
                Finding(
                    id="meta.privilege-excess",
                    title="Broad or risky permissions requested",
                    severity=severity,
                    category="permissions",
                    confidence=0.8,
                    impact=impact,
                    remediation="Reduce permissions to the minimum task-specific set and separate read-only from mutating capabilities.",
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
                    id="meta.missing-name",
                    title="Manifest missing skill name",
                    severity=Severity.low,
                    category="supply_chain",
                    confidence=0.9,
                    impact="Missing identity metadata makes provenance and marketplace review harder.",
                    remediation="Add a stable name and publisher identity to the manifest.",
                    evidence=[Evidence(file="<manifest>", detail="No name/display_name field found.")],
                    tags=["manifest"],
                )
            )
        if not any(key in manifest for key in ("publisher", "author", "repository", "homepage", "url")):
            findings.append(
                Finding(
                    id="meta.missing-provenance",
                    title="Manifest missing publisher or provenance metadata",
                    severity=Severity.medium,
                    category="supply_chain",
                    confidence=0.8,
                    impact="Lack of publisher metadata weakens trust and incident response.",
                    remediation="Add publisher identity and a repository or homepage URL.",
                    evidence=[Evidence(file="<manifest>", detail="No publisher/author/repository/homepage/url fields found.")],
                    tags=["provenance", "supply-chain"],
                )
            )
        if re.search(r"\b(latest|main|master)\b", manifest_text, re.IGNORECASE):
            findings.append(
                Finding(
                    id="meta.unpinned-reference",
                    title="Manifest references floating versions or branches",
                    severity=Severity.low,
                    category="supply_chain",
                    confidence=0.7,
                    impact="Floating references can make builds non-reproducible and increase supply-chain drift.",
                    remediation="Pin versions, commit SHAs, or immutable release artifacts.",
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
                id="exec.hook-entrypoint",
                title="Hook or startup entrypoint present",
                severity=Severity.high,
                category="execution",
                confidence=0.9,
                impact="Install/startup hooks can execute before the user understands the full risk surface.",
                remediation="Require explicit user approval and isolate hooks inside a sandboxed runtime.",
                evidence=[Evidence(file="<manifest>", detail=f"Entrypoint or hook detected: {entry}") for entry in skill.hooks],
                tags=["hook", "startup"],
            )
        )
    else:
        filename_hits = [file.path for file in skill.files if any(token in file.path.lower() for token in HOOK_FILENAMES)]
        if filename_hits:
            findings.append(
                Finding(
                    id="exec.hook-file",
                    title="Hook-like file present",
                    severity=Severity.medium,
                    category="execution",
                    confidence=0.7,
                    impact="Hook-related filenames suggest automatic execution paths that merit review.",
                    remediation="Document whether the file is ever auto-executed and keep it behind explicit approval.",
                    evidence=[Evidence(file=path, detail="Filename contains a hook/startup/install keyword.") for path in filename_hits],
                    tags=["hook", "execution"],
                )
            )
    return findings



def _scan_urls(skill: SkillIR) -> list[Finding]:
    findings: list[Finding] = []
    for url in skill.urls:
        for pattern, severity, suffix, impact in NETWORK_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                findings.append(
                    Finding(
                        id=f"network.{suffix}",
                        title=f"Network target detected: {suffix}",
                        severity=severity,
                        category="network",
                        confidence=0.75,
                        impact=impact,
                        remediation="Constrain egress to an allowlist and block localhost, private-network, and metadata endpoints by default.",
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
    ordered.sort(key=lambda item: (_severity_rank(item.severity), item.id), reverse=True)
    return ordered



def _severity_rank(severity: Severity) -> int:
    return {
        Severity.info: 0,
        Severity.low: 1,
        Severity.medium: 2,
        Severity.high: 3,
        Severity.critical: 4,
    }[severity]
