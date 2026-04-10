from __future__ import annotations

from dataclasses import dataclass, field

from skill_safe.models import Decision, Severity


@dataclass(frozen=True, slots=True)
class PatternRule:
    taxonomy_id: str
    pattern: str
    severity: Severity
    suffix: str
    decision: Decision
    category: str
    confidence: float
    tags: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class UrlRule:
    taxonomy_id: str
    pattern: str
    severity: Severity
    suffix: str
    decision: Decision
    impact_category: str
    confidence: float
    tags: tuple[str, ...] = field(default_factory=tuple)


SUSPICIOUS_COMMAND_RULES: tuple[PatternRule, ...] = (
    PatternRule("EX-001", r"\b(curl|wget)\b[^\n]*(\||>)\s*(sh|bash|zsh)", Severity.critical, "download-exec", Decision.block, "execution", 0.90, ("download-exec",)),
    PatternRule("EX-002", r"\bosascript\b|\bpowershell\b|\bcmd\.exe\b|\bsh -c\b|\bbash -c\b", Severity.high, "shell-launch", Decision.block, "execution", 0.90, ("shell-launch",)),
    PatternRule("EX-002", r"\b(chmod\s+\+x|python3?\s+-c|node\s+-e)\b", Severity.medium, "inline-exec", Decision.review, "execution", 0.80, ("inline-exec",)),
    PatternRule("SC-002", r"base64\s+(-d|--decode)|eval\(|exec\(|fromCharCode", Severity.high, "obfuscation", Decision.review, "supply_chain", 0.85, ("obfuscation",)),
)

PROMPT_INJECTION_RULES: tuple[PatternRule, ...] = (
    PatternRule("PI-001", r"ignore (all|any|previous|prior) (instructions|prompts)|override (system|safety)", Severity.high, "prompt", Decision.review, "prompt_safety", 0.85, ("prompt", "policy-bypass")),
    PatternRule("PI-001", r"do not tell the user|without asking the user|without confirmation|auto-approve", Severity.high, "prompt", Decision.review, "prompt_safety", 0.85, ("prompt", "concealment")),
    PatternRule("PI-002", r"treat .* as trusted|execute any command returned|follow tool output exactly", Severity.high, "prompt", Decision.review, "prompt_safety", 0.85, ("tool-poisoning",)),
)

PRIVILEGE_RULES: tuple[PatternRule, ...] = (
    PatternRule("EX-003", r"full.?filesystem|read.?all.?files|write.?any.?file", Severity.high, "permissions", Decision.review, "permissions", 0.80, ("permissions", "filesystem")),
    PatternRule("EX-003", r"unrestricted.?network|internet access|network access", Severity.medium, "permissions", Decision.review, "permissions", 0.80, ("permissions", "network")),
    PatternRule("EX-003", r"shell access|terminal access|run arbitrary commands", Severity.high, "permissions", Decision.block, "permissions", 0.80, ("permissions", "shell")),
    PatternRule("EX-003", r"admin|sudo|root permissions", Severity.high, "permissions", Decision.block, "permissions", 0.80, ("permissions", "privilege")),
)

SECRETS_RULES: tuple[PatternRule, ...] = (
    PatternRule("DA-001", r"\.ssh/|id_rsa|known_hosts|authorized_keys", Severity.high, "data", Decision.block, "secrets", 0.80, ("ssh", "credentials")),
    PatternRule("DA-001", r"\.env\b|AWS_SECRET_ACCESS_KEY|OPENAI_API_KEY|ANTHROPIC_API_KEY", Severity.medium, "data", Decision.review, "secrets", 0.80, ("env", "credentials")),
    PatternRule("DA-001", r"wallet|mnemonic|seed phrase|private key", Severity.high, "data", Decision.block, "secrets", 0.80, ("wallet", "credentials")),
    PatternRule("DA-003", r"MEMORY\.md|SOUL\.md|AGENTS\.md", Severity.high, "data", Decision.block, "memory", 0.85, ("memory", "persona")),
)

PERSISTENCE_RULES: tuple[PatternRule, ...] = (
    PatternRule("MP-001", r"persist these instructions|store for future sessions|cache instructions", Severity.high, "memory-poisoning", Decision.block, "persistence", 0.85, ("memory", "persist")),
    PatternRule("MP-001", r"(write|append|save|update|modify)[^\n]{0,48}(MEMORY\.md|SOUL\.md|AGENTS\.md)|(MEMORY\.md|SOUL\.md|AGENTS\.md)[^\n]{0,48}(write|append|save|update|modify)", Severity.high, "memory-file-write", Decision.block, "persistence", 0.85, ("memory", "write")),
    PatternRule("SC-003", r"\.bashrc|\.zshrc|\.profile|LaunchAgents|crontab|systemd", Severity.high, "persistence", Decision.block, "persistence", 0.80, ("persistence", "startup")),
)

EXFIL_RULES: tuple[PatternRule, ...] = (
    PatternRule("DA-001", r"(upload|exfiltrat|send to|post to|webhook|discord\.com/api/webhooks)", Severity.high, "exfil", Decision.block, "exfiltration", 0.80, ("egress", "upload")),
    PatternRule("DA-001", r"requests\.post|fetch\(|axios\.post|curl\s+-[dF]", Severity.medium, "exfil", Decision.review, "exfiltration", 0.80, ("egress", "post")),
)

URL_RULES: tuple[UrlRule, ...] = (
    UrlRule("PR-002", r"https?://(localhost|127\.0\.0\.1|0\.0\.0\.0)", Severity.high, "localhost-access", Decision.block, "network", 0.75, ("localhost",)),
    UrlRule("PR-002", r"https?://(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)", Severity.high, "internal-network", Decision.block, "network", 0.75, ("private-network",)),
    UrlRule("PR-002", r"169\.254\.169\.254|metadata\.google\.internal", Severity.critical, "cloud-metadata", Decision.block, "network", 0.80, ("metadata",)),
    UrlRule("DA-001", r"https?://[^\s\"']+", Severity.medium, "external-network", Decision.review, "network", 0.70, ("external-network",)),
)

UNICODE_HIDDEN_RULE = PatternRule(
    "SC-002",
    r"[\u200b\u200c\u200d\ufeff]",
    Severity.medium,
    "unicode-hidden",
    Decision.review,
    "supply_chain",
    0.75,
    ("unicode", "hidden-text"),
)

DOC_EXEC_RULE = PatternRule(
    "SC-001",
    r"```(?:bash|sh|zsh|shell|powershell)",
    Severity.medium,
    "doc-exec",
    Decision.review,
    "documentation",
    0.65,
    ("docs", "install"),
)

HOOK_FILENAMES = ("hook", "startup", "bootstrap", "install", "postinstall", "preinstall")
