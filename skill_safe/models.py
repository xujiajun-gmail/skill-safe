from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Stage(str, Enum):
    gatekeeper = "gatekeeper"
    alignment = "alignment"
    flow = "flow"
    dynamic = "dynamic"


class Decision(str, Enum):
    allow = "allow"
    review = "review"
    block = "block"
    sandbox_only = "sandbox_only"


class AlignmentStatus(str, Enum):
    match = "match"
    over_declared = "over_declared"
    under_declared = "under_declared"
    mixed = "mixed"


@dataclass(slots=True)
class SourceInfo:
    target: str
    source_type: str
    extracted_to: str | None = None
    provenance: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class FileRecord:
    path: str
    size: int
    sha256: str
    text: str | None
    is_binary: bool


@dataclass(slots=True)
class SkillIR:
    root: Path
    source: SourceInfo
    files: list[FileRecord]
    manifest: dict[str, Any] | None = None
    permission_hints: list[str] = field(default_factory=list)
    entrypoints: list[str] = field(default_factory=list)
    hooks: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)

    def natural_language_blob(self) -> str:
        parts: list[str] = []
        if self.manifest:
            parts.append(str(self.manifest))
        for file in self.files:
            if file.text and file.path.lower().endswith((".md", ".txt", ".json", ".toml", ".yaml", ".yml")):
                parts.append(file.text)
        return "\n".join(parts)


@dataclass(slots=True)
class Evidence:
    file: str
    detail: str
    line: int | None = None
    excerpt: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class LLMMetadata:
    llm_used: bool = False
    llm_provider: str | None = None
    llm_model: str | None = None
    llm_prompt_version: str | None = None
    llm_confidence: float | None = None
    evidence_refs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Finding:
    id: str
    taxonomy_id: str
    stage: Stage
    severity: Severity
    category: str
    confidence: float
    decision_hint: Decision
    evidence: list[Evidence]
    tags: list[str] = field(default_factory=list)
    alignment_status: AlignmentStatus | None = None
    llm: LLMMetadata = field(default_factory=LLMMetadata)


@dataclass(slots=True)
class ScoreCard:
    malice_likelihood: int
    exploitability: int
    blast_radius: int
    privilege_excess: int
    supply_chain_trust: int
    overall: str


@dataclass(slots=True)
class TrustProfile:
    publisher_confidence: str
    provenance_status: str
    permission_transparency: str
    version_stability: str
    continuous_monitoring_status: str
    security_score: int


@dataclass(slots=True)
class ScanReport:
    schema_version: str
    target: str
    source: SourceInfo
    output_language: str
    decision: Decision
    summary: dict[str, Any]
    scores: ScoreCard
    trust_profile: TrustProfile
    provenance: dict[str, Any]
    findings: list[Finding]
    flows: list[dict[str, Any]]
    runtime_trace: dict[str, Any] | None
    artifacts: dict[str, Any]
    llm: LLMMetadata = field(default_factory=LLMMetadata)
