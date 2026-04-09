from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


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


@dataclass(slots=True)
class Evidence:
    file: str
    detail: str
    line: int | None = None
    excerpt: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Finding:
    id: str
    title: str
    severity: Severity
    category: str
    confidence: float
    impact: str
    remediation: str
    evidence: list[Evidence]
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


@dataclass(slots=True)
class ScoreCard:
    malice_likelihood: int
    exploitability: int
    blast_radius: int
    privilege_excess: int
    supply_chain_trust: int
    overall: str


@dataclass(slots=True)
class ScanReport:
    target: str
    source: SourceInfo
    summary: dict[str, Any]
    scores: ScoreCard
    findings: list[Finding]
    artifacts: dict[str, Any]
    sandbox_observations: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "source": asdict(self.source),
            "summary": self.summary,
            "scores": asdict(self.scores),
            "findings": [finding.to_dict() for finding in self.findings],
            "artifacts": self.artifacts,
            "sandbox_observations": self.sandbox_observations,
        }
