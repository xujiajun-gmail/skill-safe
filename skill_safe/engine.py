from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from skill_safe.admission import build_provenance, build_summary, build_trust_profile, decide_findings
from skill_safe.config import get_config_value, load_config, merge_taxonomy_overrides
from skill_safe.dynamic import run_dynamic_observation
from skill_safe.flow import apply_flow_decisions, run_flow_analysis
from skill_safe.ingest import ingest_target
from skill_safe.i18n import detect_language
from skill_safe.llm_config import resolve_llm_config
from skill_safe.models import ScanReport
from skill_safe.policy import apply_environment_policy, apply_policy_profile, apply_taxonomy_overrides
from skill_safe.scanners import run_static_analysis
from skill_safe.scoring import score_findings
from skill_safe.semantic import run_semantic_review


@dataclass(slots=True)
class ScanOptions:
    config_path: str | None = None
    source_type: str = "auto"
    policy: str | None = None
    policy_profile: str = "default"
    offline: bool = False
    dynamic: bool = False
    lang: str = "auto"
    llm_mode: str | None = None
    llm_provider: str | None = None
    llm_base_url: str | None = None
    llm_model: str | None = None
    llm_api_key_env: str | None = None


def build_scan_report(target: str, options: ScanOptions) -> ScanReport:
    config = load_config(options.config_path, cwd=Path(target).resolve() if Path(target).exists() else Path.cwd())
    source_type = options.source_type
    if source_type == "auto":
        source_type = get_config_value(config, "scan", "source_type", default="auto")
    skill = ingest_target(target, source_type)

    llm_config = resolve_llm_config(options, config)
    gatekeeper_findings = run_static_analysis(skill)
    findings = list(gatekeeper_findings)
    findings.extend(run_semantic_review(skill, gatekeeper_findings=gatekeeper_findings))
    flow_findings, flows = run_flow_analysis(skill, findings)
    findings.extend(flow_findings)
    policy_profile = options.policy_profile
    if policy_profile == "default":
        policy_profile = get_config_value(config, "policy", "profile", default="default")
    findings = apply_policy_profile(findings, policy_profile)
    findings = apply_environment_policy(findings, config)
    findings = apply_taxonomy_overrides(findings, merge_taxonomy_overrides(config))
    flows = apply_flow_decisions(flows, findings)
    findings.sort(key=lambda item: item.confidence, reverse=True)
    output_language = detect_language(skill.natural_language_blob(), _resolve_lang_mode(options, config))
    scores = score_findings(findings)
    artifacts = {
        "manifest_present": skill.manifest is not None,
        "file_count": len(skill.files),
        "permission_hints": skill.permission_hints,
        "entrypoints": skill.entrypoints,
        "urls": skill.urls,
        "policy": options.policy,
        "policy_profile": policy_profile,
        "config_path": options.config_path,
        "offline": options.offline,
        "llm_config": llm_config.public_dict(),
        "publisher_identity": _publisher_identity(skill),
        "repository_url": _repository_url(skill),
        "release_ref": None,
        "content_hash": _manifest_hash(skill),
    }
    runtime_trace = run_dynamic_observation(skill, enabled=options.dynamic)
    return ScanReport(
        schema_version="1.0",
        target=target,
        source=skill.source,
        output_language=output_language,
        decision=decide_findings(findings),
        summary=build_summary(findings),
        scores=scores,
        trust_profile=build_trust_profile(artifacts, findings, scores.supply_chain_trust),
        provenance=build_provenance(artifacts, findings),
        findings=findings,
        flows=flows,
        runtime_trace=runtime_trace,
        artifacts=artifacts,
    )


def _resolve_lang_mode(options: ScanOptions, config: dict[str, object]) -> str:
    lang_mode = options.lang
    if lang_mode == "auto":
        lang_mode = get_config_value(config, "language", "mode", default="auto")
    return lang_mode


def _publisher_identity(skill) -> str | None:
    manifest = skill.manifest or {}
    return manifest.get("publisher") or manifest.get("author")


def _repository_url(skill) -> str | None:
    manifest = skill.manifest or {}
    for key in ("repository", "homepage", "url"):
        value = manifest.get(key)
        if isinstance(value, str):
            return value
    return None


def _manifest_hash(skill) -> str | None:
    for file in skill.files:
        if file.path in {"skill.json", "manifest.json", ".codex-plugin/plugin.json", "package.json", "pyproject.toml"}:
            return file.sha256
    return None
