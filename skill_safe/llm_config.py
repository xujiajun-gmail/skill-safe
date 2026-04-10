from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class LLMRuntimeConfig:
    mode: str = "off"
    provider: str | None = None
    base_url: str | None = None
    model: str | None = None
    api_key_env: str | None = None
    timeout_seconds: int = 30
    max_tokens: int = 1200
    temperature: float = 0.1
    purpose_limits: dict[str, bool] = field(
        default_factory=lambda: {
            "alignment": True,
            "explain": True,
            "localization": True,
            "admission": False,
            "gatekeeper": False,
        }
    )

    def public_dict(self) -> dict[str, Any]:
        return asdict(self)


def resolve_llm_config(args: Any, config: dict[str, Any]) -> LLMRuntimeConfig:
    llm = config.get("llm", {})
    if not isinstance(llm, dict):
        llm = {}
    purpose_limits = llm.get("purpose_limits", {})
    if not isinstance(purpose_limits, dict):
        purpose_limits = {}
    return LLMRuntimeConfig(
        mode=_first_value(getattr(args, "llm_mode", None), llm.get("mode"), "off"),
        provider=_first_value(getattr(args, "llm_provider", None), llm.get("provider")),
        base_url=_first_value(getattr(args, "llm_base_url", None), llm.get("base_url")),
        model=_first_value(getattr(args, "llm_model", None), llm.get("model")),
        api_key_env=_first_value(getattr(args, "llm_api_key_env", None), llm.get("api_key_env")),
        timeout_seconds=int(_first_value(None, llm.get("timeout_seconds"), 30)),
        max_tokens=int(_first_value(None, llm.get("max_tokens"), 1200)),
        temperature=float(_first_value(None, llm.get("temperature"), 0.1)),
        purpose_limits={
            "alignment": bool(purpose_limits.get("alignment", True)),
            "explain": bool(purpose_limits.get("explain", True)),
            "localization": bool(purpose_limits.get("localization", True)),
            "admission": bool(purpose_limits.get("admission", False)),
            "gatekeeper": bool(purpose_limits.get("gatekeeper", False)),
        },
    )


def _first_value(*values: Any) -> Any:
    for value in values:
        if value is not None:
            return value
    return None
