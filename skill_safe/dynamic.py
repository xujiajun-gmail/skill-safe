from __future__ import annotations

from pathlib import Path

from skill_safe.models import SkillIR



def run_dynamic_observation(skill: SkillIR, enabled: bool) -> dict[str, object]:
    if not enabled:
        return {
            "mode": "disabled",
            "executed": False,
            "note": "Dynamic observation not requested.",
        }
    candidate_scripts = [
        file.path
        for file in skill.files
        if Path(file.path).suffix.lower() in {".sh", ".bash", ".zsh", ".py", ".js", ".ts"}
    ]
    return {
        "mode": "simulation",
        "executed": False,
        "note": "v0.2 intentionally avoids executing untrusted skills on the host. Use a hardened sandbox runner before enabling live execution.",
        "candidate_entrypoints": sorted(set(candidate_scripts + skill.entrypoints))[:20],
    }
