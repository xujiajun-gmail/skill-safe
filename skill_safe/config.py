from __future__ import annotations

from pathlib import Path
from typing import Any

CONFIG_CANDIDATES = ("skill-safe.yml", "skill-safe.yaml", ".skill-safe.yml")



def load_config(path: str | None = None, cwd: str | Path | None = None) -> dict[str, Any]:
    if path:
        config_path = Path(path)
        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")
        return _parse_config(config_path)
    search_root = Path(cwd or ".")
    for candidate in CONFIG_CANDIDATES:
        config_path = search_root / candidate
        if config_path.exists():
            return _parse_config(config_path)
    return {}



def get_config_value(config: dict[str, Any], *keys: str, default: Any = None) -> Any:
    current: Any = config
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return default
        current = current[key]
    return current



def merge_taxonomy_overrides(config: dict[str, Any]) -> dict[str, str]:
    overrides = get_config_value(config, "policy", "taxonomy_overrides", default={})
    if not isinstance(overrides, dict):
        return {}
    return {str(key): str(value) for key, value in overrides.items()}



def _parse_config(path: Path) -> dict[str, Any]:
    suffix = path.suffix.lower()
    if suffix == ".json":
        import json

        return json.loads(path.read_text(encoding="utf-8"))
    if suffix == ".toml":
        import tomllib

        return tomllib.loads(path.read_text(encoding="utf-8"))
    return _parse_simple_yaml(path.read_text(encoding="utf-8"))



def _parse_simple_yaml(text: str) -> dict[str, Any]:
    root: dict[str, Any] = {}
    stack: list[tuple[int, Any]] = [(-1, root)]
    lines = text.splitlines()

    for index, raw_line in enumerate(lines):
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        line = raw_line.strip()

        while len(stack) > 1 and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]

        if line.startswith("- "):
            value = _parse_scalar(line[2:].strip())
            if not isinstance(parent, list):
                raise ValueError("Invalid YAML list structure")
            parent.append(value)
            continue

        key, _, value_part = line.partition(":")
        key = key.strip()
        value_part = value_part.strip()

        if value_part == "":
            next_container: Any = _decide_next_container(lines, index, indent)
            if isinstance(parent, dict):
                parent[key] = next_container
            else:
                raise ValueError("Invalid YAML mapping structure")
            stack.append((indent, next_container))
        else:
            if isinstance(parent, dict):
                parent[key] = _parse_scalar(value_part)
            else:
                raise ValueError("Invalid YAML scalar placement")

    return root



def _decide_next_container(lines: list[str], current_index: int, current_indent: int) -> Any:
    for raw_line in lines[current_index + 1 :]:
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        if indent <= current_indent:
            break
        stripped = raw_line.strip()
        if stripped.startswith("- "):
            return []
        return {}
    return {}



def _parse_scalar(value: str) -> Any:
    if value in {"true", "True"}:
        return True
    if value in {"false", "False"}:
        return False
    if value in {"null", "None", "~"}:
        return None
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass
    return value
