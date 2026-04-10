from __future__ import annotations

import hashlib
import json
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None

from skill_safe.models import FileRecord, SkillIR, SourceInfo

TEXT_EXTENSIONS = {
    ".md",
    ".txt",
    ".json",
    ".toml",
    ".yaml",
    ".yml",
    ".py",
    ".sh",
    ".bash",
    ".zsh",
    ".js",
    ".ts",
    ".mjs",
    ".cjs",
    ".env",
    ".cfg",
    ".conf",
    ".ini",
    ".xml",
}
MANIFEST_CANDIDATES = {
    "skill.json",
    "manifest.json",
    "plugin.json",
    "package.json",
    "pyproject.toml",
    ".codex-plugin/plugin.json",
}
HOOK_KEYWORDS = ("hook", "startup", "bootstrap", "install", "postinstall", "preinstall")
URL_KEYS = {"url", "urls", "endpoint", "endpoints", "domain", "domains"}


class IngestError(RuntimeError):
    pass


class ExtractedTarget:
    def __init__(self, root: Path, cleanup: tempfile.TemporaryDirectory[str] | None = None):
        self.root = root
        self._cleanup = cleanup

    def close(self) -> None:
        if self._cleanup is not None:
            self._cleanup.cleanup()



def ingest_target(target: str, source_type: str = "auto") -> SkillIR:
    extracted = _prepare_target(Path(target), source_type)
    try:
        files = [_read_file(path, extracted.root) for path in _iter_files(extracted.root)]
        manifest = _load_manifest(extracted.root, files)
        permission_hints = _extract_permission_hints(manifest)
        entrypoints = _extract_entrypoints(manifest, files)
        hooks = [entry for entry in entrypoints if any(keyword in entry.lower() for keyword in HOOK_KEYWORDS)]
        urls = sorted({url for file in files for url in _extract_urls(file.text or "")})
        urls.extend(_extract_urls_from_manifest(manifest))
        source = SourceInfo(
            target=target,
            source_type=_detect_source_type(Path(target), source_type),
            extracted_to=str(extracted.root) if extracted.root != Path(target) else None,
            provenance={
                "file_count": len(files),
                "manifest_path": _manifest_path(extracted.root),
            },
        )
        return SkillIR(
            root=extracted.root,
            source=source,
            files=files,
            manifest=manifest,
            permission_hints=permission_hints,
            entrypoints=entrypoints,
            hooks=hooks,
            urls=sorted(set(urls)),
        )
    finally:
        extracted.close()



def _prepare_target(path: Path, source_type: str) -> ExtractedTarget:
    detected = _detect_source_type(path, source_type)
    if detected in {"dir", "git"}:
        if not path.exists() or not path.is_dir():
            raise IngestError(f"Directory target not found: {path}")
        return ExtractedTarget(path.resolve())
    if detected == "archive":
        if not path.exists() or not path.is_file():
            raise IngestError(f"Archive target not found: {path}")
        temp_dir = tempfile.TemporaryDirectory(prefix="skill-safe-")
        root = Path(temp_dir.name)
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as archive:
                archive.extractall(root)
        elif tarfile.is_tarfile(path):
            with tarfile.open(path) as archive:
                archive.extractall(root)
        else:
            temp_dir.cleanup()
            raise IngestError(f"Unsupported archive format: {path}")
        members = [child for child in root.iterdir()]
        if len(members) == 1 and members[0].is_dir():
            return ExtractedTarget(members[0], temp_dir)
        return ExtractedTarget(root, temp_dir)
    raise IngestError(
        "Unsupported target. v0.2 supports directories, local git working trees, and archives only."
    )



def _detect_source_type(path: Path, requested: str) -> str:
    if requested != "auto":
        return requested
    if path.is_dir() and (path / ".git").exists():
        return "git"
    if path.is_dir():
        return "dir"
    if path.is_file() and (zipfile.is_zipfile(path) or tarfile.is_tarfile(path)):
        return "archive"
    return "unknown"



def _iter_files(root: Path) -> list[Path]:
    return sorted(path for path in root.rglob("*") if path.is_file())



def _read_file(path: Path, root: Path) -> FileRecord:
    raw = path.read_bytes()
    sha256 = hashlib.sha256(raw).hexdigest()
    rel_path = str(path.relative_to(root))
    is_binary = _is_binary(raw, path)
    text = None
    if not is_binary:
        text = raw.decode("utf-8", errors="replace")
    return FileRecord(path=rel_path, size=len(raw), sha256=sha256, text=text, is_binary=is_binary)



def _is_binary(raw: bytes, path: Path) -> bool:
    if path.suffix.lower() in TEXT_EXTENSIONS:
        return False
    if not raw:
        return False
    return b"\x00" in raw[:1024]



def _load_manifest(root: Path, files: list[FileRecord]) -> dict[str, Any] | None:
    for candidate in MANIFEST_CANDIDATES:
        path = root / candidate
        if path.exists() and path.is_file():
            return _parse_manifest(path)
    for file in files:
        if Path(file.path).name in MANIFEST_CANDIDATES and file.text:
            return _parse_text_manifest(file.path, file.text)
    return None



def _parse_manifest(path: Path) -> dict[str, Any] | None:
    text = path.read_text(encoding="utf-8", errors="replace")
    return _parse_text_manifest(str(path), text)



def _parse_text_manifest(name: str, text: str) -> dict[str, Any] | None:
    suffix = Path(name).suffix.lower()
    if suffix == ".json":
        try:
            data = json.loads(text)
            return data if isinstance(data, dict) else {"_root": data}
        except json.JSONDecodeError:
            return None
    if suffix == ".toml" and tomllib is not None:
        try:
            data = tomllib.loads(text)
            return data if isinstance(data, dict) else {"_root": data}
        except tomllib.TOMLDecodeError:
            return None
    return None



def _extract_permission_hints(manifest: dict[str, Any] | None) -> list[str]:
    if not manifest:
        return []
    results: list[str] = []
    stack = [manifest]
    while stack:
        current = stack.pop()
        for key, value in current.items():
            key_lower = str(key).lower()
            if isinstance(value, dict):
                stack.append(value)
                continue
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        stack.append(item)
                    elif "permission" in key_lower or key_lower in {"capabilities", "scopes", "tools"}:
                        results.append(str(item))
                continue
            if "permission" in key_lower or key_lower in {"capabilities", "scope", "tools", "access"}:
                results.append(str(value))
    return sorted(set(results))



def _extract_entrypoints(manifest: dict[str, Any] | None, files: list[FileRecord]) -> list[str]:
    entries: list[str] = []
    if manifest:
        stack = [manifest]
        while stack:
            current = stack.pop()
            for key, value in current.items():
                key_lower = str(key).lower()
                if isinstance(value, dict):
                    stack.append(value)
                    continue
                if isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            stack.append(item)
                        elif any(token in key_lower for token in ("entry", "command", "hook", "script", "run")):
                            entries.append(str(item))
                    continue
                if any(token in key_lower for token in ("entry", "command", "hook", "script", "run")):
                    entries.append(str(value))
    for file in files:
        lower = file.path.lower()
        if any(keyword in lower for keyword in HOOK_KEYWORDS):
            entries.append(file.path)
    return sorted(set(entries))



def _extract_urls(text: str) -> list[str]:
    results: list[str] = []
    for token in text.split():
        if token.startswith(("http://", "https://")):
            results.append(token.strip("()[]<>{}\"'.,"))
    return results



def _extract_urls_from_manifest(manifest: dict[str, Any] | None) -> list[str]:
    if not manifest:
        return []
    results: list[str] = []
    stack = [manifest]
    while stack:
        current = stack.pop()
        for key, value in current.items():
            key_lower = str(key).lower()
            if isinstance(value, dict):
                stack.append(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        stack.append(item)
                    elif key_lower in URL_KEYS and str(item).startswith(("http://", "https://")):
                        results.append(str(item))
            elif key_lower in URL_KEYS and str(value).startswith(("http://", "https://")):
                results.append(str(value))
    return results



def _manifest_path(root: Path) -> str | None:
    for candidate in MANIFEST_CANDIDATES:
        if (root / candidate).exists():
            return candidate
    return None
