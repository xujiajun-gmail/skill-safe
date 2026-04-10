from __future__ import annotations

import mimetypes
import tempfile
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from skill_safe import __version__
from skill_safe.engine import ScanOptions, build_scan_report
from skill_safe.explain import build_explanation, render_explanation
from skill_safe.reporting import report_to_dict

DEFAULT_DOWNLOAD_TIMEOUT_SECONDS = 30
DEFAULT_MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024
DEFAULT_MAX_UPLOAD_BYTES = 50 * 1024 * 1024
DEFAULT_MAX_DIRECTORY_FILES = 2000
SUPPORTED_ARCHIVE_SUFFIXES = (".zip", ".tar", ".tgz", ".tar.gz", ".tar.bz2", ".tar.xz")


@dataclass(slots=True)
class UploadedFile:
    filename: str
    content: bytes
    relative_path: str | None = None


def scan_path(path: str, *, lang: str = "auto", dynamic: bool = False) -> dict[str, object]:
    if not Path(path).exists():
        raise FileNotFoundError(f"Target path not found: {path}")
    return _scan_target(path, lang=lang, dynamic=dynamic, input_mode="path", source_hint=path)


def scan_archive_upload(file: UploadedFile, *, lang: str = "auto", dynamic: bool = False) -> dict[str, object]:
    _validate_upload_size(len(file.content), file.filename)
    _validate_archive_filename(file.filename)
    suffix = "".join(Path(file.filename).suffixes) or mimetypes.guess_extension("application/octet-stream") or ".bin"
    with tempfile.TemporaryDirectory(prefix="skill-safe-app-archive-") as temp_dir:
        archive_path = Path(temp_dir) / f"upload{suffix}"
        archive_path.write_bytes(file.content)
        return _scan_target(str(archive_path), lang=lang, dynamic=dynamic, input_mode="archive_upload", source_hint=file.filename)


def scan_directory_upload(files: list[UploadedFile], *, lang: str = "auto", dynamic: bool = False) -> dict[str, object]:
    if not files:
        raise ValueError("No directory files were uploaded.")
    if len(files) > DEFAULT_MAX_DIRECTORY_FILES:
        raise ValueError(f"Uploaded directory exceeds the {DEFAULT_MAX_DIRECTORY_FILES} file limit.")
    total_bytes = sum(len(file.content) for file in files)
    _validate_upload_size(total_bytes, "directory upload")
    with tempfile.TemporaryDirectory(prefix="skill-safe-app-dir-") as temp_dir:
        root = Path(temp_dir) / "skill"
        root.mkdir(parents=True, exist_ok=True)
        for file in files:
            relative = file.relative_path or file.filename
            relative_path = Path(relative)
            if relative_path.is_absolute() or ".." in relative_path.parts:
                raise ValueError(f"Unsafe relative path in uploaded directory: {relative}")
            destination = root / relative_path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(file.content)
        return _scan_target(str(root), lang=lang, dynamic=dynamic, input_mode="directory_upload", source_hint="directory")


def scan_url(url: str, *, lang: str = "auto", dynamic: bool = False) -> dict[str, object]:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only http/https URLs are supported.")
    if not parsed.netloc:
        raise ValueError("URL must include a hostname.")
    if parsed.username or parsed.password:
        raise ValueError("Credentialed URLs are not supported.")
    suffix = "".join(Path(parsed.path).suffixes) or ".download"
    with tempfile.TemporaryDirectory(prefix="skill-safe-app-url-") as temp_dir:
        target_path = Path(temp_dir) / f"remote{suffix}"
        request = urllib.request.Request(url, headers={"User-Agent": f"skill-safe-app/{__version__}"})
        target_path.write_bytes(_download_bytes(request))
        return _scan_target(str(target_path), lang=lang, dynamic=dynamic, input_mode="url", source_hint=url)


def _scan_target(
    target: str,
    *,
    lang: str,
    dynamic: bool,
    input_mode: str,
    source_hint: str,
) -> dict[str, object]:
    _validate_lang(lang)
    report = build_scan_report(target, ScanOptions(lang=lang, dynamic=dynamic))
    report_dict = report_to_dict(report)
    explanation = build_explanation(report_dict, report.output_language)
    explanation_text = render_explanation(report_dict, report.output_language, "text")
    return {
        "request": {
            "input_mode": input_mode,
            "source_hint": source_hint,
            "lang_requested": lang,
            "lang": report.output_language,
            "dynamic": dynamic,
        },
        "scan_report": report_dict,
        "explanation": explanation,
        "explanation_text": explanation_text,
    }


def _download_bytes(request: urllib.request.Request) -> bytes:
    chunks: list[bytes] = []
    total = 0
    with urllib.request.urlopen(request, timeout=DEFAULT_DOWNLOAD_TIMEOUT_SECONDS) as response:  # noqa: S310
        while True:
            chunk = response.read(64 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > DEFAULT_MAX_DOWNLOAD_BYTES:
                raise ValueError("Downloaded skill exceeds the 50 MB limit.")
            chunks.append(chunk)
    return b"".join(chunks)


def _validate_upload_size(size: int, label: str) -> None:
    if size > DEFAULT_MAX_UPLOAD_BYTES:
        raise ValueError(f"{label} exceeds the 50 MB limit.")


def _validate_archive_filename(filename: str) -> None:
    lowered = filename.lower()
    if not lowered.endswith(SUPPORTED_ARCHIVE_SUFFIXES):
        raise ValueError("Uploaded archive must be one of: .zip, .tar, .tgz, .tar.gz, .tar.bz2, .tar.xz")


def _validate_lang(lang: str) -> None:
    if lang not in {"auto", "zh", "en"}:
        raise ValueError("lang must be one of: auto, zh, en")
