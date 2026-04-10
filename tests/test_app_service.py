from __future__ import annotations

import tempfile
import unittest
import zipfile
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

from app.service.history import ScanHistory
from app.service.scan_service import UploadedFile, scan_archive_upload, scan_directory_upload, scan_path, scan_url
from skill_safe.ingest import IngestError, ingest_target

FIXTURES = Path(__file__).parent / "fixtures"


class AppServiceTests(unittest.TestCase):
    def test_scan_path_returns_structured_response(self) -> None:
        response = scan_path(str(FIXTURES / "basic_skill"), lang="en")
        self.assertEqual(response["request"]["input_mode"], "path")
        self.assertEqual(response["scan_report"]["output_language"], "en")
        self.assertIn("Explanation type", response["explanation_text"])

    def test_scan_archive_upload_supports_zip(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / "skill.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                for path in (FIXTURES / "risky_skill").rglob("*"):
                    if path.is_file():
                        archive.write(path, arcname=str(path.relative_to(FIXTURES / "risky_skill")))
            response = scan_archive_upload(UploadedFile(filename="skill.zip", content=archive_path.read_bytes()), lang="en")
        self.assertEqual(response["request"]["input_mode"], "archive_upload")
        self.assertTrue(response["scan_report"]["findings"])
        self.assertEqual(response["scan_report"]["decision"], "block")

    def test_scan_directory_upload_reconstructs_relative_paths(self) -> None:
        files = [
            UploadedFile(
                filename=str(path.name),
                relative_path=str(path.relative_to(FIXTURES / "basic_skill")),
                content=path.read_bytes(),
            )
            for path in (FIXTURES / "basic_skill").rglob("*")
            if path.is_file()
        ]
        response = scan_directory_upload(files, lang="en")
        self.assertEqual(response["request"]["input_mode"], "directory_upload")
        self.assertEqual(response["scan_report"]["decision"], "allow")

    def test_scan_url_supports_mocked_download(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / "skill.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                for path in (FIXTURES / "basic_skill").rglob("*"):
                    if path.is_file():
                        archive.write(path, arcname=str(path.relative_to(FIXTURES / "basic_skill")))

            class FakeResponse(BytesIO):
                def __enter__(self) -> "FakeResponse":
                    return self

                def __exit__(self, exc_type, exc, tb) -> None:
                    self.close()

            with patch("urllib.request.urlopen", return_value=FakeResponse(archive_path.read_bytes())):
                response = scan_url("https://example.test/skill.zip", lang="en")
        self.assertEqual(response["request"]["input_mode"], "url")
        self.assertEqual(response["scan_report"]["decision"], "allow")

    def test_scan_directory_upload_rejects_unsafe_relative_path(self) -> None:
        with self.assertRaises(ValueError):
            scan_directory_upload([UploadedFile(filename="evil.sh", relative_path="../evil.sh", content=b"echo bad")])

    def test_unsafe_archive_member_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / "evil.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("../escape.sh", "echo hacked")
            with self.assertRaises(IngestError):
                ingest_target(str(archive_path))

    def test_scan_url_rejects_credentialed_urls(self) -> None:
        with self.assertRaises(ValueError):
            scan_url("https://user:pass@example.test/skill.zip")

    def test_scan_archive_upload_rejects_unsupported_extension(self) -> None:
        with self.assertRaises(ValueError):
            scan_archive_upload(UploadedFile(filename="skill.exe", content=b"not-archive"))

    def test_history_store_keeps_latest_entries(self) -> None:
        history = ScanHistory(max_entries=2)
        first = history.add(_payload("scan-1", "allow", 1))
        second = history.add(_payload("scan-2", "review", 2))
        third = history.add(_payload("scan-3", "block", 3))
        items = history.list_items()
        self.assertEqual([item["scan_id"] for item in items], [third["scan_id"], second["scan_id"]])
        self.assertIsNone(history.get_payload(first["scan_id"]))
        self.assertIsNotNone(history.get_payload(third["scan_id"]))


def _payload(target: str, decision: str, finding_count: int) -> dict[str, object]:
    return {
        "request": {"input_mode": "path", "source_hint": target},
        "scan_report": {
            "target": target,
            "output_language": "en",
            "decision": decision,
            "summary": {"finding_count": finding_count},
            "scores": {"overall": "medium"},
        },
        "explanation": {},
        "explanation_text": "demo",
    }


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
