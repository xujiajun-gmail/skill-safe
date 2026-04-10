from __future__ import annotations

import json
import unittest
from pathlib import Path

from skill_safe.cli import main
from skill_safe.ingest import ingest_target
from skill_safe.i18n import detect_language
from skill_safe.admission import build_summary
from skill_safe.scanners import run_static_analysis
from skill_safe.scoring import score_findings
from skill_safe.semantic import run_semantic_review

FIXTURES = Path(__file__).parent / "fixtures"


class ScanTests(unittest.TestCase):
    def test_basic_skill_has_low_risk(self) -> None:
        target = FIXTURES / "basic_skill"
        from io import StringIO
        import contextlib

        buffer = StringIO()
        with contextlib.redirect_stdout(buffer):
            exit_code = main(["scan", str(target), "--format", "json"])
        self.assertEqual(exit_code, 0)
        payload = json.loads(buffer.getvalue())
        self.assertIn(payload["scores"]["overall"], {"low", "medium"})
        self.assertGreaterEqual(payload["summary"]["finding_count"], 0)
        self.assertEqual(payload["output_language"], "en")
        self.assertEqual(payload["decision"], "allow")

    def test_risky_skill_detects_expected_taxonomy(self) -> None:
        skill = ingest_target(str(FIXTURES / "risky_skill"))
        findings = run_static_analysis(skill) + run_semantic_review(skill)
        taxonomy_ids = {finding.taxonomy_id for finding in findings}
        self.assertIn("EX-001", taxonomy_ids)
        self.assertIn("PI-001", taxonomy_ids)
        self.assertIn("PR-003", taxonomy_ids)
        scores = score_findings(findings)
        self.assertIn(scores.overall, {"high", "critical"})
        self.assertGreaterEqual(scores.exploitability, 65)

    def test_sarif_output_can_be_written(self) -> None:
        target = FIXTURES / "risky_skill"
        output = Path(self._testMethodName + ".sarif")
        try:
            exit_code = main(["scan", str(target), "--format", "sarif", "--output", str(output)])
            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["version"], "2.1.0")
            self.assertTrue(payload["runs"][0]["results"])
        finally:
            if output.exists():
                output.unlink()

    def test_summary_breakdown_present(self) -> None:
        skill = ingest_target(str(FIXTURES / "risky_skill"))
        findings = run_static_analysis(skill) + run_semantic_review(skill)
        summary = build_summary(findings)
        self.assertEqual(summary["finding_count"], len(findings))
        self.assertIn("EX-001", summary["taxonomy_breakdown"])

    def test_language_override_to_zh(self) -> None:
        target = FIXTURES / "basic_skill"
        from io import StringIO
        import contextlib

        buffer = StringIO()
        with contextlib.redirect_stdout(buffer):
            exit_code = main(["scan", str(target), "--format", "json", "--lang", "zh"])
        self.assertEqual(exit_code, 0)
        payload = json.loads(buffer.getvalue())
        self.assertEqual(payload["output_language"], "zh")

    def test_detect_language_defaults_to_zh_when_ambiguous(self) -> None:
        self.assertEqual(detect_language("", "auto"), "zh")
        self.assertEqual(detect_language("123456", "auto"), "zh")

    def test_json_report_includes_taxonomy_and_decision_hint(self) -> None:
        target = FIXTURES / "risky_skill"
        from io import StringIO
        import contextlib

        buffer = StringIO()
        with contextlib.redirect_stdout(buffer):
            exit_code = main(["scan", str(target), "--format", "json", "--lang", "en"])
        self.assertEqual(exit_code, 0)
        payload = json.loads(buffer.getvalue())
        self.assertEqual(payload["decision"], "block")
        self.assertTrue(payload["findings"])
        first = payload["findings"][0]
        self.assertIn("taxonomy_id", first)
        self.assertIn("decision_hint", first)
        self.assertIn("stage", first)
        self.assertIn(first["taxonomy_id"], payload["summary"]["taxonomy_breakdown"])

    def test_localized_text_changes_but_schema_stays_stable(self) -> None:
        target = FIXTURES / "risky_skill"
        from io import StringIO
        import contextlib

        zh_buffer = StringIO()
        with contextlib.redirect_stdout(zh_buffer):
            exit_code_zh = main(["scan", str(target), "--format", "json", "--lang", "zh"])
        self.assertEqual(exit_code_zh, 0)
        zh_payload = json.loads(zh_buffer.getvalue())

        en_buffer = StringIO()
        with contextlib.redirect_stdout(en_buffer):
            exit_code_en = main(["scan", str(target), "--format", "json", "--lang", "en"])
        self.assertEqual(exit_code_en, 0)
        en_payload = json.loads(en_buffer.getvalue())

        self.assertEqual(zh_payload["decision"], en_payload["decision"])
        self.assertEqual(
            [item["taxonomy_id"] for item in zh_payload["findings"]],
            [item["taxonomy_id"] for item in en_payload["findings"]],
        )
        self.assertNotEqual(zh_payload["findings"][0]["title"], en_payload["findings"][0]["title"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
