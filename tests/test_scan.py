from __future__ import annotations

import json
import unittest
from pathlib import Path

from skill_safe.cli import main
from skill_safe.ingest import ingest_target
from skill_safe.reporting import build_summary
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
        self.assertTrue(payload["artifacts"]["manifest_present"])

    def test_risky_skill_detects_critical_patterns(self) -> None:
        skill = ingest_target(str(FIXTURES / "risky_skill"))
        findings = run_static_analysis(skill) + run_semantic_review(skill)
        ids = {finding.id for finding in findings}
        self.assertIn("static.download-exec", ids)
        self.assertIn("static.prompt-injection", ids)
        self.assertIn("exec.hook-entrypoint", ids)
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
        self.assertIn("execution", summary["category_breakdown"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
