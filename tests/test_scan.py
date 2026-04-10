from __future__ import annotations

import json
import unittest
from pathlib import Path

from skill_safe.cli import main
from skill_safe.ingest import ingest_target
from skill_safe.i18n import detect_language
from skill_safe.admission import build_summary
from skill_safe.scanners import run_static_analysis
from skill_safe.policy import apply_policy_profile
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

    def test_risky_skill_scan_report_includes_chain_flows(self) -> None:
        target = FIXTURES / "risky_skill"
        from io import StringIO
        import contextlib

        buffer = StringIO()
        with contextlib.redirect_stdout(buffer):
            exit_code = main(["scan", str(target), "--format", "json", "--lang", "en"])
        self.assertEqual(exit_code, 0)
        payload = json.loads(buffer.getvalue())
        taxonomy_ids = {item["taxonomy_id"] for item in payload["findings"]}
        self.assertIn("CH-001", taxonomy_ids)
        self.assertIn("CH-004", taxonomy_ids)
        flow_ids = {item["id"] for item in payload["flows"]}
        self.assertIn("flow.ch001.untrusted-string-to-shell", flow_ids)
        self.assertIn("flow.ch004.secret-to-egress", flow_ids)
        self.assertTrue(all(item["blocked_by_policy"] for item in payload["flows"]))
        secret_flow = next(item for item in payload["flows"] if item["id"] == "flow.ch004.secret-to-egress")
        self.assertNotIn("SC-004", secret_flow["triggered_taxonomy_ids"])
        self.assertEqual(len(secret_flow["path"]), 2)
        self.assertIn("source_node", secret_flow)
        self.assertIn("sink_node", secret_flow)
        self.assertTrue(secret_flow["source_node"]["evidence_refs"])
        self.assertTrue(secret_flow["sink_node"]["evidence_refs"])
        self.assertEqual(len(secret_flow["path_labels"]), 2)

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

    def test_strict_policy_profile_can_escalate_alignment_risk(self) -> None:
        skill = ingest_target(str(FIXTURES / "risky_skill"))
        findings = run_static_analysis(skill) + run_semantic_review(skill)
        default_alignment = [f for f in findings if f.taxonomy_id == "AL-001"]
        self.assertTrue(default_alignment)
        self.assertTrue(all(f.decision_hint.value == "review" for f in default_alignment))
        strict_findings = apply_policy_profile(findings, "strict")
        strict_alignment = [f for f in strict_findings if f.taxonomy_id == "AL-001"]
        self.assertTrue(strict_alignment)
        self.assertTrue(all(f.decision_hint.value == "block" for f in strict_alignment))

    def test_config_file_can_override_taxonomy_decision(self) -> None:
        target = FIXTURES / "risky_skill"
        config_path = Path(self._testMethodName + ".yml")
        config_path.write_text(
            "\n".join(
                [
                    "version: 1",
                    "policy:",
                    "  profile: default",
                    "  taxonomy_overrides:",
                    "    PI-001: block",
                    "language:",
                    "  mode: en",
                ]
            ),
            encoding="utf-8",
        )
        try:
            from io import StringIO
            import contextlib

            buffer = StringIO()
            with contextlib.redirect_stdout(buffer):
                exit_code = main(["scan", str(target), "--format", "json", "--config", str(config_path)])
            self.assertEqual(exit_code, 0)
            payload = json.loads(buffer.getvalue())
            pi_findings = [item for item in payload["findings"] if item["taxonomy_id"] == "PI-001"]
            self.assertTrue(pi_findings)
            self.assertTrue(all(item["decision_hint"] == "block" for item in pi_findings))
            self.assertEqual(payload["output_language"], "en")
        finally:
            if config_path.exists():
                config_path.unlink()

    def test_supply_chain_fixture_hits_sc004_and_sc002(self) -> None:
        target = FIXTURES / "supply_chain_skill"
        from io import StringIO
        import contextlib

        buffer = StringIO()
        with contextlib.redirect_stdout(buffer):
            exit_code = main(["scan", str(target), "--format", "json", "--lang", "en"])
        self.assertEqual(exit_code, 0)
        payload = json.loads(buffer.getvalue())
        taxonomy_ids = {item["taxonomy_id"] for item in payload["findings"]}
        self.assertIn("SC-004", taxonomy_ids)
        self.assertIn("SC-002", taxonomy_ids)
        self.assertEqual(payload["trust_profile"]["version_stability"], "floating")

    def test_destructive_fixture_hits_ex004(self) -> None:
        skill = ingest_target(str(FIXTURES / "destructive_skill"))
        findings = run_static_analysis(skill)
        destructive = [finding for finding in findings if finding.taxonomy_id == "EX-004"]
        self.assertTrue(destructive)
        self.assertTrue(any(finding.decision_hint.value == "block" for finding in destructive))

    def test_credential_leak_fixture_hits_da002(self) -> None:
        skill = ingest_target(str(FIXTURES / "credential_leak_skill"))
        findings = run_static_analysis(skill)
        credential = [finding for finding in findings if finding.taxonomy_id == "DA-002"]
        self.assertTrue(credential)
        self.assertTrue(all(finding.decision_hint.value == "review" for finding in credential))

    def test_workspace_poison_fixture_hits_mp002(self) -> None:
        target = FIXTURES / "workspace_poison_skill"
        from io import StringIO
        import contextlib

        buffer = StringIO()
        with contextlib.redirect_stdout(buffer):
            exit_code = main(["scan", str(target), "--format", "json", "--lang", "en"])
        self.assertEqual(exit_code, 0)
        payload = json.loads(buffer.getvalue())
        workspace = [item for item in payload["findings"] if item["taxonomy_id"] == "MP-002"]
        self.assertTrue(workspace)
        self.assertTrue(all(item["decision_hint"] == "review" for item in workspace))

    def test_trust_mismatch_fixture_hits_sc004_identity_mismatch(self) -> None:
        skill = ingest_target(str(FIXTURES / "trust_mismatch_skill"))
        findings = run_static_analysis(skill)
        trust_findings = [finding for finding in findings if finding.id == "gatekeeper.sc004.identity-mismatch"]
        self.assertTrue(trust_findings)
        tags = {tag for finding in trust_findings for tag in finding.tags}
        self.assertIn("repo-mismatch", tags)
        self.assertIn("docs-mismatch", tags)

    def test_repository_slug_with_master_substring_is_not_floating_reference(self) -> None:
        skill = ingest_target(str(FIXTURES / "destructive_skill"))
        findings = run_static_analysis(skill)
        floating = [finding for finding in findings if finding.id == "gatekeeper.sc004.unpinned-reference"]
        self.assertFalse(floating)

    def test_alignment_fixture_detects_under_declared_behavior(self) -> None:
        skill = ingest_target(str(FIXTURES / "alignment_skill"))
        gatekeeper_findings = run_static_analysis(skill)
        findings = gatekeeper_findings + run_semantic_review(skill, gatekeeper_findings=gatekeeper_findings)
        alignment_findings = [finding for finding in findings if finding.taxonomy_id == "AL-001"]
        self.assertTrue(alignment_findings)
        self.assertTrue(any(finding.alignment_status.value == "under_declared" for finding in alignment_findings))
        joined_tags = {tag for finding in alignment_findings for tag in finding.tags}
        self.assertIn("no_network_claim_conflicts_with_network_behavior", joined_tags)
        self.assertIn("no_shell_claim_conflicts_with_shell_behavior", joined_tags)

    def test_flow_context_fixture_hits_ch002(self) -> None:
        target = FIXTURES / "flow_context_skill"
        from io import StringIO
        import contextlib

        buffer = StringIO()
        with contextlib.redirect_stdout(buffer):
            exit_code = main(["scan", str(target), "--format", "json", "--lang", "en"])
        self.assertEqual(exit_code, 0)
        payload = json.loads(buffer.getvalue())
        taxonomy_ids = {item["taxonomy_id"] for item in payload["findings"]}
        self.assertIn("CH-002", taxonomy_ids)
        self.assertTrue(any(flow["id"] == "flow.ch002.untrusted-string-to-context" for flow in payload["flows"]))

    def test_flow_param_fixture_hits_ch003(self) -> None:
        target = FIXTURES / "flow_param_skill"
        from io import StringIO
        import contextlib

        buffer = StringIO()
        with contextlib.redirect_stdout(buffer):
            exit_code = main(["scan", str(target), "--format", "json", "--lang", "en"])
        self.assertEqual(exit_code, 0)
        payload = json.loads(buffer.getvalue())
        taxonomy_ids = {item["taxonomy_id"] for item in payload["findings"]}
        self.assertIn("CH-003", taxonomy_ids)
        flow = next(flow for flow in payload["flows"] if flow["id"] == "flow.ch003.untrusted-string-to-parameter")
        self.assertTrue(flow["blocked_by_policy"])
        self.assertIn("EX-003", flow["triggered_taxonomy_ids"])

    def test_config_can_relax_localhost_without_relaxing_metadata(self) -> None:
        target = FIXTURES / "network_skill"
        config_path = Path(self._testMethodName + ".yml")
        config_path.write_text(
            "\n".join(
                [
                    "version: 1",
                    "policy:",
                    "  allow_localhost: true",
                    "  allow_private_network: false",
                    "  allow_metadata_access: false",
                    "language:",
                    "  mode: en",
                ]
            ),
            encoding="utf-8",
        )
        try:
            from io import StringIO
            import contextlib

            buffer = StringIO()
            with contextlib.redirect_stdout(buffer):
                exit_code = main(["scan", str(target), "--format", "json", "--config", str(config_path)])
            self.assertEqual(exit_code, 0)
            payload = json.loads(buffer.getvalue())
            localhost = [
                item for item in payload["findings"] if item["taxonomy_id"] == "PR-002" and "localhost" in item["tags"]
            ]
            metadata = [
                item for item in payload["findings"] if item["taxonomy_id"] == "PR-002" and "metadata" in item["tags"]
            ]
            self.assertTrue(localhost)
            self.assertTrue(metadata)
            self.assertTrue(all(item["decision_hint"] == "review" for item in localhost))
            self.assertTrue(all(item["decision_hint"] == "block" for item in metadata))
        finally:
            if config_path.exists():
                config_path.unlink()

    def test_config_can_relax_shell_and_startup_policy(self) -> None:
        target = FIXTURES / "risky_skill"
        config_path = Path(self._testMethodName + ".yml")
        config_path.write_text(
            "\n".join(
                [
                    "version: 1",
                    "policy:",
                    "  allow_shell: true",
                    "  allow_startup_hooks: true",
                    "language:",
                    "  mode: en",
                ]
            ),
            encoding="utf-8",
        )
        try:
            from io import StringIO
            import contextlib

            buffer = StringIO()
            with contextlib.redirect_stdout(buffer):
                exit_code = main(["scan", str(target), "--format", "json", "--config", str(config_path)])
            self.assertEqual(exit_code, 0)
            payload = json.loads(buffer.getvalue())
            shell_findings = [
                item for item in payload["findings"] if item["taxonomy_id"] == "EX-003" and "shell" in item["tags"]
            ]
            hook_findings = [item for item in payload["findings"] if item["taxonomy_id"] == "PR-003"]
            self.assertTrue(shell_findings)
            self.assertTrue(hook_findings)
            self.assertTrue(all(item["decision_hint"] == "review" for item in shell_findings))
            self.assertTrue(all(item["decision_hint"] == "review" for item in hook_findings))
        finally:
            if config_path.exists():
                config_path.unlink()

    def test_memory_write_policy_toggle_can_downgrade_mp001(self) -> None:
        target = FIXTURES / "memory_writer_skill"
        skill = ingest_target(str(target))
        default_findings = run_static_analysis(skill) + run_semantic_review(skill)
        memory_findings = [finding for finding in default_findings if finding.taxonomy_id == "MP-001"]
        self.assertTrue(memory_findings)
        self.assertTrue(all(finding.decision_hint.value == "block" for finding in memory_findings))

        config_path = Path(self._testMethodName + ".yml")
        config_path.write_text(
            "\n".join(
                [
                    "version: 1",
                    "policy:",
                    "  allow_memory_file_write: true",
                    "language:",
                    "  mode: en",
                ]
            ),
            encoding="utf-8",
        )
        try:
            from io import StringIO
            import contextlib

            buffer = StringIO()
            with contextlib.redirect_stdout(buffer):
                exit_code = main(["scan", str(target), "--format", "json", "--config", str(config_path)])
            self.assertEqual(exit_code, 0)
            payload = json.loads(buffer.getvalue())
            memory_items = [item for item in payload["findings"] if item["taxonomy_id"] == "MP-001"]
            self.assertTrue(memory_items)
            self.assertTrue(all(item["decision_hint"] == "review" for item in memory_items))
        finally:
            if config_path.exists():
                config_path.unlink()

    def test_llm_config_can_be_resolved_from_config_and_cli(self) -> None:
        target = FIXTURES / "basic_skill"
        config_path = Path(self._testMethodName + ".yml")
        config_path.write_text(
            "\n".join(
                [
                    "version: 1",
                    "llm:",
                    "  mode: remote",
                    "  provider: openai_compatible",
                    "  base_url: https://llm.example/v1",
                    "  model: scanner-default",
                    "  api_key_env: SKILL_SAFE_API_KEY",
                    "language:",
                    "  mode: en",
                ]
            ),
            encoding="utf-8",
        )
        try:
            from io import StringIO
            import contextlib

            buffer = StringIO()
            with contextlib.redirect_stdout(buffer):
                exit_code = main(
                    [
                        "scan",
                        str(target),
                        "--format",
                        "json",
                        "--config",
                        str(config_path),
                        "--llm-model",
                        "scanner-override",
                    ]
                )
            self.assertEqual(exit_code, 0)
            payload = json.loads(buffer.getvalue())
            llm_config = payload["artifacts"]["llm_config"]
            self.assertEqual(llm_config["mode"], "remote")
            self.assertEqual(llm_config["provider"], "openai_compatible")
            self.assertEqual(llm_config["base_url"], "https://llm.example/v1")
            self.assertEqual(llm_config["model"], "scanner-override")
            self.assertEqual(llm_config["api_key_env"], "SKILL_SAFE_API_KEY")
        finally:
            if config_path.exists():
                config_path.unlink()

    def test_diff_report_detects_added_taxonomy_and_decision_change(self) -> None:
        old_target = FIXTURES / "diff_case_v1"
        new_target = FIXTURES / "diff_case_v2"
        from io import StringIO
        import contextlib

        buffer = StringIO()
        with contextlib.redirect_stdout(buffer):
            exit_code = main(["diff", str(old_target), str(new_target), "--format", "json", "--lang", "en"])
        self.assertEqual(exit_code, 0)
        payload = json.loads(buffer.getvalue())
        diff = payload["diff"]
        self.assertTrue(diff["decision_changed"])
        self.assertEqual(diff["old_decision"], "allow")
        self.assertEqual(diff["new_decision"], "block")
        self.assertIn("EX-001", diff["added_taxonomy_ids"])
        self.assertIn("PR-003", diff["added_taxonomy_ids"])
        self.assertTrue(diff["permission_drift"]["shell"]["changed"])
        self.assertTrue(diff["permission_drift"]["network"]["changed"])
        self.assertTrue(diff["permission_drift"]["startup_hooks"]["changed"])

    def test_diff_text_output_uses_localized_labels(self) -> None:
        old_target = FIXTURES / "diff_case_v1"
        new_target = FIXTURES / "diff_case_v2"
        from io import StringIO
        import contextlib

        buffer = StringIO()
        with contextlib.redirect_stdout(buffer):
            exit_code = main(["diff", str(old_target), str(new_target), "--lang", "zh"])
        self.assertEqual(exit_code, 0)
        text = buffer.getvalue()
        self.assertIn("旧版本目标", text)
        self.assertIn("新增风险分类", text)
        self.assertIn("攻击链漂移", text)

    def test_diff_report_detects_added_flow_ids(self) -> None:
        old_target = FIXTURES / "diff_flow_v1"
        new_target = FIXTURES / "diff_flow_v2"
        from io import StringIO
        import contextlib

        buffer = StringIO()
        with contextlib.redirect_stdout(buffer):
            exit_code = main(["diff", str(old_target), str(new_target), "--format", "json", "--lang", "en"])
        self.assertEqual(exit_code, 0)
        payload = json.loads(buffer.getvalue())
        flow_drift = payload["diff"]["flow_drift"]
        self.assertTrue(flow_drift["changed"])
        self.assertIn("flow.ch002.untrusted-string-to-context", flow_drift["added_flow_ids"])
        self.assertIn("CH-002", flow_drift["added_flow_taxonomy_ids"])

    def test_explain_scan_report_outputs_human_readable_summary(self) -> None:
        target = FIXTURES / "risky_skill"
        report_path = Path(self._testMethodName + ".json")
        try:
            exit_code = main(["scan", str(target), "--format", "json", "--lang", "en", "--output", str(report_path)])
            self.assertEqual(exit_code, 0)

            from io import StringIO
            import contextlib

            buffer = StringIO()
            with contextlib.redirect_stdout(buffer):
                explain_exit = main(["explain", str(report_path), "--lang", "en"])
            self.assertEqual(explain_exit, 0)
            text = buffer.getvalue()
            self.assertIn("Explanation type: scan", text)
            self.assertIn("Key findings", text)
            self.assertIn("Key flows", text)
            self.assertIn("secret_material(DA-001)", text)
            self.assertIn("Recommended actions", text)
        finally:
            if report_path.exists():
                report_path.unlink()

    def test_explain_diff_report_can_render_json(self) -> None:
        old_target = FIXTURES / "diff_case_v1"
        new_target = FIXTURES / "diff_case_v2"
        report_path = Path(self._testMethodName + ".json")
        try:
            exit_code = main(["diff", str(old_target), str(new_target), "--format", "json", "--lang", "en", "--output", str(report_path)])
            self.assertEqual(exit_code, 0)

            from io import StringIO
            import contextlib

            buffer = StringIO()
            with contextlib.redirect_stdout(buffer):
                explain_exit = main(["explain", str(report_path), "--format", "json", "--lang", "zh"])
            self.assertEqual(explain_exit, 0)
            payload = json.loads(buffer.getvalue())
            self.assertEqual(payload["kind"], "diff")
            self.assertEqual(payload["output_language"], "zh")
            self.assertIn("flows", payload["key_changes"])
            self.assertIn("recommended_actions", payload)
        finally:
            if report_path.exists():
                report_path.unlink()


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
