#!/usr/bin/env python3
"""Automated unit test suite for the Output AI Verification Loop & Karpathy Review Council."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
  sys.path.insert(0, str(SCRIPTS_DIR))

import check_ste100  # noqa: E402
import council_runner  # noqa: E402
import eval_council  # noqa: E402
import render_canvas  # noqa: E402
import scan_document  # noqa: E402


class TestCheckSTE100(unittest.TestCase):
  """Tests for scripts/check_ste100.py."""

  def test_recognizes_all_tagged_formats(self) -> None:
    sample = "\n".join([
        "- **D** [17] Model Armor screens the user prompt, uploaded session files up to 4 MB, and the final response.",
        "- **[D] (17w)** SDP screens retrieved connector content and uploaded files up to 50 MB PDF or 30 MB Office.",
        "- [P] (7w) Set `failure_mode=FAIL_CLOSED` on each Model Armor template.",
        "1. **P** [7] Configure a `userPromptTemplate` to activate snippet screening.",
    ])
    res = check_ste100.audit_text(
        sample,
        filepath_label="formats.md",
        check_passive=True,
        check_word_tags=True,
    )
    self.assertTrue(res.passed, f"Unexpected violations: {res.violations}")
    self.assertEqual(res.tagged_sentences_checked, 4)

  def test_fails_on_zero_sentences_by_default(self) -> None:
    sample = "# Heading Only\n\nSome untagged prose without STE100 tags.\n"
    res = check_ste100.audit_text(sample, filepath_label="untagged.md")
    self.assertFalse(res.passed)
    self.assertEqual(res.tagged_sentences_checked, 0)
    self.assertEqual(res.violations[0].category, "EMPTY_AUDIT")

    # Passes when allow_empty=True
    res_allowed = check_ste100.audit_text(
        sample, filepath_label="untagged.md", allow_empty=True
    )
    self.assertTrue(res_allowed.passed)

  def test_enforces_procedural_and_descriptive_word_caps(self) -> None:
    sample = "\n".join([
        "- **P** [22] Configure the primary security template in the console and verify that every single regional endpoint across all customer organizations is active today.",
        "- **D** [27] The conversational assistant processes the incoming request through multiple sequential and parallel validation layers before forwarding the resulting payload across the internal network boundary to model serving.",
    ])
    res = check_ste100.audit_text(sample, filepath_label="caps.md")
    self.assertFalse(res.passed)
    categories = [v.category for v in res.violations]
    self.assertEqual(categories, ["WORD_CAP", "WORD_CAP"])

  def test_detects_banned_filler_and_passive_voice(self) -> None:
    sample = "\n".join([
        "- **D** [10] Furthermore, the payload is evaluated by the security gateway.",
    ])
    res = check_ste100.audit_text(
        sample, filepath_label="filler_passive.md", check_passive=True
    )
    self.assertFalse(res.passed)
    cats = {v.category for v in res.violations}
    self.assertIn("FILLER", cats)
    self.assertIn("PASSIVE_VOICE", cats)

  def test_detects_word_tag_mismatch(self) -> None:
    sample = "- **[P] (15w)** Set `failure_mode=FAIL_CLOSED` on each Model Armor template.\n"
    res = check_ste100.audit_text(
        sample, filepath_label="mismatch.md", check_word_tags=True
    )
    self.assertFalse(res.passed)
    self.assertEqual(res.violations[0].category, "WORD_TAG_MISMATCH")

  def test_existing_repo_docs_pass_ste100_audit(self) -> None:
    benchmark_md = PROJECT_ROOT / "examples" / "dual_model_benchmark_report.md"
    quick_ref_md = (
        PROJECT_ROOT
        / "skill"
        / "output-engineer"
        / "references"
        / "asd_ste100_quick_reference.md"
    )
    for path in (benchmark_md, quick_ref_md):
      res = check_ste100.audit_text(
          path.read_text(encoding="utf-8"),
          filepath_label=path.name,
          check_passive=True,
          check_word_tags=True,
      )
      self.assertTrue(res.passed, f"{path.name} failed STE100: {res.violations}")
      self.assertGreater(res.tagged_sentences_checked, 0)


class TestKarpathyCouncilAndEvalFramework(unittest.TestCase):
  """Tests for council_runner.py, render_canvas.py, and eval_council.py."""

  def test_stage2_blind_peer_review_borda_ranking(self) -> None:
    review = council_runner.load_preset_council("security-review")
    s2 = review["council"]["stage2_peer_review"]
    self.assertEqual(
        s2["anonymization_map"],
        {
            "Response A": "seat-gemini-pro",
            "Response B": "seat-claude-opus",
            "Response C": "seat-gemini-flash",
        },
    )
    leaderboard = s2["leaderboard"]
    self.assertEqual(leaderboard[0]["seat_id"], "seat-claude-opus")
    self.assertEqual(leaderboard[0]["rank"], 1)
    self.assertEqual(leaderboard[0]["borda_points"], 9)

  def test_render_canvas_compiles_valid_6_tab_html(self) -> None:
    review = council_runner.load_preset_council("security-review")
    with tempfile.TemporaryDirectory() as tmpdir:
      out_html = Path(tmpdir) / "test_canvas.html"
      render_canvas.compile_canvas(review, out_html)
      html_text = out_html.read_text(encoding="utf-8")

      self.assertIn("Gemini Enterprise Security Architecture", html_text)
      self.assertIn("EMAIL-13-UPLOAD", html_text)
      for panel_id in (
          "panel-claims",
          "panel-models",
          "panel-ste100",
          "panel-diagrams",
          "panel-video",
          "panel-gatekeeper",
      ):
        self.assertIn(panel_id, html_text)

  def test_eval_council_against_golden_dataset(self) -> None:
    council_data = council_runner.load_preset_council("security-review")
    golden_path = PROJECT_ROOT / "examples" / "golden_security_claims_eval.json"
    golden_data = json.loads(golden_path.read_text(encoding="utf-8"))
    eval_res = eval_council.evaluate_council_run(council_data, golden_data)

    self.assertTrue(eval_res["passed"])
    self.assertEqual(eval_res["stage3_karpathy_council"]["f1_pct"], 100.0)
    self.assertEqual(
        eval_res["stage3_karpathy_council"]["false_positive_rejection_rate_pct"],
        100.0,
    )
    self.assertEqual(
        eval_res["stage3_karpathy_council"]["score_calibration_mae"], 0.0
    )
    self.assertEqual(
        eval_res["stage1_single_model_baselines"]["seat-gemini-pro"]["recall_pct"],
        50.0,
    )


class TestSelfServeDocumentScanner(unittest.TestCase):
  """Tests for scripts/scan_document.py."""

  def test_detects_ai_slop_gcp_contradictions_and_risky_guarantees(self) -> None:
    samples_dir = PROJECT_ROOT / "examples" / "presend_gate_samples"
    v1_path = samples_dir / "workers_comp_security_response_v1.md"
    slop_path = samples_dir / "fsr_unverified_ai_slop_draft.md"
    v2_path = samples_dir / "workers_comp_security_response_v2_reworked.md"

    # 1. Fixable v1 draft -> HOLD
    res_v1 = scan_document.scan_text(
        scan_document.extract_text_from_file(v1_path), source_label=v1_path.name
    )
    self.assertEqual(res_v1["verdict"], "HOLD")
    self.assertEqual(res_v1["counts"]["gcp_fact_check"], 2)
    self.assertEqual(res_v1["counts"]["risky_guarantee"], 1)

    # 2. Unsalvageable AI slop draft -> REJECT_RECREATE
    res_slop = scan_document.scan_text(
        scan_document.extract_text_from_file(slop_path), source_label=slop_path.name
    )
    self.assertEqual(res_slop["verdict"], "REJECT_RECREATE")
    self.assertGreaterEqual(res_slop["counts"]["ai_slop"], 1)
    self.assertGreaterEqual(res_slop["counts"]["gcp_fact_check"], 1)

    # 3. Reworked v2 artifact -> PASS
    res_v2 = scan_document.scan_text(
        scan_document.extract_text_from_file(v2_path), source_label=v2_path.name
    )
    self.assertEqual(res_v2["verdict"], "PASS")
    self.assertEqual(res_v2["counts"]["total"], 0)

  def test_extracts_docx_paragraphs_without_external_deps(self) -> None:
    import zipfile
    with tempfile.TemporaryDirectory() as tmpdir:
      docx_path = Path(tmpdir) / "sample.docx"
      doc_xml = (
          '<?xml version="1.0" encoding="UTF-8"?>'
          '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
          "<w:body>"
          "<w:p><w:r><w:t>Gemini Enterprise enforces data residency within the us multi-region.</w:t></w:r></w:p>"
          "</w:body></w:document>"
      )
      with zipfile.ZipFile(docx_path, "w") as zf:
        zf.writestr("word/document.xml", doc_xml)

      extracted = scan_document.extract_text_from_file(docx_path)
      self.assertIn("us multi-region", extracted)
      res = scan_document.scan_text(extracted, source_label="sample.docx")
      self.assertEqual(res["verdict"], "PASS")


if __name__ == "__main__":
  unittest.main()
