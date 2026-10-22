#!/usr/bin/env python3
"""Self-serve Pre-Send Document Scanner for FSRs and Customer Engineers.

Scans uploaded customer drafts (.docx, .md, .txt, .html) or pasted text for:
  1. GCP Architecture & Security Fact-Check Contradictions
  2. Risky Unqualified Customer Guarantees ("100% immune", "zero risk", etc.)
  3. AI Slop & Readability Issues (LLM filler phrases and run-on sentences)

Generates a Pre-Send Verification Receipt (#GPS-XXXX), actionable fixes, and
an auto-remediated draft.

Usage:
  python3 scripts/scan_document.py <path/to/draft.docx|draft.md> [--json]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence


RULES: List[Dict[str, Any]] = [
    {
        "id": "GCP-DRZ-REGION",
        "category": "GCP Fact-Check",
        "severity": "HIGH",
        "pattern": re.compile(
            r"([^\n.]*\b(?:us-central1|us-east4|us-west1|single[- ]region)\b[^\n.]*\b(?:data residency|DRZ|CMEK|Gemini Enterprise)\b[^\n.]*\.?|"
            r"[^\n.]*\b(?:data residency|DRZ|CMEK|Gemini Enterprise)\b[^\n.]*\b(?:us-central1|us-east4|us-west1)\b[^\n.]*\.?)",
            re.IGNORECASE,
        ),
        "why_risky": "Gemini Enterprise data residency (DRZ) and CMEK operate at the 'us' or 'eu' multi-region boundary, not single regions like us-central1.",
        "fix_replacement": "Gemini Enterprise enforces data residency (DRZ) and CMEK within the selected 'us' or 'eu' multi-region boundary.",
    },
    {
        "id": "GCP-SDP-UPLOAD-MASK",
        "category": "GCP Fact-Check",
        "severity": "HIGH",
        "pattern": re.compile(
            r"([^\n.]*(?:\[SSN-MASKED\]|masks?\s+SSNs?\s+inline|masks?\s+the\s+SSN\s+inline)[^\n.]*\.?)",
            re.IGNORECASE,
        ),
        "why_risky": "UploadSessionFile (CheckFileContent) rejects the entire uploaded file when it hits a blocked InfoType like an SSN; it does not mask inline and continue.",
        "fix_replacement": "When Cloud SDP detects a configured InfoType such as an SSN during UploadSessionFile, Gemini Enterprise blocks the file upload before model inference.",
    },
    {
        "id": "GCP-SDP-INFOTYPE",
        "category": "GCP Fact-Check",
        "severity": "HIGH",
        "pattern": re.compile(
            r"([^\n.]*\b(?:STATE_DRIVERS_LICENSE_NUMBER|US_INDIVIDUAL_TAX_IDENTIFIER)\b[^\n.]*\.?)",
            re.IGNORECASE,
        ),
        "why_risky": "Neither identifier exists in Google Cloud Sensitive Data Protection (SDP); citing non-existent InfoTypes breaks customer Terraform/API configs.",
        "fix_replacement": "Configure the built-in Cloud SDP detectors US_DRIVERS_LICENSE_NUMBER and US_INDIVIDUAL_TAXPAYER_IDENTIFICATION_NUMBER.",
    },
    {
        "id": "GCP-KMS-ROTATION",
        "category": "GCP Fact-Check",
        "severity": "HIGH",
        "pattern": re.compile(
            r"([^\n.]*\bkey rotation\b[^\n.]*\b(?:revokes|destroys|cryptographically erases|renders unreadable|deletes old)\b[^\n.]*\.?)",
            re.IGNORECASE,
        ),
        "why_risky": "Cloud KMS key rotation creates a new primary version for encryption but keeps older key versions ENABLED for decryption. Only key version destruction is permanent.",
        "fix_replacement": "Cloud KMS key rotation generates a new primary key version for new writes, while Destroying a key version permanently blocks decryption of historical data.",
    },
    {
        "id": "GCP-VPCSC-IMAGE",
        "category": "GCP Fact-Check",
        "severity": "HIGH",
        "pattern": re.compile(
            r"([^\n.]*\b(?:VPC-SC|VPC Service Controls)\b[^\n.]*\b(?:browser|markdown image|<img>|image exfiltration)\b[^\n.]*\.?)",
            re.IGNORECASE,
        ),
        "why_risky": "VPC Service Controls protect Google Cloud API perimeters on the backend; they do not control what an end-user's web browser fetches.",
        "fix_replacement": "The Gemini Enterprise web client (ucs_widget) blocks external Markdown image tags client-side by default (render_images_in_ui_directly=false).",
    },
    {
        "id": "GCP-QUOTA-300RPM",
        "category": "GCP Fact-Check",
        "severity": "MEDIUM",
        "pattern": re.compile(
            r"([^\n.]*\b300\s*(?:API\s*)?(?:requests\s*per\s*minute|RPM)\b[^\n.]*\b(?:Assistant|StreamAssist)\b[^\n.]*\.?)",
            re.IGNORECASE,
        ),
        "why_risky": "300 RPM is the Search quota. StreamAssist (Assistant) quota is 600 RPM per project per region and 1,800 RPM per organization per region.",
        "fix_replacement": "Gemini Enterprise Assistant enforces a default quota of 600 requests per minute per project per region (and 1,800 RPM per organization per region).",
    },
    {
        "id": "RISK-ABSOLUTE-GUARANTEE",
        "category": "Risky Guarantee",
        "severity": "HIGH",
        "pattern": re.compile(
            r"([^\n.]*\b(?:100%\s+(?:immune|guaranteed|secure|hack-proof|out-of-the-box)|zero\s+risk\s+of|completely\s+impossible\s+to\s+exfiltrate|unconditionally\s+guarantees|automatically\s+guarantees\s+100%)\b[^\n.]*\.?)",
            re.IGNORECASE,
        ),
        "why_risky": "Unqualified '100% immune / zero risk / out-of-the-box compliance' claims create legal and compliance liability and get rejected by customer CISO reviewers.",
        "fix_replacement": "Defense-in-depth controls—combining Model Armor (with FAIL_CLOSED enabled), Cloud SDP, and VPC Service Controls—mitigate prompt injection and data exfiltration risks.",
    },
    {
        "id": "SLOP-AI-FILLER",
        "category": "AI Slop & Readability",
        "severity": "MEDIUM",
        "pattern": re.compile(
            r"([^\n.]*\b(?:delve\s+into|testament\s+to|rich\s+tapestry|in\s+today's\s+fast-paced|it\s+is\s+important\s+to\s+note\s+that\s+furthermore|seamless\s+synergy)\b[^\n.]*\.?)",
            re.IGNORECASE,
        ),
        "why_risky": "Reads like unedited AI-generated filler ('AI slop'), reducing credibility with enterprise architects and security reviewers.",
        "fix_replacement": "Below is the verified Google Cloud security architecture and control mapping for your deployment.",
    },
]


def extract_text_from_file(filepath: Path) -> str:
  """Extracts plain text from .docx, .md, .txt, or .html files using only stdlib."""
  suffix = filepath.suffix.lower()
  if suffix == ".docx":
    with zipfile.ZipFile(filepath, "r") as zf:
      if "word/document.xml" not in zf.namelist():
        raise ValueError(f"{filepath} is not a valid Word .docx archive.")
      xml_bytes = zf.read("word/document.xml")
    root = ET.fromstring(xml_bytes)
    paragraphs: List[str] = []
    for p in root.iter("{http://schemas.openxmlformats.org/wordprocessingml/2006/main}p"):
      texts = [
          t.text
          for t in p.iter("{http://schemas.openxmlformats.org/wordprocessingml/2006/main}t")
          if t.text
      ]
      if texts:
        paragraphs.append("".join(texts))
    return "\n\n".join(paragraphs)

  raw = filepath.read_text(encoding="utf-8", errors="replace")
  if suffix in (".html", ".htm"):
    raw = re.sub(r"<script\b[^>]*>.*?</script>", " ", raw, flags=re.DOTALL | re.IGNORECASE)
    raw = re.sub(r"<style\b[^>]*>.*?</style>", " ", raw, flags=re.DOTALL | re.IGNORECASE)
    raw = re.sub(r"<[^>]+>", " ", raw)
  return raw


def scan_text(text: str, source_label: str = "Pasted Draft") -> Dict[str, Any]:
  """Scans customer-facing text for GCP contradictions, risky guarantees, and AI slop."""
  normalized = text.strip()
  findings: List[Dict[str, str]] = []
  remediated = normalized

  for rule in RULES:
    for match in rule["pattern"].finditer(normalized):
      snippet = match.group(0).strip()
      if any(f["original_snippet"] == snippet for f in findings):
        continue
      findings.append({
          "id": rule["id"],
          "category": rule["category"],
          "severity": rule["severity"],
          "original_snippet": snippet,
          "why_risky": rule["why_risky"],
          "suggested_replacement": rule["fix_replacement"],
      })
      remediated = remediated.replace(snippet, rule["fix_replacement"])

  # Also check for >35-word run-on sentences not already flagged
  sentences = [
      s.strip()
      for s in re.split(r"(?<=[.!?])\s+|\n+", normalized)
      if len(s.strip()) > 0
  ]
  for sent in sentences:
    words = re.findall(r"\b[\w'-]+\b", sent)
    if len(words) > 35 and not any(sent in f["original_snippet"] or f["original_snippet"] in sent for f in findings):
      short_fix = " ".join(words[:20]) + "."
      findings.append({
          "id": "SLOP-RUN-ON-SENTENCE",
          "category": "AI Slop & Readability",
          "severity": "LOW",
          "original_snippet": sent,
          "why_risky": f"Sentence is {len(words)} words long (ASD-STE100 technical limit is 25 words max). Long run-on sentences hide technical errors.",
          "suggested_replacement": short_fix,
      })

  high_count = sum(1 for f in findings if f["severity"] == "HIGH")
  med_count = sum(1 for f in findings if f["severity"] == "MEDIUM")
  low_count = sum(1 for f in findings if f["severity"] == "LOW")

  raw_score = 10.0 - (high_count * 2.0) - (med_count * 1.0) - (low_count * 0.4)
  score = round(max(1.0, min(10.0, raw_score)), 1) if normalized else 0.0
  slop_count = sum(1 for f in findings if f["category"] == "AI Slop & Readability")
  if high_count == 0 and med_count == 0 and score >= 8.5:
    verdict = "PASS"
  elif slop_count >= 1 and high_count >= 2:
    verdict = "REJECT_RECREATE"
  else:
    verdict = "HOLD"

  digest = hashlib.sha256((normalized + str(score)).encode("utf-8")).hexdigest()[:6].upper()
  receipt_id = f"GPS-{digest}"

  return {
      "source_label": source_label,
      "verdict": verdict,
      "score": score,
      "receipt_id": receipt_id,
      "counts": {
          "total": len(findings),
          "gcp_fact_check": sum(1 for f in findings if f["category"] == "GCP Fact-Check"),
          "risky_guarantee": sum(1 for f in findings if f["category"] == "Risky Guarantee"),
          "ai_slop": sum(1 for f in findings if f["category"] == "AI Slop & Readability"),
      },
      "findings": findings,
      "remediated_text": remediated,
  }


def main(argv: Optional[Sequence[str]] = None) -> int:
  parser = argparse.ArgumentParser(
      description="Scan a customer draft (.docx, .md, .txt, .html) for AI slop and GCP architecture mistakes."
  )
  parser.add_argument("input_file", type=Path, help="Path to draft file (.docx, .md, .txt, .html)")
  parser.add_argument("--json", action="store_true", help="Print JSON output")
  args = parser.parse_args(argv)

  text = extract_text_from_file(args.input_file)
  result = scan_text(text, source_label=args.input_file.name)

  if args.json:
    print(json.dumps(result, indent=2))
  else:
    print(f"=== GPS Pre-Send Document Scanner ({result['source_label']}) ===")
    print(f"Verdict: {result['verdict']} ({result['score']} / 10.0) · Receipt #{result['receipt_id']}")
    print(f"Issues Found: {result['counts']['total']} "
          f"(GCP Fact-Checks: {result['counts']['gcp_fact_check']}, "
          f"Risky Guarantees: {result['counts']['risky_guarantee']}, "
          f"AI Slop: {result['counts']['ai_slop']})")
    for idx, f in enumerate(result["findings"], 1):
      print(f"\n  [{idx}] [{f['category']}] {f['id']} ({f['severity']})")
      print(f"      Found: {f['original_snippet']}")
      print(f"      Why:   {f['why_risky']}")
      print(f"      Fix:   {f['suggested_replacement']}")
  return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
  sys.exit(main())
