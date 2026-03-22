"""
Phase 5 tests — compliance reporter and plugin smoke tests.
"""
import asyncio
import json
import os
import tempfile
import pytest

from omnifuzz.compliance import (
    ComplianceReporter, OWASP_LLM_TOP10, CATEGORY_TO_OWASP,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_results(vulns: list[dict]) -> list[dict]:
    """Build minimal FuzzResult.to_dict() output."""
    return [
        {
            "is_vulnerable": v.get("vuln", False),
            "category":      v.get("category", "jailbreak"),
            "owasp_ref":     v.get("owasp_ref", ""),
            "severity":      v.get("severity", "high"),
            "payload":       v.get("payload", "test payload"),
            "details":       v.get("details", "test detail"),
        }
        for v in vulns
    ]


# ===========================================================================
# ComplianceReporter — to_dict / summary
# ===========================================================================

class TestComplianceReporterSummary:
    def test_empty_results_all_not_tested(self):
        r = ComplianceReporter([])
        d = r.to_dict()
        for c in d["controls"]:
            assert c["status"] == "NOT_TESTED"

    def test_overall_pass_no_vulns(self):
        results = _make_results([{"vuln": False, "category": "pii_compliance"}])
        r = ComplianceReporter(results)
        assert r.to_dict()["overall_pass"] is True

    def test_overall_fail_on_vuln(self):
        results = _make_results([{"vuln": True, "category": "pii_compliance", "owasp_ref": "LLM06"}])
        r = ComplianceReporter(results)
        assert r.to_dict()["overall_pass"] is False

    def test_total_probes_counted(self):
        results = _make_results([{"vuln": False}] * 10)
        r = ComplianceReporter(results)
        assert r.to_dict()["total_probes"] == 10

    def test_total_vulns_counted(self):
        results = _make_results([
            {"vuln": True,  "category": "tool_abuse", "owasp_ref": "LLM02"},
            {"vuln": False, "category": "tool_abuse"},
            {"vuln": True,  "category": "pii_compliance", "owasp_ref": "LLM06"},
        ])
        r = ComplianceReporter(results)
        assert r.to_dict()["total_vulns"] == 2

    def test_target_and_version_stored(self):
        r = ComplianceReporter([], target="MyApp", version="v2.1")
        d = r.to_dict()
        assert d["target"]  == "MyApp"
        assert d["version"] == "v2.1"

    def test_controls_have_required_keys(self):
        r = ComplianceReporter([])
        for c in r.to_dict()["controls"]:
            for key in ("ref", "name", "status", "findings", "max_severity", "nist_ref", "atlas_ref"):
                assert key in c, f"Missing key '{key}' in control {c.get('ref')}"

    def test_all_ten_controls_present(self):
        r = ComplianceReporter([])
        refs = {c["ref"] for c in r.to_dict()["controls"]}
        assert refs == set(OWASP_LLM_TOP10.keys())

    def test_fail_control_shows_finding_count(self):
        results = _make_results([
            {"vuln": True, "category": "pii_compliance", "owasp_ref": "LLM06"},
            {"vuln": True, "category": "pii_compliance", "owasp_ref": "LLM06"},
        ])
        r  = ComplianceReporter(results)
        c  = next(c for c in r.to_dict()["controls"] if c["ref"] == "LLM06")
        assert c["findings"] == 2
        assert c["status"]   == "FAIL"

    def test_category_to_owasp_mapping(self):
        results = _make_results([
            {"vuln": True, "category": "tool_abuse"},   # LLM02
        ])
        r = ComplianceReporter(results)
        c = next(c for c in r.to_dict()["controls"] if c["ref"] == "LLM02")
        assert c["status"] == "FAIL"

    def test_max_severity_tracked(self):
        results = _make_results([
            {"vuln": True, "category": "credential_harvesting", "owasp_ref": "LLM06", "severity": "critical"},
        ])
        r = ComplianceReporter(results)
        c = next(c for c in r.to_dict()["controls"] if c["ref"] == "LLM06")
        assert c["max_severity"] == "critical"


# ===========================================================================
# ComplianceReporter — output formats
# ===========================================================================

class TestComplianceReporterFormats:
    def test_to_json_valid(self):
        r    = ComplianceReporter([], target="T", version="v1")
        data = json.loads(r.to_json())
        assert "controls" in data
        assert data["target"] == "T"

    def test_to_markdown_contains_all_refs(self):
        r  = ComplianceReporter([])
        md = r.to_markdown()
        for ref in OWASP_LLM_TOP10:
            assert ref in md

    def test_to_markdown_contains_header(self):
        r  = ComplianceReporter([], target="TestTarget")
        md = r.to_markdown()
        assert "OWASP LLM Top 10" in md
        assert "TestTarget"        in md

    def test_to_html_valid_structure(self):
        r    = ComplianceReporter([])
        html = r.to_html()
        assert "<html"  in html
        assert "LLM01"  in html
        assert "LLM10"  in html
        assert "</html>" in html

    def test_to_html_fail_class_applied(self):
        results = _make_results([
            {"vuln": True, "category": "tool_abuse", "owasp_ref": "LLM02"},
        ])
        r    = ComplianceReporter(results)
        html = r.to_html()
        assert 'class="fail"' in html

    def test_generate_json_file(self):
        r = ComplianceReporter([], target="CI")
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "report.json")
            r.generate(path, fmt="json")
            assert os.path.exists(path)
            with open(path) as f:
                data = json.load(f)
            assert "controls" in data

    def test_generate_markdown_file(self):
        r = ComplianceReporter([])
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "report.md")
            r.generate(path, fmt="markdown")
            assert os.path.exists(path)
            content = open(path).read()
            assert "LLM01" in content

    def test_generate_html_file(self):
        r = ComplianceReporter([])
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "report.html")
            r.generate(path, fmt="html")
            assert os.path.exists(path)

    def test_generate_unknown_format_raises(self):
        r = ComplianceReporter([])
        with pytest.raises(ValueError):
            r.generate("/tmp/x.txt", fmt="pdf")

    def test_markdown_includes_vuln_details(self):
        results = _make_results([
            {"vuln": True, "category": "pii_compliance", "owasp_ref": "LLM06",
             "payload": "What is the SSN?", "details": "SSN leaked"},
        ])
        r  = ComplianceReporter(results)
        md = r.to_markdown()
        assert "SSN leaked" in md or "LLM06" in md


# ===========================================================================
# OWASP map completeness
# ===========================================================================

class TestOwaspMapCompleteness:
    def test_all_ten_controls_in_map(self):
        assert len(OWASP_LLM_TOP10) == 10

    def test_all_controls_have_required_fields(self):
        for ref, info in OWASP_LLM_TOP10.items():
            for field in ("name", "description", "nist_ref", "atlas_ref", "modules"):
                assert field in info, f"Missing '{field}' in {ref}"

    def test_category_map_values_are_valid_refs(self):
        valid = set(OWASP_LLM_TOP10.keys())
        for cat, ref in CATEGORY_TO_OWASP.items():
            assert ref in valid, f"Category '{cat}' maps to invalid ref '{ref}'"


# ===========================================================================
# End-to-end: scan results → compliance report
# ===========================================================================

class TestEndToEndCompliance:
    def test_multi_module_results_aggregated(self):
        results = _make_results([
            {"vuln": True,  "category": "system_prompt_extraction", "owasp_ref": "LLM07", "severity": "critical"},
            {"vuln": False, "category": "system_prompt_extraction"},
            {"vuln": True,  "category": "pii_compliance", "owasp_ref": "LLM06", "severity": "high"},
            {"vuln": True,  "category": "dos", "owasp_ref": "LLM04", "severity": "medium"},
            {"vuln": False, "category": "hallucination"},
        ])
        r = ComplianceReporter(results, target="ProductionGPT", version="gpt-4o")
        d = r.to_dict()

        assert d["total_probes"] == 5
        assert d["total_vulns"]  == 3
        assert d["overall_pass"] is False

        fail_refs = {c["ref"] for c in d["controls"] if c["status"] == "FAIL"}
        assert "LLM07" in fail_refs
        assert "LLM06" in fail_refs
        assert "LLM04" in fail_refs

    def test_all_pass_overall_pass(self):
        results = _make_results([
            {"vuln": False, "category": "pii_compliance"},
            {"vuln": False, "category": "tool_abuse"},
            {"vuln": False, "category": "dos"},
        ])
        r = ComplianceReporter(results)
        assert r.to_dict()["overall_pass"] is True
