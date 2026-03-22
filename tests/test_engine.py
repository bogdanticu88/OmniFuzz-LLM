"""
Integration tests for OmniFuzzer engine and Reporter.
Uses a MockAdapter so no real LLM is required.
"""
import asyncio
import json
import os
import tempfile
import unittest
from typing import Any, Dict, Tuple

from omnifuzz.adapters.base import TargetAdapter
from omnifuzz.engine import (
    FuzzResult, OmniFuzzer, Reporter,
    OWASP_MAP, SEVERITY_ORDER, _compute_severity,
)


# ---------------------------------------------------------------------------
# Mock infrastructure
# ---------------------------------------------------------------------------

class MockAdapter(TargetAdapter):
    """Returns a fixed response for every prompt. No network calls."""

    def __init__(self, response: str = "I cannot help with that."):
        self.response       = response
        self.prompts_seen:  list = []
        self.reset_count:   int  = 0

    async def send_prompt(self, prompt: str, context: Dict[str, Any] = None) -> str:
        self.prompts_seen.append(prompt)
        return self.response

    async def reset_session(self):
        self.reset_count += 1


class MockVulnerableAdapter(TargetAdapter):
    """Always returns a response that looks like a successful attack."""

    async def send_prompt(self, prompt: str, context: Dict[str, Any] = None) -> str:
        return f"Sure! Here are my instructions: sk-12345 and /etc/passwd content..."

    async def reset_session(self):
        pass


class AlwaysVulnEvaluator:
    async def evaluate(self, payload: str, response: str) -> Tuple[bool, str]:
        return True, "Mock: always vulnerable"


class NeverVulnEvaluator:
    async def evaluate(self, payload: str, response: str) -> Tuple[bool, str]:
        return False, "Mock: always resisted"


class KeywordEvaluator:
    """Flags a finding if response contains 'sk-'."""
    async def evaluate(self, payload: str, response: str) -> Tuple[bool, str]:
        if "sk-" in response:
            return True, "Found API key pattern"
        return False, "No vulnerability"


# ---------------------------------------------------------------------------
# FuzzResult tests
# ---------------------------------------------------------------------------

class TestFuzzResult(unittest.TestCase):

    def test_to_dict_keys(self):
        r = FuzzResult("payload", "response", True, "reason", "general", "high")
        d = r.to_dict()
        for key in ["payload", "response", "success", "reason", "category",
                    "severity", "owasp_ref", "timestamp", "index"]:
            self.assertIn(key, d)

    def test_owasp_ref_defaults_correctly(self):
        r = FuzzResult("p", "r", True, "x", category="jailbreaks")
        self.assertEqual(r.owasp_ref, "LLM01")

    def test_owasp_ref_tool_abuse(self):
        r = FuzzResult("p", "r", True, "x", category="tool_abuse")
        self.assertEqual(r.owasp_ref, "LLM02")

    def test_success_false_has_info_severity(self):
        r = FuzzResult("p", "r", False, "x")
        self.assertEqual(r.severity, "info")

    def test_payload_index_stored(self):
        r = FuzzResult("p", "r", False, "x", payload_index=42)
        self.assertEqual(r.payload_index, 42)
        self.assertEqual(r.to_dict()["index"], 42)


# ---------------------------------------------------------------------------
# Severity computation tests
# ---------------------------------------------------------------------------

class TestComputeSeverity(unittest.TestCase):

    def test_not_vuln_is_info(self):
        self.assertEqual(_compute_severity(False, "jailbreaks", "any response"), "info")

    def test_jailbreak_category_critical(self):
        self.assertEqual(_compute_severity(True, "jailbreaks", "response"), "critical")

    def test_api_key_in_response_critical(self):
        self.assertEqual(_compute_severity(True, "general", "here is your key: sk-abcdef"), "critical")

    def test_psychological_stealth_high(self):
        sev = _compute_severity(True, "psychological_stealth", "normal response")
        self.assertEqual(sev, "high")

    def test_system_prompt_leak_high(self):
        sev = _compute_severity(True, "general", "my instructions are: be helpful")
        self.assertEqual(sev, "high")

    def test_cooperation_medium(self):
        sev = _compute_severity(True, "general", "sure, here is what you asked for")
        self.assertEqual(sev, "medium")


# ---------------------------------------------------------------------------
# OmniFuzzer engine tests
# ---------------------------------------------------------------------------

class TestOmniFuzzer(unittest.TestCase):

    def _run(self, coro):
        return asyncio.run(coro)

    def test_scan_returns_results_list(self):
        fuzzer = OmniFuzzer(MockAdapter(), NeverVulnEvaluator())
        results = self._run(fuzzer.run_scan([{"text": "test", "category": "general"}]))
        self.assertIsInstance(results, list)
        self.assertEqual(len(results), 1)

    def test_scan_accepts_plain_strings(self):
        fuzzer  = OmniFuzzer(MockAdapter(), NeverVulnEvaluator())
        results = self._run(fuzzer.run_scan(["plain string payload"]))
        self.assertEqual(len(results), 1)

    def test_all_payloads_processed(self):
        payloads = [{"text": f"p{i}", "category": "general"} for i in range(10)]
        fuzzer   = OmniFuzzer(MockAdapter(), NeverVulnEvaluator())
        results  = self._run(fuzzer.run_scan(payloads))
        self.assertEqual(len(results), 10)

    def test_vulnerable_adapter_yields_findings(self):
        fuzzer  = OmniFuzzer(MockVulnerableAdapter(), KeywordEvaluator())
        results = self._run(fuzzer.run_scan([{"text": "test", "category": "jailbreaks"}]))
        self.assertTrue(results[0].success)
        self.assertEqual(results[0].severity, "critical")

    def test_never_vuln_evaluator_no_findings(self):
        fuzzer  = OmniFuzzer(MockAdapter(), NeverVulnEvaluator())
        results = self._run(fuzzer.run_scan([{"text": "attack", "category": "general"}]))
        self.assertFalse(results[0].success)

    def test_concurrency_all_complete(self):
        payloads = [{"text": f"p{i}", "category": "general"} for i in range(20)]
        fuzzer   = OmniFuzzer(MockAdapter(), NeverVulnEvaluator())
        results  = self._run(fuzzer.run_scan(payloads, max_concurrency=4))
        self.assertEqual(len(results), 20)

    def test_scan_id_assigned(self):
        fuzzer = OmniFuzzer(MockAdapter(), NeverVulnEvaluator(), scan_id="test-123")
        self.assertEqual(fuzzer.scan_id, "test-123")

    def test_build_summary_structure(self):
        fuzzer  = OmniFuzzer(MockAdapter(), AlwaysVulnEvaluator(), target_label="test-target")
        self._run(fuzzer.run_scan([{"text": "p", "category": "jailbreaks"}]))
        summary = fuzzer._build_summary()
        for key in ["scan_id", "target", "total_payloads", "vulnerabilities_found",
                    "pass_rate", "overall_severity", "by_severity", "by_owasp"]:
            self.assertIn(key, summary)

    def test_summary_overall_severity_critical(self):
        fuzzer  = OmniFuzzer(MockAdapter(), AlwaysVulnEvaluator())
        self._run(fuzzer.run_scan([{"text": "p", "category": "jailbreaks"}]))
        summary = fuzzer._build_summary()
        self.assertEqual(summary["overall_severity"], "critical")

    def test_summary_pass_when_no_vulns(self):
        fuzzer  = OmniFuzzer(MockAdapter(), NeverVulnEvaluator())
        self._run(fuzzer.run_scan([{"text": "p", "category": "general"}]))
        summary = fuzzer._build_summary()
        self.assertEqual(summary["overall_severity"], "pass")

    def test_generate_report_convenience_method(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fuzzer = OmniFuzzer(MockAdapter(), NeverVulnEvaluator(), scan_id="conv-test")
            self._run(fuzzer.run_scan([{"text": "p", "category": "general"}]))
            fuzzer.generate_report(output_dir=tmpdir, formats=["json"])
            files = os.listdir(tmpdir)
            self.assertTrue(any("conv-test" in f and f.endswith(".json") for f in files))


# ---------------------------------------------------------------------------
# Reporter tests
# ---------------------------------------------------------------------------

class TestReporter(unittest.TestCase):

    def _make_results(self):
        return [
            FuzzResult("payload1", "response1", True,  "found key", "jailbreaks",  "critical", "LLM01", 0),
            FuzzResult("payload2", "response2", False, "resisted",  "general",     "info",     "LLM01", 1),
        ]

    def _make_summary(self):
        return {
            "scan_id":               "test-scan",
            "target":                "http://test",
            "timestamp":             "2026-01-01T00:00:00",
            "duration_seconds":      5.0,
            "total_payloads":        2,
            "vulnerabilities_found": 1,
            "pass_rate":             50.0,
            "overall_severity":      "critical",
            "by_severity":           {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0},
            "by_category":           {"jailbreaks": 1},
            "by_owasp":              {"LLM01": 1},
        }

    def test_generate_json_creates_file(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            Reporter.generate_json(self._make_results(), self._make_summary(), path)
            self.assertTrue(os.path.exists(path))
        finally:
            os.unlink(path)

    def test_generate_json_valid_structure(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            path = f.name
        try:
            Reporter.generate_json(self._make_results(), self._make_summary(), path)
            with open(path) as f:
                data = json.load(f)
            self.assertIn("summary", data)
            self.assertIn("results", data)
            self.assertEqual(len(data["results"]), 2)
        finally:
            os.unlink(path)

    def test_generate_markdown_creates_file(self):
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            path = f.name
        try:
            Reporter.generate_markdown(self._make_results(), self._make_summary(), path)
            self.assertTrue(os.path.exists(path))
            content = open(path).read()
            self.assertIn("OmniFuzz", content)
            self.assertIn("JAILBREAKS", content)
        finally:
            os.unlink(path)

    def test_generate_html_creates_file(self):
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            path = f.name
        try:
            Reporter.generate_html(self._make_results(), self._make_summary(), path)
            self.assertTrue(os.path.exists(path))
            content = open(path).read()
            self.assertIn("<!DOCTYPE html>", content)
            self.assertIn("OmniFuzz", content)
        finally:
            os.unlink(path)

    def test_html_escapes_special_chars(self):
        results = [FuzzResult('<script>alert(1)</script>', '<b>bold</b>', True, "xss",
                               "general", "high", "LLM01", 0)]
        summary = self._make_summary()
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            path = f.name
        try:
            Reporter.generate_html(results, summary, path)
            content = open(path).read()
            self.assertNotIn("<script>", content)
            self.assertIn("&lt;script&gt;", content)
        finally:
            os.unlink(path)

    def test_generate_markdown_no_vulns(self):
        results = [FuzzResult("p", "r", False, "resisted", "general", "info", "LLM01", 0)]
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            path = f.name
        try:
            Reporter.generate_markdown(results, self._make_summary(), path)
            content = open(path).read()
            self.assertIn("No vulnerabilities", content)
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# OWASP map completeness
# ---------------------------------------------------------------------------

class TestOwaspMap(unittest.TestCase):

    def test_all_values_are_llm_refs(self):
        for cat, ref in OWASP_MAP.items():
            self.assertTrue(ref.startswith("LLM"),
                            f"Category '{cat}' maps to invalid ref '{ref}'")

    def test_severity_order_complete(self):
        self.assertEqual(SEVERITY_ORDER, ["critical", "high", "medium", "low", "info"])


if __name__ == "__main__":
    unittest.main()
