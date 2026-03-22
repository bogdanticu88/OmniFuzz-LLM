"""
Tests for Phase 2: config loader, payload manager, and adapter construction.
No real network calls — all mocked.
"""
import json
import os
import tempfile
import unittest

from omnifuzz.config import load_config, config_to_args, DEFAULTS, generate_example_config
from omnifuzz.payload_manager import (
    validate_payload, load_library, filter_payloads, payloads_to_scan_format,
    add_payload, validate_library, PayloadValidationError,
)


# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------

class TestConfigLoader(unittest.TestCase):

    def _write_yaml(self, content: str) -> str:
        f = tempfile.NamedTemporaryFile(suffix=".yaml", delete=False, mode="w", encoding="utf-8")
        f.write(content)
        f.close()
        return f.name

    def _write_toml(self, content: str) -> str:
        f = tempfile.NamedTemporaryFile(suffix=".toml", delete=False, mode="w", encoding="utf-8")
        f.write(content)
        f.close()
        return f.name

    def tearDown(self):
        # cleanup any stray temp files — they're OS-temp so auto-cleaned anyway
        pass

    def test_raises_on_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            load_config("/nonexistent/path/omnifuzz.yaml")

    def test_raises_on_unsupported_extension(self):
        f = tempfile.NamedTemporaryFile(suffix=".ini", delete=False)
        f.close()
        try:
            with self.assertRaises(ValueError):
                load_config(f.name)
        finally:
            os.unlink(f.name)

    def test_yaml_loads_target(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML not installed")
        path = self._write_yaml("target: http://test.local\nmodel: gpt4\n")
        try:
            config = load_config(path)
            self.assertEqual(config["target"], "http://test.local")
            self.assertEqual(config["model"],  "gpt4")
        finally:
            os.unlink(path)

    def test_yaml_merges_defaults(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML not installed")
        path = self._write_yaml("target: http://x\n")
        try:
            config = load_config(path)
            # Should have all default keys
            self.assertIn("scan",    config)
            self.assertIn("output",  config)
            self.assertIn("logging", config)
        finally:
            os.unlink(path)

    def test_yaml_override_nested(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML not installed")
        path = self._write_yaml("scan:\n  concurrency: 10\n")
        try:
            config = load_config(path)
            self.assertEqual(config["scan"]["concurrency"], 10)
            # Other nested defaults preserved
            self.assertIn("checkpoint", config["scan"])
        finally:
            os.unlink(path)

    def test_config_to_args_structure(self):
        args = config_to_args(DEFAULTS)
        for attr in ("target", "model", "concurrency", "checkpoint",
                     "output_dir", "output_format", "verbose", "quiet"):
            self.assertTrue(hasattr(args, attr), f"Missing attr: {attr}")

    def test_config_to_args_heuristic_flag(self):
        config = {**DEFAULTS, "evaluator": "heuristic"}
        args = config_to_args(config)
        self.assertTrue(args.heuristic)

    def test_config_to_args_ollama_no_heuristic(self):
        config = {**DEFAULTS, "evaluator": "ollama"}
        args = config_to_args(config)
        self.assertFalse(args.heuristic)

    def test_generate_example_yaml(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML not installed")
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
            path = f.name
        try:
            generate_example_config(path, fmt="yaml")
            self.assertTrue(os.path.exists(path))
            content = open(path).read()
            self.assertIn("target:", content)
            self.assertIn("concurrency:", content)
        finally:
            os.unlink(path)

    def test_generate_example_toml(self):
        with tempfile.NamedTemporaryFile(suffix=".toml", delete=False) as f:
            path = f.name
        try:
            generate_example_config(path, fmt="toml")
            content = open(path).read()
            self.assertIn('target = ', content)
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Payload validation
# ---------------------------------------------------------------------------

class TestPayloadValidation(unittest.TestCase):

    def _valid(self) -> dict:
        return {
            "id":       "TST-001",
            "name":     "Test payload",
            "payload":  "This is a test adversarial payload text",
            "category": "test",
        }

    def test_valid_entry_no_errors(self):
        errors = validate_payload(self._valid())
        self.assertEqual(errors, [])

    def test_missing_id_error(self):
        e = self._valid()
        del e["id"]
        self.assertTrue(len(validate_payload(e)) > 0)

    def test_missing_name_error(self):
        e = self._valid()
        del e["name"]
        self.assertTrue(len(validate_payload(e)) > 0)

    def test_missing_payload_error(self):
        e = self._valid()
        del e["payload"]
        self.assertTrue(len(validate_payload(e)) > 0)

    def test_missing_category_error(self):
        e = self._valid()
        del e["category"]
        self.assertTrue(len(validate_payload(e)) > 0)

    def test_invalid_severity_error(self):
        e = {**self._valid(), "severity": "super_critical"}
        self.assertTrue(len(validate_payload(e)) > 0)

    def test_valid_severity_no_error(self):
        for sev in ("critical", "high", "medium", "low", "info"):
            e = {**self._valid(), "severity": sev}
            self.assertEqual(validate_payload(e), [], f"Failed for severity: {sev}")

    def test_invalid_owasp_ref_error(self):
        e = {**self._valid(), "owasp_ref": "LLM99"}
        self.assertTrue(len(validate_payload(e)) > 0)

    def test_valid_owasp_refs(self):
        for i in range(1, 11):
            e = {**self._valid(), "owasp_ref": f"LLM{i:02d}"}
            self.assertEqual(validate_payload(e), [])

    def test_models_not_list_error(self):
        e = {**self._valid(), "models": "*"}  # string, not list
        self.assertTrue(len(validate_payload(e)) > 0)

    def test_tags_not_list_error(self):
        e = {**self._valid(), "tags": "jailbreak"}  # string, not list
        self.assertTrue(len(validate_payload(e)) > 0)

    def test_short_payload_error(self):
        e = {**self._valid(), "payload": "short"}
        self.assertTrue(len(validate_payload(e)) > 0)

    def test_strict_mode_flags_missing_recommended(self):
        e = self._valid()  # no severity, owasp_ref etc.
        errors = validate_payload(e, strict=True)
        self.assertTrue(any("[strict]" in err for err in errors))


# ---------------------------------------------------------------------------
# Library loading & filtering
# ---------------------------------------------------------------------------

class TestPayloadLibrary(unittest.TestCase):

    def _make_library_file(self, data: dict) -> str:
        f = tempfile.NamedTemporaryFile(
            suffix=".json", delete=False, mode="w", encoding="utf-8"
        )
        json.dump(data, f)
        f.close()
        return f.name

    def test_load_default_library(self):
        lib = load_library()
        self.assertIsInstance(lib, dict)
        self.assertTrue(len(lib) > 0)

    def test_load_custom_library(self):
        path = self._make_library_file({
            "test_cat": [
                {"id": "T-001", "name": "t", "payload": "test payload abc", "category": "test_cat"}
            ]
        })
        try:
            lib = load_library([path])
            self.assertIn("test_cat", lib)
            self.assertEqual(len(lib["test_cat"]), 1)
        finally:
            os.unlink(path)

    def test_load_skips_missing_file(self):
        lib = load_library(["/nonexistent/path.json"])
        self.assertEqual(lib, {})

    def test_load_merges_multiple_files(self):
        p1 = self._make_library_file({"cat_a": [{"id": "A-001", "name": "a", "payload": "payload a", "category": "cat_a"}]})
        p2 = self._make_library_file({"cat_b": [{"id": "B-001", "name": "b", "payload": "payload b", "category": "cat_b"}]})
        try:
            lib = load_library([p1, p2])
            self.assertIn("cat_a", lib)
            self.assertIn("cat_b", lib)
        finally:
            os.unlink(p1)
            os.unlink(p2)

    def test_filter_by_category(self):
        lib = {"cat1": [{"id": "C1", "payload": "p1"}], "cat2": [{"id": "C2", "payload": "p2"}]}
        results = filter_payloads(lib, categories=["cat1"])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["id"], "C1")

    def test_filter_by_severity(self):
        lib = {
            "general": [
                {"id": "H1", "payload": "high payload", "severity": "high"},
                {"id": "L1", "payload": "low payload",  "severity": "low"},
            ]
        }
        results = filter_payloads(lib, severity="high")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["id"], "H1")

    def test_filter_by_owasp_ref(self):
        lib = {
            "general": [
                {"id": "O1", "payload": "p1", "owasp_ref": "LLM01"},
                {"id": "O2", "payload": "p2", "owasp_ref": "LLM07"},
            ]
        }
        results = filter_payloads(lib, owasp_ref="LLM07")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["id"], "O2")

    def test_filter_model_wildcard_included(self):
        lib = {"general": [{"id": "W1", "payload": "p", "models": ["*"]}]}
        results = filter_payloads(lib, model_family="gpt")
        self.assertEqual(len(results), 1)

    def test_filter_model_family_exclusion(self):
        lib = {"general": [{"id": "M1", "payload": "p", "models": ["claude"]}]}
        results = filter_payloads(lib, model_family="gpt")
        self.assertEqual(len(results), 0)

    def test_payloads_to_scan_format(self):
        entries = [
            {"id": "X1", "payload": "text1", "category": "cat1"},
            {"id": "X2", "payload": "text2", "category": "cat2"},
        ]
        scan = payloads_to_scan_format(entries)
        self.assertEqual(len(scan), 2)
        self.assertEqual(scan[0]["text"],     "text1")
        self.assertEqual(scan[0]["category"], "cat1")
        for item in scan:
            self.assertIn("text",     item)
            self.assertIn("category", item)


# ---------------------------------------------------------------------------
# Add payload / validate library
# ---------------------------------------------------------------------------

class TestAddPayload(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(
            suffix=".json", delete=False, mode="w", encoding="utf-8"
        )
        json.dump({"existing_cat": []}, self.tmp)
        self.tmp.close()
        self.lib_path = self.tmp.name

    def tearDown(self):
        os.unlink(self.lib_path)

    def test_add_creates_entry(self):
        entry = add_payload(
            "This is a long enough adversarial payload text",
            "test_category",
            library_path=self.lib_path,
        )
        self.assertIn("id",      entry)
        self.assertIn("payload", entry)
        self.assertEqual(entry["category"], "test_category")

    def test_add_auto_generates_id(self):
        entry = add_payload(
            "Adversarial payload for testing purposes here",
            "my_cat",
            library_path=self.lib_path,
        )
        self.assertTrue(entry["id"].startswith("MY_CA") or len(entry["id"]) > 0)

    def test_add_persists_to_file(self):
        add_payload(
            "This payload should be saved to the library file",
            "saved_cat",
            library_path=self.lib_path,
        )
        with open(self.lib_path) as f:
            data = json.load(f)
        self.assertIn("saved_cat", data)

    def test_add_invalid_raises(self):
        with self.assertRaises(PayloadValidationError):
            add_payload("short", "cat", library_path=self.lib_path)

    def test_validate_library_clean(self):
        add_payload(
            "A valid adversarial payload text for library",
            "valid_cat",
            severity="high",
            owasp_ref="LLM01",
            library_path=self.lib_path,
        )
        report = validate_library(library_path=self.lib_path)
        self.assertEqual(report["invalid"], 0)
        self.assertGreater(report["valid"], 0)


if __name__ == "__main__":
    unittest.main()
