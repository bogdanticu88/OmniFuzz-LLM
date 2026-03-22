"""
Tests for CheckpointManager: save, load, resume, cleanup, list.
"""
import json
import os
import tempfile
import unittest

from omnifuzz.checkpoint import CheckpointManager


class TestCheckpointManager(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.cm = CheckpointManager(scan_id="test-scan-001", checkpoint_dir=self.tmpdir)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    # --- save / load ---

    def test_save_creates_file(self):
        self.cm.save({"target": "http://test", "payloads": [], "completed_indices": [], "results": []})
        self.assertTrue(os.path.exists(self.cm.checkpoint_path))

    def test_load_returns_none_when_no_file(self):
        cm = CheckpointManager(scan_id="nonexistent", checkpoint_dir=self.tmpdir)
        self.assertIsNone(cm.load())

    def test_save_and_load_roundtrip(self):
        state = {
            "target":            "http://example.com",
            "payloads":          [{"text": "p1", "category": "general", "index": 0}],
            "completed_indices": [0],
            "results":           [],
        }
        self.cm.save(state)
        loaded = self.cm.load()
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded["target"], "http://example.com")
        self.assertEqual(loaded["completed_indices"], [0])

    def test_save_injects_scan_id(self):
        self.cm.save({"payloads": [], "completed_indices": [], "results": []})
        loaded = self.cm.load()
        self.assertEqual(loaded["scan_id"], "test-scan-001")

    def test_save_injects_last_updated(self):
        self.cm.save({"payloads": [], "completed_indices": [], "results": []})
        loaded = self.cm.load()
        self.assertIn("last_updated", loaded)

    def test_incremental_save_updates_progress(self):
        self.cm.save({"completed_indices": [0], "payloads": [], "results": []})
        self.cm.save({"completed_indices": [0, 1], "payloads": [], "results": []})
        loaded = self.cm.load()
        self.assertEqual(set(loaded["completed_indices"]), {0, 1})

    # --- exists / delete ---

    def test_exists_false_before_save(self):
        cm = CheckpointManager(scan_id="new-scan", checkpoint_dir=self.tmpdir)
        self.assertFalse(cm.exists())

    def test_exists_true_after_save(self):
        self.cm.save({"payloads": [], "completed_indices": [], "results": []})
        self.assertTrue(self.cm.exists())

    def test_delete_removes_file(self):
        self.cm.save({"payloads": [], "completed_indices": [], "results": []})
        self.cm.delete()
        self.assertFalse(os.path.exists(self.cm.checkpoint_path))

    def test_delete_noop_when_no_file(self):
        # Should not raise
        self.cm.delete()

    # --- list_checkpoints ---

    def test_list_returns_empty_for_missing_dir(self):
        checkpoints = CheckpointManager.list_checkpoints("/nonexistent/dir/abc")
        self.assertEqual(checkpoints, [])

    def test_list_returns_saved_checkpoints(self):
        cm1 = CheckpointManager(scan_id="scan-a", checkpoint_dir=self.tmpdir)
        cm2 = CheckpointManager(scan_id="scan-b", checkpoint_dir=self.tmpdir)
        cm1.save({"target": "http://a", "payloads": [{"text": "p", "index": 0}],
                  "completed_indices": [0], "results": []})
        cm2.save({"target": "http://b", "payloads": [{"text": "p1", "index": 0},
                                                      {"text": "p2", "index": 1}],
                  "completed_indices": [], "results": []})
        checkpoints = CheckpointManager.list_checkpoints(self.tmpdir)
        scan_ids = [c["scan_id"] for c in checkpoints]
        self.assertIn("scan-a", scan_ids)
        self.assertIn("scan-b", scan_ids)

    def test_list_metadata_structure(self):
        self.cm.save({
            "target":            "http://target",
            "payloads":          [{"text": "p1", "index": 0}, {"text": "p2", "index": 1}],
            "completed_indices": [0],
            "results":           [],
        })
        checkpoints = CheckpointManager.list_checkpoints(self.tmpdir)
        c = next(x for x in checkpoints if x["scan_id"] == "test-scan-001")
        self.assertEqual(c["total"],     2)
        self.assertEqual(c["completed"], 1)
        self.assertEqual(c["pct"],       50.0)
        self.assertEqual(c["target"],    "http://target")

    def test_list_sorted_newest_first(self):
        import time
        cm1 = CheckpointManager(scan_id="old-scan", checkpoint_dir=self.tmpdir)
        cm1.save({"payloads": [], "completed_indices": [], "results": []})
        time.sleep(0.01)
        cm2 = CheckpointManager(scan_id="new-scan", checkpoint_dir=self.tmpdir)
        cm2.save({"payloads": [], "completed_indices": [], "results": []})
        checkpoints = CheckpointManager.list_checkpoints(self.tmpdir)
        ids = [c["scan_id"] for c in checkpoints]
        self.assertLess(ids.index("new-scan"), ids.index("old-scan"))

    # --- auto scan_id generation ---

    def test_auto_scan_id_is_string(self):
        cm = CheckpointManager(checkpoint_dir=self.tmpdir)
        self.assertIsInstance(cm.scan_id, str)
        self.assertGreater(len(cm.scan_id), 0)

    def test_two_auto_ids_are_unique(self):
        import time
        cm1 = CheckpointManager(checkpoint_dir=self.tmpdir)
        time.sleep(0.01)
        cm2 = CheckpointManager(checkpoint_dir=self.tmpdir)
        self.assertNotEqual(cm1.scan_id, cm2.scan_id)

    # --- atomic write safety ---

    def test_no_tmp_file_left_after_save(self):
        self.cm.save({"payloads": [], "completed_indices": [], "results": []})
        tmp_path = self.cm.checkpoint_path + ".tmp"
        self.assertFalse(os.path.exists(tmp_path))


if __name__ == "__main__":
    unittest.main()
