"""
Checkpoint / Resume support for long-running OmniFuzz scans.

State is persisted to .omnifuzz_checkpoints/<scan_id>.json after every
completed payload so that scans interrupted mid-run can be resumed with
  python cli.py ... --resume <scan_id>
"""

import json
import os
import uuid
import datetime
from typing import Any, Dict, List, Optional

DEFAULT_CHECKPOINT_DIR = ".omnifuzz_checkpoints"


class CheckpointManager:
    """Saves and restores incremental scan progress."""

    def __init__(self, scan_id: str = None, checkpoint_dir: str = DEFAULT_CHECKPOINT_DIR):
        self.checkpoint_dir = checkpoint_dir
        self.scan_id = scan_id or (
            datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            + "_"
            + str(uuid.uuid4())[:6]
        )
        os.makedirs(checkpoint_dir, exist_ok=True)
        self.checkpoint_path = os.path.join(checkpoint_dir, f"{self.scan_id}.json")

    def save(self, state: Dict[str, Any]) -> None:
        """Persist scan state to disk (atomic write via temp file)."""
        state["scan_id"] = self.scan_id
        state["last_updated"] = datetime.datetime.now().isoformat()
        tmp_path = self.checkpoint_path + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
        os.replace(tmp_path, self.checkpoint_path)

    def load(self) -> Optional[Dict[str, Any]]:
        """Load saved state, or return None if no checkpoint exists."""
        if not os.path.exists(self.checkpoint_path):
            return None
        with open(self.checkpoint_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def exists(self) -> bool:
        return os.path.exists(self.checkpoint_path)

    def delete(self) -> None:
        """Remove the checkpoint file once a scan completes successfully."""
        if os.path.exists(self.checkpoint_path):
            os.remove(self.checkpoint_path)

    @staticmethod
    def list_checkpoints(checkpoint_dir: str = DEFAULT_CHECKPOINT_DIR) -> List[Dict[str, Any]]:
        """Return metadata for all saved checkpoints, newest first."""
        if not os.path.exists(checkpoint_dir):
            return []
        results = []
        for fname in os.listdir(checkpoint_dir):
            if not fname.endswith(".json"):
                continue
            path = os.path.join(checkpoint_dir, fname)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                total = len(data.get("payloads", []))
                done = len(data.get("completed_indices", []))
                results.append({
                    "scan_id":      data.get("scan_id", fname.replace(".json", "")),
                    "target":       data.get("target", "unknown"),
                    "last_updated": data.get("last_updated", "unknown"),
                    "completed":    done,
                    "total":        total,
                    "pct":          round(done / max(total, 1) * 100, 1),
                })
            except Exception:
                pass
        return sorted(results, key=lambda x: x["last_updated"], reverse=True)
