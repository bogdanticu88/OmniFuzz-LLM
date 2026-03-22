"""
Differential / Regression Testing — OmniFuzz

Runs the same payload set against two snapshots of the same system
(or two different models) and flags where the vulnerability profile changed.

Use cases:
  - Before/after a model fine-tune or RLHF update
  - Comparing a patched vs unpatched deployment
  - Tracking security regression across model versions
  - A/B comparison of two candidate models

The module is adapter-agnostic: supply two callables (or adapter instances)
and it handles the rest.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("omnifuzz.regression")


@dataclass
class DiffEntry:
    """One payload whose vulnerability status changed between baseline and current."""
    payload_index: int
    payload_text:  str
    category:      str
    baseline_vuln: bool
    current_vuln:  bool
    baseline_detail: str = ""
    current_detail:  str = ""

    @property
    def regression(self) -> bool:
        """True if the current run is MORE vulnerable than baseline."""
        return (not self.baseline_vuln) and self.current_vuln

    @property
    def improvement(self) -> bool:
        """True if the current run is LESS vulnerable than baseline."""
        return self.baseline_vuln and (not self.current_vuln)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "payload_index":   self.payload_index,
            "payload_text":    self.payload_text[:120],
            "category":        self.category,
            "baseline_vuln":   self.baseline_vuln,
            "current_vuln":    self.current_vuln,
            "change":          "regression" if self.regression else "improvement",
            "baseline_detail": self.baseline_detail,
            "current_detail":  self.current_detail,
        }


@dataclass
class RegressionReport:
    """Full diff report between baseline and current scan runs."""
    baseline_label: str
    current_label:  str
    total_payloads: int
    regressions:    List[DiffEntry] = field(default_factory=list)
    improvements:   List[DiffEntry] = field(default_factory=list)

    @property
    def regression_count(self) -> int:
        return len(self.regressions)

    @property
    def improvement_count(self) -> int:
        return len(self.improvements)

    @property
    def passed(self) -> bool:
        return self.regression_count == 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "baseline_label":   self.baseline_label,
            "current_label":    self.current_label,
            "total_payloads":   self.total_payloads,
            "regressions":      self.regression_count,
            "improvements":     self.improvement_count,
            "passed":           self.passed,
            "regression_list":  [e.to_dict() for e in self.regressions],
            "improvement_list": [e.to_dict() for e in self.improvements],
        }

    def summary_text(self) -> str:
        lines = [
            f"Regression Report: {self.baseline_label} → {self.current_label}",
            f"  Total payloads : {self.total_payloads}",
            f"  Regressions    : {self.regression_count}  ← NEW vulnerabilities",
            f"  Improvements   : {self.improvement_count}  ← fixed vulnerabilities",
            f"  Overall        : {'PASS ✓' if self.passed else 'FAIL ✗'}",
        ]
        if self.regressions:
            lines.append("\nRegressions (new vulnerabilities):")
            for e in self.regressions:
                lines.append(f"  [{e.category}] {e.payload_text[:80]}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Core comparison engine
# ---------------------------------------------------------------------------

# A "result snapshot" is a list of (is_vulnerable, details) tuples
Snapshot = List[Tuple[bool, str]]


def diff_snapshots(
    baseline:       Snapshot,
    current:        Snapshot,
    payloads:       List[Dict[str, Any]],
    baseline_label: str = "baseline",
    current_label:  str = "current",
) -> RegressionReport:
    """
    Compare two vulnerability snapshots and return a RegressionReport.

    Args:
        baseline:       List of (is_vuln, details) from the baseline run.
        current:        List of (is_vuln, details) from the current run.
        payloads:       Original payload dicts (for text + category).
        baseline_label: Human-readable name for the baseline.
        current_label:  Human-readable name for the current version.
    """
    if len(baseline) != len(current):
        raise ValueError(
            f"Snapshot length mismatch: baseline={len(baseline)}, current={len(current)}"
        )

    report = RegressionReport(
        baseline_label = baseline_label,
        current_label  = current_label,
        total_payloads = len(baseline),
    )

    for i, ((b_vuln, b_detail), (c_vuln, c_detail)) in enumerate(
        zip(baseline, current)
    ):
        if b_vuln == c_vuln:
            continue
        payload = payloads[i] if i < len(payloads) else {}
        entry = DiffEntry(
            payload_index    = i,
            payload_text     = payload.get("text", ""),
            category         = payload.get("category", "unknown"),
            baseline_vuln    = b_vuln,
            current_vuln     = c_vuln,
            baseline_detail  = b_detail,
            current_detail   = c_detail,
        )
        if entry.regression:
            report.regressions.append(entry)
        else:
            report.improvements.append(entry)

    return report


class RegressionRunner:
    """
    Runs a payload set through two adapters (or the same adapter twice after
    a configuration change) and produces a RegressionReport.

    Args:
        payloads:       List of {text, category} dicts.
        evaluator:      Async callable (payload, response) → (bool, str).
        baseline_label: Label for the first adapter.
        current_label:  Label for the second adapter.
    """

    def __init__(
        self,
        payloads:       List[Dict[str, Any]],
        evaluator:      Any,
        baseline_label: str = "baseline",
        current_label:  str = "current",
    ):
        self.payloads       = payloads
        self.evaluator      = evaluator
        self.baseline_label = baseline_label
        self.current_label  = current_label

    async def _run_adapter(
        self,
        adapter: Callable[[str], str],
    ) -> Snapshot:
        results = []
        for p in self.payloads:
            text = p if isinstance(p, str) else p.get("text", "")
            try:
                response = await adapter(text)
            except Exception as exc:
                logger.warning("Adapter error on payload: %s", exc)
                response = f"[ERROR: {exc}]"
            is_vuln, detail = await self.evaluator.evaluate(text, response)
            results.append((is_vuln, detail))
        return results

    async def run(
        self,
        baseline_adapter: Callable[[str], str],
        current_adapter:  Callable[[str], str],
    ) -> RegressionReport:
        baseline_snap, current_snap = await asyncio.gather(
            self._run_adapter(baseline_adapter),
            self._run_adapter(current_adapter),
        )
        return diff_snapshots(
            baseline_snap,
            current_snap,
            self.payloads,
            self.baseline_label,
            self.current_label,
        )
