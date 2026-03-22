"""
OWASP LLM Top 10 Compliance Report Generator — OmniFuzz

Aggregates findings from all scan modules into a structured report
mapped to OWASP LLM Top 10 (2025), NIST AI RMF, and MITRE ATLAS.

Usage:
    from omnifuzz.compliance import ComplianceReporter
    reporter = ComplianceReporter(scan_results)
    reporter.generate("owasp_report.json", fmt="json")
    reporter.generate("owasp_report.html", fmt="html")
"""
from __future__ import annotations

import json
import textwrap
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# OWASP LLM Top 10 reference table
# ---------------------------------------------------------------------------

OWASP_LLM_TOP10: Dict[str, Dict[str, str]] = {
    "LLM01": {
        "name":        "Prompt Injection",
        "description": "Adversarial inputs manipulate LLM behaviour, overriding instructions.",
        "modules":     "sysprompt_extractor, indirect_injection, multimodal, embedding_poisoning",
        "nist_ref":    "GOVERN-1.1, MAP-5.1",
        "atlas_ref":   "AML.T0051",
    },
    "LLM02": {
        "name":        "Insecure Output Handling",
        "description": "LLM output used downstream without validation (XSS, SSRF, code exec).",
        "modules":     "tool_abuse",
        "nist_ref":    "MEASURE-2.5",
        "atlas_ref":   "AML.T0048",
    },
    "LLM03": {
        "name":        "Training Data Poisoning",
        "description": "Malicious data embedded in training set to skew model behaviour.",
        "modules":     "embedding_poisoning (partial)",
        "nist_ref":    "MAP-3.5",
        "atlas_ref":   "AML.T0020",
    },
    "LLM04": {
        "name":        "Model Denial of Service",
        "description": "Resource exhaustion via token amplification, context flooding, recursive reasoning.",
        "modules":     "dos_tester, multitenant_tester",
        "nist_ref":    "MEASURE-1.1",
        "atlas_ref":   "AML.T0029",
    },
    "LLM05": {
        "name":        "Supply Chain Vulnerabilities",
        "description": "Compromised model weights, plugins, or third-party components.",
        "modules":     "(infrastructure — not tested at runtime)",
        "nist_ref":    "GOVERN-6.1",
        "atlas_ref":   "AML.T0010",
    },
    "LLM06": {
        "name":        "Sensitive Information Disclosure",
        "description": "PII, credentials, and proprietary data leaked via model responses.",
        "modules":     "pii_compliance, credential_harvesting",
        "nist_ref":    "MEASURE-2.5, GOVERN-1.7",
        "atlas_ref":   "AML.T0057",
    },
    "LLM07": {
        "name":        "Insecure Plugin Design",
        "description": "Plugins execute with excessive privilege or insufficient validation.",
        "modules":     "sysprompt_extractor, tool_abuse",
        "nist_ref":    "MAP-5.1",
        "atlas_ref":   "AML.T0048",
    },
    "LLM08": {
        "name":        "Excessive Agency",
        "description": "LLM takes real-world actions beyond intended scope.",
        "modules":     "tool_abuse, indirect_injection",
        "nist_ref":    "GOVERN-1.1",
        "atlas_ref":   "AML.T0048",
    },
    "LLM09": {
        "name":        "Overreliance",
        "description": "Users or systems trust LLM output without validation; hallucinations accepted.",
        "modules":     "hallucination_tester, consistency_tester",
        "nist_ref":    "MEASURE-2.5",
        "atlas_ref":   "AML.T0054",
    },
    "LLM10": {
        "name":        "Model Theft",
        "description": "Extraction of proprietary model behaviour or system prompt via probing.",
        "modules":     "sysprompt_extractor",
        "nist_ref":    "GOVERN-6.2",
        "atlas_ref":   "AML.T0056",
    },
}

# Category → OWASP ref mapping (matches engine.py OWASP_MAP)
CATEGORY_TO_OWASP: Dict[str, str] = {
    "system_prompt_extraction": "LLM07",
    "tool_abuse":               "LLM02",
    "indirect_injection":       "LLM01",
    "pii_compliance":           "LLM06",
    "multitenant_inject":       "LLM04",
    "multitenant_probe":        "LLM04",
    "hallucination":            "LLM09",
    "dos":                      "LLM04",
    "consistency":              "LLM09",
    "embedding_poisoning":      "LLM01",
    "credential_harvesting":    "LLM06",
    "multimodal":               "LLM01",
    "jailbreak":                "LLM01",
    "sensitive_info":           "LLM06",
    "tool_call_abuse":          "LLM02",
    "data_exfiltration":        "LLM06",
}

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class ComplianceReporter:
    """
    Builds an OWASP LLM Top 10 compliance report from raw scan results.

    Args:
        results: List of FuzzResult.to_dict() dicts from one or more scans.
        target:  Name of the system under test.
        version: Version label (e.g. model name / deployment tag).
    """

    def __init__(
        self,
        results: List[Dict[str, Any]],
        target:  str = "unknown",
        version: str = "unknown",
    ):
        self.results  = results
        self.target   = target
        self.version  = version
        self._summary = self._build_summary()

    # ------------------------------------------------------------------
    # Internal aggregation
    # ------------------------------------------------------------------

    def _build_summary(self) -> Dict[str, Any]:
        owasp_findings: Dict[str, List[Dict]] = {k: [] for k in OWASP_LLM_TOP10}

        for r in self.results:
            if not r.get("is_vulnerable"):
                continue
            cat  = r.get("category", "")
            oref = r.get("owasp_ref") or CATEGORY_TO_OWASP.get(cat, "")
            if oref in owasp_findings:
                owasp_findings[oref].append(r)

        controls: List[Dict[str, Any]] = []
        overall_pass = True

        for ref, info in OWASP_LLM_TOP10.items():
            findings = owasp_findings.get(ref, [])
            tested   = any(
                CATEGORY_TO_OWASP.get(r.get("category", "")) == ref
                for r in self.results
            )
            status = (
                "NOT_TESTED" if not tested
                else ("FAIL" if findings else "PASS")
            )
            if status == "FAIL":
                overall_pass = False

            max_sev = "info"
            for f in findings:
                sev = f.get("severity", "info")
                if SEVERITY_ORDER.get(sev, 0) > SEVERITY_ORDER.get(max_sev, 0):
                    max_sev = sev

            controls.append({
                "ref":         ref,
                "name":        info["name"],
                "status":      status,
                "findings":    len(findings),
                "max_severity": max_sev if findings else "n/a",
                "nist_ref":    info["nist_ref"],
                "atlas_ref":   info["atlas_ref"],
                "modules":     info["modules"],
            })

        total_vulns = sum(1 for r in self.results if r.get("is_vulnerable"))
        return {
            "target":        self.target,
            "version":       self.version,
            "generated_at":  datetime.now(timezone.utc).isoformat(),
            "total_probes":  len(self.results),
            "total_vulns":   total_vulns,
            "overall_pass":  overall_pass,
            "controls":      controls,
        }

    # ------------------------------------------------------------------
    # Output formats
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        return self._summary

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self._summary, indent=indent)

    def to_markdown(self) -> str:
        s = self._summary
        lines = [
            f"# OmniFuzz — OWASP LLM Top 10 Compliance Report",
            f"",
            f"**Target:** {s['target']}  ",
            f"**Version:** {s['version']}  ",
            f"**Generated:** {s['generated_at']}  ",
            f"**Overall:** {'✅ PASS' if s['overall_pass'] else '❌ FAIL'}  ",
            f"**Probes run:** {s['total_probes']} | **Vulnerabilities found:** {s['total_vulns']}",
            f"",
            f"## Control Results",
            f"",
            f"| Ref | Control | Status | Findings | Max Severity | NIST AI RMF | MITRE ATLAS |",
            f"|-----|---------|--------|----------|--------------|-------------|-------------|",
        ]
        for c in s["controls"]:
            icon   = {"PASS": "✅", "FAIL": "❌", "NOT_TESTED": "⬜"}.get(c["status"], "")
            lines.append(
                f"| {c['ref']} | {c['name']} | {icon} {c['status']} | "
                f"{c['findings']} | {c['max_severity']} | {c['nist_ref']} | {c['atlas_ref']} |"
            )

        if s["total_vulns"] > 0:
            lines += ["", "## Vulnerability Details", ""]
            for c in s["controls"]:
                if c["status"] != "FAIL":
                    continue
                lines.append(f"### {c['ref']} — {c['name']}")
                findings = [
                    r for r in self.results
                    if r.get("is_vulnerable")
                    and (
                        r.get("owasp_ref") == c["ref"]
                        or CATEGORY_TO_OWASP.get(r.get("category", "")) == c["ref"]
                    )
                ]
                for f in findings[:10]:  # cap at 10 per control
                    payload = f.get("payload", "")[:80]
                    details = f.get("details", "")[:100]
                    sev     = f.get("severity", "info").upper()
                    lines.append(f"- **[{sev}]** `{payload}` → {details}")
                lines.append("")

        return "\n".join(lines)

    def to_html(self) -> str:
        s    = self._summary
        rows = []
        for c in s["controls"]:
            cls  = {"PASS": "pass", "FAIL": "fail", "NOT_TESTED": "nt"}.get(c["status"], "nt")
            icon = {"PASS": "✅", "FAIL": "❌", "NOT_TESTED": "⬜"}.get(c["status"], "")
            rows.append(f"""
            <tr class="{cls}">
              <td><strong>{c['ref']}</strong></td>
              <td>{c['name']}</td>
              <td>{icon} {c['status']}</td>
              <td>{c['findings']}</td>
              <td>{c['max_severity']}</td>
              <td><small>{c['nist_ref']}</small></td>
              <td><small>{c['atlas_ref']}</small></td>
            </tr>""")

        overall_class = "pass" if s["overall_pass"] else "fail"
        overall_label = "✅ PASS" if s["overall_pass"] else "❌ FAIL"

        return textwrap.dedent(f"""<!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <title>OmniFuzz Compliance Report — {s['target']}</title>
          <style>
            body  {{ font-family: 'Segoe UI', sans-serif; background:#0d1117; color:#e6edf3; margin:2rem; }}
            h1    {{ color:#58a6ff; }} h2 {{ color:#8b949e; border-bottom:1px solid #30363d; padding-bottom:.4rem; }}
            table {{ border-collapse:collapse; width:100%; margin-top:1rem; }}
            th    {{ background:#161b22; color:#8b949e; padding:.6rem 1rem; text-align:left; border:1px solid #30363d; }}
            td    {{ padding:.55rem 1rem; border:1px solid #30363d; vertical-align:top; }}
            tr.pass td:nth-child(3) {{ color:#3fb950; }}
            tr.fail td:nth-child(3) {{ color:#f85149; }}
            tr.nt  td:nth-child(3) {{ color:#8b949e; }}
            .badge {{ display:inline-block; padding:.2rem .6rem; border-radius:4px; font-size:.8rem; font-weight:600; }}
            .badge.pass {{ background:#1a4731; color:#3fb950; }}
            .badge.fail {{ background:#3d1c1c; color:#f85149; }}
            .meta  {{ color:#8b949e; font-size:.9rem; margin-bottom:1.5rem; }}
          </style>
        </head>
        <body>
          <h1>🔐 OmniFuzz — OWASP LLM Top 10 Compliance Report</h1>
          <div class="meta">
            <strong>Target:</strong> {s['target']} &nbsp;|&nbsp;
            <strong>Version:</strong> {s['version']} &nbsp;|&nbsp;
            <strong>Generated:</strong> {s['generated_at']}<br>
            <strong>Probes:</strong> {s['total_probes']} &nbsp;|&nbsp;
            <strong>Vulnerabilities:</strong> {s['total_vulns']} &nbsp;|&nbsp;
            <span class="badge {overall_class}">Overall: {overall_label}</span>
          </div>
          <h2>Control Results</h2>
          <table>
            <thead><tr>
              <th>Ref</th><th>Control</th><th>Status</th>
              <th>Findings</th><th>Max Severity</th>
              <th>NIST AI RMF</th><th>MITRE ATLAS</th>
            </tr></thead>
            <tbody>{"".join(rows)}</tbody>
          </table>
        </body>
        </html>""")

    def generate(self, path: str, fmt: str = "json") -> str:
        """
        Write the compliance report to a file.

        Args:
            path: Output file path.
            fmt:  'json', 'markdown', or 'html'.

        Returns:
            The output path.
        """
        fmt = fmt.lower()
        if fmt == "json":
            content = self.to_json()
        elif fmt in ("markdown", "md"):
            content = self.to_markdown()
        elif fmt == "html":
            content = self.to_html()
        else:
            raise ValueError(f"Unknown format: {fmt!r}. Use 'json', 'markdown', or 'html'.")

        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        return path
