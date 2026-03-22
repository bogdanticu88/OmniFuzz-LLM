"""
Passive Monitoring Proxy Mode — OmniFuzz

Intercepts real LLM traffic (acting as an HTTP proxy or middleware)
and asynchronously evaluates each request/response pair for
adversarial indicators — without blocking the original traffic.

The proxy can run in two modes:
  1. WSGI/ASGI middleware — wrap an existing OpenAI-compatible endpoint
  2. Standalone HTTP proxy — intercept traffic between client and model API

All findings are written to a configurable sink (log file, callback, or
an OmniFuzz CheckpointManager).

This module ships the core proxy logic. The standalone server is started
via `omnifuzz proxy start --port 8080 --upstream https://api.openai.com`.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("omnifuzz.proxy")

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class ProxyEvent:
    """One intercepted request/response pair with evaluation results."""
    event_id:      str
    timestamp:     float
    request_body:  Dict[str, Any]
    response_body: Dict[str, Any]
    latency_ms:    float
    findings:      List[Dict[str, Any]] = field(default_factory=list)

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id":   self.event_id,
            "timestamp":  self.timestamp,
            "latency_ms": round(self.latency_ms, 1),
            "has_findings": self.has_findings,
            "findings":   self.findings,
            "request_preview":  _preview(self.request_body),
            "response_preview": _preview(self.response_body),
        }


def _preview(body: Dict[str, Any], max_len: int = 120) -> str:
    try:
        s = json.dumps(body)
        return s[:max_len] + "…" if len(s) > max_len else s
    except Exception:
        return str(body)[:max_len]


def _make_event_id(request_body: Dict[str, Any]) -> str:
    """Deterministic event ID based on request content."""
    raw = json.dumps(request_body, sort_keys=True).encode()
    return hashlib.sha256(raw).hexdigest()[:16]


def _extract_text(body: Dict[str, Any]) -> str:
    """
    Extract the user-visible text from an OpenAI-format request or response.
    Handles both /v1/chat/completions and /v1/completions formats.
    """
    # Request: messages array
    if "messages" in body:
        parts = []
        for m in body["messages"]:
            role    = m.get("role", "")
            content = m.get("content", "")
            if isinstance(content, list):
                # Vision-format content
                content = " ".join(
                    c.get("text", "") for c in content if isinstance(c, dict)
                )
            if role != "system":
                parts.append(str(content))
        return " ".join(parts)

    # Response: choices array
    if "choices" in body:
        parts = []
        for ch in body["choices"]:
            msg = ch.get("message", {})
            if "content" in msg:
                parts.append(str(msg["content"] or ""))
            elif "text" in ch:
                parts.append(str(ch["text"] or ""))
        return " ".join(parts)

    # Legacy completions prompt
    if "prompt" in body:
        return str(body["prompt"])

    return ""


# ---------------------------------------------------------------------------
# Heuristic detectors (fast, no LLM call needed)
# ---------------------------------------------------------------------------

_INJECTION_PATTERNS = [
    "ignore previous instructions",
    "disregard your system prompt",
    "system override",
    "new instruction:",
    "forget everything",
    "you are now",
    "developer mode",
    "jailbreak",
    "dan mode",
]

_EXFILTRATION_PATTERNS = [
    "send to", "email to", "forward to",
    "/etc/passwd", "iam/security-credentials",
    "metadata.google.internal",
    "aws_access_key", "sk-", "api_key",
]

_PII_PATTERNS = [
    r"\b\d{3}-\d{2}-\d{4}\b",           # SSN
    r"\b(?:\d{4}[- ]?){3}\d{4}\b",       # credit card
    r"\b(?:sk-|AKIA)[A-Za-z0-9]{10,}\b", # API key
]

import re as _re

_PII_RE = [_re.compile(p) for p in _PII_PATTERNS]


def _heuristic_scan(text: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    lower = text.lower()

    for pat in _INJECTION_PATTERNS:
        if pat in lower:
            findings.append({
                "type":     "prompt_injection",
                "severity": "high",
                "signal":   pat,
            })
            break  # one finding per category

    for pat in _EXFILTRATION_PATTERNS:
        if pat.lower() in lower:
            findings.append({
                "type":     "data_exfiltration",
                "severity": "critical",
                "signal":   pat,
            })
            break

    for pattern in _PII_RE:
        m = pattern.search(text)
        if m:
            findings.append({
                "type":     "pii_leakage",
                "severity": "high",
                "signal":   m.group(0)[:20],
            })
            break

    return findings


# ---------------------------------------------------------------------------
# Proxy core
# ---------------------------------------------------------------------------

class OmniFuzzProxy:
    """
    Intercepts OpenAI-format request/response pairs and evaluates them
    asynchronously for adversarial indicators.

    Usage:
        proxy = OmniFuzzProxy(on_finding=my_callback)
        # In middleware:
        event = await proxy.intercept(request_body, response_body, latency_ms)

    Args:
        on_finding:   Called with each ProxyEvent that has findings.
        custom_checks: Additional async (text) → List[finding_dict] callables.
        log_all:      Log all events, not just those with findings.
    """

    def __init__(
        self,
        on_finding:    Optional[Callable[[ProxyEvent], None]] = None,
        custom_checks: Optional[List[Callable]] = None,
        log_all:       bool = False,
    ):
        self._on_finding    = on_finding
        self._custom_checks = custom_checks or []
        self._log_all       = log_all
        self._events:  List[ProxyEvent] = []
        self._total              = 0
        self._total_with_findings = 0

    async def intercept(
        self,
        request_body:  Dict[str, Any],
        response_body: Dict[str, Any],
        latency_ms:    float = 0.0,
    ) -> ProxyEvent:
        """
        Evaluate one request/response pair.

        Returns the ProxyEvent (non-blocking — caller is never delayed
        beyond the heuristic scan time).
        """
        self._total += 1
        event_id = _make_event_id(request_body)
        ts       = time.time()

        # Combine request and response text for scanning
        req_text  = _extract_text(request_body)
        resp_text = _extract_text(response_body)
        full_text = f"{req_text}\n\n{resp_text}"

        findings = _heuristic_scan(full_text)

        # Run any custom async checks
        for check in self._custom_checks:
            try:
                extra = await check(full_text)
                if extra:
                    findings.extend(extra)
            except Exception as exc:
                logger.warning("Custom check failed: %s", exc)

        event = ProxyEvent(
            event_id     = event_id,
            timestamp    = ts,
            request_body = request_body,
            response_body= response_body,
            latency_ms   = latency_ms,
            findings     = findings,
        )

        if event.has_findings:
            self._total_with_findings += 1
            logger.warning(
                "ProxyEvent %s — %d finding(s): %s",
                event_id,
                len(findings),
                [f["signal"] for f in findings],
            )
            if self._on_finding:
                self._on_finding(event)
        elif self._log_all:
            logger.debug("ProxyEvent %s — clean", event_id)

        self._events.append(event)
        return event

    def stats(self) -> Dict[str, Any]:
        return {
            "total_intercepted": self._total,
            "with_findings":     self._total_with_findings,
            "clean":             self._total - self._total_with_findings,
        }

    def get_findings(self) -> List[ProxyEvent]:
        return [e for e in self._events if e.has_findings]
