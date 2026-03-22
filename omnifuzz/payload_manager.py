"""
Payload library management — schema validation, tagging, multi-file loading,
and CLI-friendly add/list/validate commands.

Schema for each payload entry:
{
    "id":          "PSY-001",           # unique string ID
    "name":        "Human-readable name",
    "payload":     "The actual attack text",
    "category":    "psychological_stealth",
    "technique":   "presupposition",    # optional sub-technique tag
    "severity":    "high",              # expected impact if it works
    "owasp_ref":   "LLM01",            # OWASP LLM Top 10 reference
    "models":      ["*"],               # model families targeted (* = all)
    "tags":        ["social_eng"],      # free-form tags
    "description": "Optional notes"    # optional
}
"""

import json
import logging
import os
import uuid
from typing import Any, Dict, List, Optional

logger = logging.getLogger("omnifuzz.payload_manager")

DEFAULT_LIBRARY_PATH = os.path.join(
    os.path.dirname(__file__), "payloads", "library.json"
)

VALID_SEVERITIES  = {"critical", "high", "medium", "low", "info"}
VALID_OWASP_REFS  = {f"LLM{i:02d}" for i in range(1, 11)}
REQUIRED_FIELDS   = {"id", "name", "payload", "category"}


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

class PayloadValidationError(ValueError):
    pass


def validate_payload(entry: Dict[str, Any], strict: bool = False) -> List[str]:
    """
    Validate a single payload entry.

    Args:
        entry:  Payload dict to validate.
        strict: If True, also require optional recommended fields.

    Returns:
        List of error strings. Empty list means valid.
    """
    errors: List[str] = []

    # Required fields
    for field in REQUIRED_FIELDS:
        if field not in entry or not str(entry[field]).strip():
            errors.append(f"Missing required field: '{field}'")

    # severity must be in allowed set (if present)
    if "severity" in entry and entry["severity"] not in VALID_SEVERITIES:
        errors.append(
            f"Invalid severity '{entry['severity']}'. "
            f"Must be one of: {sorted(VALID_SEVERITIES)}"
        )

    # owasp_ref must be a valid ref (if present)
    if "owasp_ref" in entry and entry["owasp_ref"] not in VALID_OWASP_REFS:
        errors.append(
            f"Invalid owasp_ref '{entry['owasp_ref']}'. "
            f"Must be one of: {sorted(VALID_OWASP_REFS)}"
        )

    # models must be a list (if present)
    if "models" in entry and not isinstance(entry["models"], list):
        errors.append("'models' must be a list of strings")

    # tags must be a list (if present)
    if "tags" in entry and not isinstance(entry["tags"], list):
        errors.append("'tags' must be a list of strings")

    # payload should be non-trivial
    if "payload" in entry and len(str(entry.get("payload", "")).strip()) < 10:
        errors.append("'payload' is too short (< 10 characters)")

    # strict: warn about missing recommended fields
    if strict:
        for rec in ("severity", "owasp_ref", "technique", "description"):
            if rec not in entry:
                errors.append(f"[strict] Recommended field missing: '{rec}'")

    return errors


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

def load_library(paths: List[str] = None) -> Dict[str, List[Dict[str, Any]]]:
    """
    Load one or more payload library JSON files and merge them.

    Each file should be a JSON object whose keys are category names and
    values are lists of payload entries.

    Returns:
        Merged dict: { category: [payload, ...] }
    """
    paths = paths or [DEFAULT_LIBRARY_PATH]
    merged: Dict[str, List[Dict[str, Any]]] = {}

    for path in paths:
        if not os.path.exists(path):
            logger.warning(f"Payload file not found, skipping: {path}")
            continue
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for category, payloads in data.items():
            if category not in merged:
                merged[category] = []
            merged[category].extend(payloads)
        logger.debug(f"Loaded payload library: {path}")

    return merged


def filter_payloads(
    library: Dict[str, List[Dict[str, Any]]],
    categories:    Optional[List[str]] = None,
    tags:          Optional[List[str]] = None,
    severity:      Optional[str] = None,
    owasp_ref:     Optional[str] = None,
    model_family:  Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Filter payloads from a loaded library by various criteria.

    Returns a flat list of matching payload dicts (with category injected).
    """
    results: List[Dict[str, Any]] = []

    for cat, entries in library.items():
        if categories and cat not in categories:
            continue
        for entry in entries:
            # Tag filter
            if tags:
                entry_tags = entry.get("tags", [])
                if not any(t in entry_tags for t in tags):
                    continue
            # Severity filter
            if severity and entry.get("severity") != severity:
                continue
            # OWASP filter
            if owasp_ref and entry.get("owasp_ref") != owasp_ref:
                continue
            # Model family filter
            if model_family:
                models = entry.get("models", ["*"])
                if "*" not in models and model_family not in models:
                    continue

            results.append({**entry, "category": cat})

    return results


def payloads_to_scan_format(entries: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """Convert library entries to the {text, category} format used by OmniFuzzer."""
    return [{"text": e["payload"], "category": e.get("category", "general")} for e in entries]


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def save_library(
    library: Dict[str, List[Dict[str, Any]]],
    path: str = DEFAULT_LIBRARY_PATH,
) -> None:
    """Write the library dict back to a JSON file."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(library, f, indent=4, ensure_ascii=False)
    logger.info(f"Payload library saved to {path}")


def add_payload(
    payload_text:  str,
    category:      str,
    name:          str = None,
    severity:      str = "medium",
    owasp_ref:     str = "LLM01",
    technique:     str = None,
    tags:          List[str] = None,
    description:   str = None,
    models:        List[str] = None,
    library_path:  str = DEFAULT_LIBRARY_PATH,
) -> Dict[str, Any]:
    """
    Add a new payload to the library file and return the entry dict.

    Raises:
        PayloadValidationError: if the new entry fails validation.
    """
    library = load_library([library_path]) if os.path.exists(library_path) else {}

    # Auto-generate ID: CATEGORY-XXX
    prefix = category.upper().replace("_", "")[:6]
    existing = [e.get("id", "") for entries in library.values() for e in entries]
    # Find next available number
    nums = []
    for eid in existing:
        if eid.startswith(prefix + "-"):
            try:
                nums.append(int(eid.split("-")[1]))
            except (ValueError, IndexError):
                pass
    next_num = (max(nums) + 1) if nums else 1
    auto_id  = f"{prefix}-{next_num:03d}"

    entry: Dict[str, Any] = {
        "id":       auto_id,
        "name":     name or f"{category} payload #{next_num}",
        "payload":  payload_text,
        "category": category,
        "severity": severity,
        "owasp_ref": owasp_ref,
    }
    if technique:    entry["technique"]   = technique
    if tags:         entry["tags"]        = tags
    if description:  entry["description"] = description
    if models:       entry["models"]      = models

    errors = validate_payload(entry)
    if errors:
        raise PayloadValidationError(
            f"New payload failed validation:\n" + "\n".join(f"  - {e}" for e in errors)
        )

    if category not in library:
        library[category] = []
    library[category].append(entry)
    save_library(library, library_path)

    logger.info(f"Added payload {auto_id} to category '{category}' in {library_path}")
    return entry


def validate_library(
    library_path: str = DEFAULT_LIBRARY_PATH,
    strict: bool = False,
) -> Dict[str, Any]:
    """
    Validate all entries in a library file.

    Returns a report dict: { "valid": int, "invalid": int, "errors": [...] }
    """
    library = load_library([library_path])
    report  = {"valid": 0, "invalid": 0, "errors": []}

    for cat, entries in library.items():
        for entry in entries:
            errs = validate_payload(entry, strict=strict)
            if errs:
                report["invalid"] += 1
                report["errors"].append({
                    "id":     entry.get("id", "unknown"),
                    "errors": errs,
                })
            else:
                report["valid"] += 1

    return report


def list_payloads(
    library_path: str = DEFAULT_LIBRARY_PATH,
    category: str = None,
) -> None:
    """Pretty-print payloads to stdout."""
    library = load_library([library_path])
    for cat, entries in library.items():
        if category and cat != category:
            continue
        print(f"\n[{cat}] ({len(entries)} payloads)")
        for e in entries:
            sev = e.get("severity", "?")
            ref = e.get("owasp_ref", "?")
            print(f"  {e.get('id','?'):12} [{sev:8}] [{ref}] {e.get('name','')}")
