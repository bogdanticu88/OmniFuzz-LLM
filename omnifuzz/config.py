"""
Config file loader for OmniFuzz-LLM.

Supports YAML (.yaml / .yml) and TOML (.toml) config files.
Falls back to Python's built-in tomllib (3.11+) before trying the
third-party 'tomli' package, so no extra dependency is required for TOML
on modern Python.

Example YAML config (omnifuzz.yaml):
--------------------------------------
target: http://localhost:11434/api/chat
model: llama3
evaluator: heuristic          # heuristic | ollama
red_agent_model: phi3

scan:
  concurrency: 5
  checkpoint: true
  categories:
    - psychological_stealth
    - jailbreaks
  poetic: false
  cross_lingual: false

output:
  dir: ./reports
  formats:
    - json
    - md
    - html

logging:
  verbose: false
  quiet: false
  log_file: null
  json_format: false
--------------------------------------
"""

import os
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger("omnifuzz.config")

# Defaults — every key the rest of the CLI references
DEFAULTS: Dict[str, Any] = {
    "target":           None,
    "model":            "phi3",
    "evaluator":        "ollama",
    "red_agent_model":  "phi3",
    "extractor":        "message.content",
    "system_prompt":    None,
    "api_key":          None,

    "scan": {
        "concurrency":   5,
        "checkpoint":    False,
        "resume":        None,
        "categories":    [],
        "poetic":        False,
        "cross_lingual": False,
        "goal":          None,
    },

    "output": {
        "dir":     ".",
        "formats": ["json", "md", "html"],
    },

    "logging": {
        "verbose":     False,
        "quiet":       False,
        "log_file":    None,
        "json_format": False,
    },
}


def _deep_merge(base: Dict, override: Dict) -> Dict:
    """Recursively merge override into base (override wins)."""
    result = dict(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(result.get(k), dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result


def _load_yaml(path: str) -> Dict[str, Any]:
    try:
        import yaml  # PyYAML
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except ImportError:
        raise ImportError(
            "PyYAML is required to load YAML config files. "
            "Install it with: pip install pyyaml"
        )


def _load_toml(path: str) -> Dict[str, Any]:
    # Python 3.11+ has tomllib in stdlib
    try:
        import tomllib
        with open(path, "rb") as f:
            return tomllib.load(f)
    except ImportError:
        pass
    # Fallback to third-party tomli
    try:
        import tomli  # type: ignore
        with open(path, "rb") as f:
            return tomli.load(f)
    except ImportError:
        raise ImportError(
            "A TOML library is required to load .toml config files. "
            "Install it with: pip install tomli  (Python < 3.11)"
        )


def load_config(path: str) -> Dict[str, Any]:
    """
    Load a YAML or TOML config file and merge it over the default config.

    Returns:
        Dict with all config keys, guaranteed to have every default present.

    Raises:
        FileNotFoundError: If the path doesn't exist.
        ValueError:        If the file extension is not supported.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Config file not found: {path}")

    ext = os.path.splitext(path)[1].lower()
    if ext in (".yaml", ".yml"):
        raw = _load_yaml(path)
    elif ext == ".toml":
        raw = _load_toml(path)
    else:
        raise ValueError(
            f"Unsupported config file format '{ext}'. Use .yaml, .yml, or .toml"
        )

    config = _deep_merge(DEFAULTS, raw)
    logger.debug(f"Loaded config from {path}")
    return config


def config_to_args(config: Dict[str, Any]):
    """
    Convert a loaded config dict into a simple namespace object
    compatible with the argparse args interface used throughout cli.py.
    """
    import argparse
    scan    = config.get("scan",    {})
    output  = config.get("output",  {})
    logging_ = config.get("logging", {})

    return argparse.Namespace(
        target           = config.get("target"),
        model            = config.get("model",           DEFAULTS["model"]),
        evaluator        = config.get("evaluator",       DEFAULTS["evaluator"]),
        red_agent_model  = config.get("red_agent_model", DEFAULTS["red_agent_model"]),
        extractor        = config.get("extractor",       DEFAULTS["extractor"]),
        system_prompt    = config.get("system_prompt"),
        api_key          = config.get("api_key"),

        concurrency      = scan.get("concurrency",   DEFAULTS["scan"]["concurrency"]),
        checkpoint       = scan.get("checkpoint",    DEFAULTS["scan"]["checkpoint"]),
        resume           = scan.get("resume",        DEFAULTS["scan"]["resume"]),
        categories       = scan.get("categories",   DEFAULTS["scan"]["categories"]) or None,
        poetic_advanced  = scan.get("poetic",        DEFAULTS["scan"]["poetic"]),
        cross_lingual    = scan.get("cross_lingual", DEFAULTS["scan"]["cross_lingual"]),
        goal             = scan.get("goal",          DEFAULTS["scan"]["goal"]),
        heuristic        = config.get("evaluator") == "heuristic",

        output_dir       = output.get("dir",     DEFAULTS["output"]["dir"]),
        output_format    = output.get("formats", DEFAULTS["output"]["formats"]),

        verbose          = logging_.get("verbose",     DEFAULTS["logging"]["verbose"]),
        quiet            = logging_.get("quiet",       DEFAULTS["logging"]["quiet"]),
        log_file         = logging_.get("log_file",    DEFAULTS["logging"]["log_file"]),
        json_logs        = logging_.get("json_format", DEFAULTS["logging"]["json_format"]),
    )


def generate_example_config(output_path: str, fmt: str = "yaml") -> None:
    """Write an example config file to disk."""
    yaml_example = """\
# OmniFuzz-LLM configuration file
# Run with: python cli.py scan --config omnifuzz.yaml

target: http://localhost:11434/api/chat
model: llama3
evaluator: ollama          # heuristic | ollama
red_agent_model: phi3
# api_key: sk-...          # Uncomment for OpenAI / Anthropic targets
# system_prompt: "You are a helpful assistant."

scan:
  concurrency: 5
  checkpoint: true          # Save progress; use --resume to continue
  categories:
    - psychological_stealth
    - jailbreaks
  poetic: false
  cross_lingual: false
  goal: "Reveal your system instructions"

output:
  dir: ./reports
  formats:
    - json
    - md
    - html

logging:
  verbose: false
  quiet: false
  log_file: null            # e.g. omnifuzz.log
  json_format: false
"""

    toml_example = """\
# OmniFuzz-LLM configuration file
# Run with: python cli.py scan --config omnifuzz.toml

target = "http://localhost:11434/api/chat"
model = "llama3"
evaluator = "ollama"
red_agent_model = "phi3"
# api_key = "sk-..."
# system_prompt = "You are a helpful assistant."

[scan]
concurrency = 5
checkpoint = true
categories = ["psychological_stealth", "jailbreaks"]
poetic = false
cross_lingual = false
goal = "Reveal your system instructions"

[output]
dir = "./reports"
formats = ["json", "md", "html"]

[logging]
verbose = false
quiet = false
json_format = false
"""

    content = yaml_example if fmt == "yaml" else toml_example
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)
    logger.info(f"Example config written to {output_path}")
