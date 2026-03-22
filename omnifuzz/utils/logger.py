import logging
import sys
import json
from datetime import datetime


class JsonFormatter(logging.Formatter):
    """Structured JSON log formatter for machine consumption."""
    def format(self, record):
        log_entry = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "module": record.module,
            "message": record.getMessage(),
        }
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry)


class ColorFormatter(logging.Formatter):
    """Human-friendly colored console output."""
    COLORS = {
        "DEBUG":    "\033[36m",   # Cyan
        "INFO":     "\033[32m",   # Green
        "WARNING":  "\033[33m",   # Yellow
        "ERROR":    "\033[31m",   # Red
        "CRITICAL": "\033[35m",   # Magenta
    }
    RESET = "\033[0m"

    def format(self, record):
        color = self.COLORS.get(record.levelname, "")
        record.levelname = f"{color}{record.levelname:<8}{self.RESET}"
        return super().format(record)


def setup_logger(
    verbose: bool = False,
    quiet: bool = False,
    log_file: str = None,
    json_format: bool = False,
) -> logging.Logger:
    """
    Configure the 'omnifuzz' logger.

    Args:
        verbose:     DEBUG level — print every payload sent/received.
        quiet:       WARNING level — suppress info/progress output.
        log_file:    Also write full logs to this file path.
        json_format: Emit structured JSON instead of human-readable lines.
    """
    if verbose:
        level = logging.DEBUG
    elif quiet:
        level = logging.WARNING
    else:
        level = logging.INFO

    root = logging.getLogger("omnifuzz")
    root.setLevel(level)
    root.handlers = []  # Reset handlers on reconfiguration

    # Console handler
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(level)
    if json_format:
        console.setFormatter(JsonFormatter())
    else:
        fmt = ColorFormatter(
            "%(asctime)s %(levelname)s %(name)s — %(message)s",
            datefmt="%H:%M:%S",
        )
        console.setFormatter(fmt)
    root.addHandler(console)

    # Optional file handler — always full DEBUG detail
    if log_file:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        if json_format:
            fh.setFormatter(JsonFormatter())
        else:
            fh.setFormatter(
                logging.Formatter("%(asctime)s - %(levelname)s - %(name)s - %(message)s")
            )
        root.addHandler(fh)

    return root


# Module-level convenience reference
logger = logging.getLogger("omnifuzz")
