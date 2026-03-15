"""
Logging Configuration for Ransomware Guard
Centralized logging setup for all modules.
Includes structured event logging (What/Who/When/Where) for detection decisions.
"""

import logging
import os
import json
from pathlib import Path
from datetime import datetime


def setup_logging(
    log_level: str = "INFO",
    log_to_file: bool = True,
    log_dir: str = None,
    log_filename: str = None
) -> logging.Logger:
    """
    Setup logging configuration for Ransomware Guard.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_to_file: Whether to also log to a file
        log_dir: Directory for log files (default: ./logs)
        log_filename: Custom log filename (default: ransomware_guard_YYYYMMDD.log)
    
    Returns:
        Root logger instance
    """
    # Create logger
    logger = logging.getLogger("ransomware_guard")
    
    # Avoid adding handlers multiple times
    if logger.handlers:
        return logger
    
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    
    # Log format
    formatter = logging.Formatter(
        fmt='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.INFO)
    logger.addHandler(console_handler)
    
    # File handler (optional)
    if log_to_file:
        if log_dir is None:
            log_dir = Path(__file__).parent.parent / "logs"
        else:
            log_dir = Path(log_dir)
        
        log_dir.mkdir(parents=True, exist_ok=True)
        
        if log_filename is None:
            date_str = datetime.now().strftime("%Y%m%d")
            log_filename = f"ransomware_guard_{date_str}.log"
        
        log_path = log_dir / log_filename
        
        file_handler = logging.FileHandler(log_path, encoding='utf-8')
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.DEBUG)  # File gets all levels
        logger.addHandler(file_handler)
        
        logger.info(f"Logging to file: {log_path}")
    
    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Get a child logger for a specific module.
    
    Args:
        name: Module name (e.g., 'entropy', 'monitor', 'process')
    
    Returns:
        Logger instance
    """
    return logging.getLogger(f"ransomware_guard.{name}")


# Convenience loggers for each module
def get_entropy_logger() -> logging.Logger:
    return get_logger("entropy")

def get_monitor_logger() -> logging.Logger:
    return get_logger("monitor")

def get_process_logger() -> logging.Logger:
    return get_logger("process")

def get_main_logger() -> logging.Logger:
    return get_logger("main")


# ---------------------------------------------------------------------------
# Structured Detection Event Logger (What / Who / When / Where)
# ---------------------------------------------------------------------------

# Dedicated logger for detection events — writes to a separate log file
_event_logger = None


def _get_event_logger() -> logging.Logger:
    """
    Lazily initialize the detection event logger.
    Writes structured JSON lines to `logs/detection_events.log`.
    """
    global _event_logger
    if _event_logger is not None:
        return _event_logger

    _event_logger = logging.getLogger("ransomware_guard.events")
    _event_logger.setLevel(logging.INFO)
    _event_logger.propagate = False  # Don't duplicate into main log

    log_dir = Path(__file__).parent.parent / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    handler = logging.FileHandler(
        log_dir / "detection_events.log", encoding="utf-8"
    )
    handler.setFormatter(logging.Formatter("%(message)s"))
    _event_logger.addHandler(handler)

    return _event_logger


def log_event(
    what: str,
    who_pid: int = None,
    who_process: str = None,
    where: str = None,
    decision: str = None,
    entropy: float = None,
    base64_encoded: bool = None,
    details: dict = None,
):
    """
    Write a structured detection event to `logs/detection_events.log`.

    Called after the pipeline decides whether a process is safe or a threat.
    Each line is a JSON object with standardized fields:

        WHAT     — what happened (e.g. "THREAT_DETECTED", "FILE_SAFE")
        WHO      — PID and process name
        WHEN     — ISO-8601 timestamp
        WHERE    — file path involved
        DECISION — "safe" | "threat" | "frozen" | "killed" | "restored"
        ENTROPY  — entropy score (if applicable)

    Args:
        what:           Event type string
        who_pid:        PID of the writing process
        who_process:    Name of the writing process
        where:          File path involved
        decision:       Pipeline decision (safe / threat / frozen / killed / restored)
        entropy:        Entropy value at decision time
        base64_encoded: Whether base64 decoding was applied
        details:        Any additional context dict
    """
    event = {
        "what": what,
        "who": {
            "pid": who_pid,
            "process": who_process or "unknown",
        },
        "when": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "where": where,
        "decision": decision,
    }

    if entropy is not None:
        event["entropy"] = round(entropy, 4)

    if base64_encoded is not None:
        event["base64_encoded"] = base64_encoded

    if details:
        event["details"] = details

    logger = _get_event_logger()
    logger.info(json.dumps(event, ensure_ascii=False))
