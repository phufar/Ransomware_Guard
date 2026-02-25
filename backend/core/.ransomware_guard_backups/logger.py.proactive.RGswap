"""
Logging Configuration for Ransomware Guard
Centralized logging setup for all modules.
"""

import logging
import os
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
