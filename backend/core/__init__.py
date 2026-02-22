# Ransomware Guard - Python Package
# Entropy-based ransomware detection and process termination

from .EntropyCalculator import EntropyCalculator
from .FileMonitor import FileMonitor
from .ProcessMonitor import ProcessMonitor, create_alert_callback
from .MagicBytesDetector import MagicBytesDetector
from .logger import setup_logging, get_logger

__version__ = "1.1.0"
__all__ = [
    'EntropyCalculator', 
    'FileMonitor', 
    'ProcessMonitor', 
    'MagicBytesDetector',
    'create_alert_callback',
    'setup_logging',
    'get_logger'
]
