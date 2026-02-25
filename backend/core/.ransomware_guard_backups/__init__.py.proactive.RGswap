# Ransomware Guard - Core Package
# eBPF-based ransomware detection with backup and process termination

from .EntropyCalculator import EntropyCalculator
from .FileMonitor import FileMonitor
from .ProcessMonitor import ProcessMonitor, create_alert_callback
from .MagicBytesDetector import MagicBytesDetector
from .BackupManager import BackupManager
from .logger import setup_logging, get_logger

# Optional: eBPF monitor (requires Linux + root + BCC)
try:
    from .EBPFMonitor import EBPFMonitor, EBPFFileEvent
except ImportError:
    EBPFMonitor = None
    EBPFFileEvent = None

__version__ = "2.0.0"
__all__ = [
    'EntropyCalculator',
    'FileMonitor',
    'ProcessMonitor',
    'MagicBytesDetector',
    'BackupManager',
    'EBPFMonitor',
    'EBPFFileEvent',
    'create_alert_callback',
    'setup_logging',
    'get_logger',
]
