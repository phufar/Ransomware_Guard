#!/usr/bin/env python3
"""
Ransomware Guard - Main Application
Combines all modules: EntropyCalculator, FileMonitor, ProcessMonitor

Usage:
    sudo python3 main.py /path/to/protect

Note: Running with sudo is recommended for process termination capabilities.
"""

import sys
import time
import argparse
import signal
import logging
from pathlib import Path

from core.EntropyCalculator import EntropyCalculator
from core.FileMonitor import FileMonitor
from core.ProcessMonitor import ProcessMonitor, create_alert_callback
from core.logger import setup_logging, get_main_logger


class RansomwareGuard:
    """Main Ransomware Guard Application."""
    
    def __init__(self, watch_path: str, entropy_threshold: float = 7.5, test_mode: bool = False):
        self.watch_path = Path(watch_path).resolve()
        self.logger = get_main_logger()
        self.test_mode = test_mode
        
        # Initialize modules
        self.entropy_calculator = EntropyCalculator(threshold=entropy_threshold)
        self.process_monitor = ProcessMonitor(test_mode=test_mode)  # Pass test_mode
        
        # CRITICAL FIX: Pass process_monitor for immediate file writer tracking
        self.file_monitor = FileMonitor(
            str(self.watch_path),
            callback_alert=create_alert_callback(self.process_monitor),
            process_monitor=self.process_monitor  # Enable immediate process tracking
        )
        
        self.running = False
        self.stats = {
            'files_scanned': 0,
            'threats_detected': 0,
            'processes_terminated': 0
        }
    
    def start(self):
        """Start the ransomware guard."""
        self.logger.info("=" * 60)
        self.logger.info("RANSOMWARE GUARD - Active Protection")
        self.logger.info("=" * 60)
        self.logger.info(f"  Monitoring: {self.watch_path}")
        self.logger.info(f"  Entropy Threshold: {self.entropy_calculator.threshold}")
        self.logger.info(f"  Protected Processes: {len(self.process_monitor.PROTECTED_PROCESSES)}")
        self.logger.info(f"  Trusted Applications: {len(self.process_monitor.TRUSTED_APPLICATIONS)}")
        if self.test_mode:
            self.logger.warning("  TEST MODE: Trusted applications will NOT be protected!")
        self.logger.info("=" * 60)
        self.logger.info("Guard is ACTIVE. Press Ctrl+C to stop.")
        
        self.running = True
        self.file_monitor.start()
        
        # Handle graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        try:
            while self.running:
                time.sleep(1)
                self._update_stats()
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()
    
    def stop(self):
        """Stop the ransomware guard."""
        self.running = False
        self.file_monitor.stop()
        self.logger.info("=" * 60)
        self.logger.info("RANSOMWARE GUARD - Stopped")
        self.logger.info("=" * 60)
        self._print_summary()
    
    def _signal_handler(self, signum, frame):
        """Handle termination signals."""
        self.running = False
    
    def _update_stats(self):
        """Update statistics from action log."""
        action_log = self.process_monitor.get_action_log()
        self.stats['threats_detected'] = len(action_log)
        self.stats['processes_terminated'] = sum(
            1 for a in action_log if a.get('success', False)
        )
    
    def _print_summary(self):
        """Print session summary."""
        action_log = self.process_monitor.get_action_log()
        
        self.logger.info(f"Session Summary:")
        self.logger.info(f"  Threats Detected: {self.stats['threats_detected']}")
        self.logger.info(f"  Processes Terminated: {self.stats['processes_terminated']}")
        
        if action_log:
            self.logger.info("Recent Actions:")
            for action in action_log[-5:]:  # Show last 5 actions
                status = "SUCCESS" if action.get('success') else "FAILED"
                self.logger.info(f"  [{status}] PID {action.get('pid')}: {action.get('message')}")
        
        self.logger.info("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="Ransomware Guard - Entropy-based ransomware detection and prevention",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python3 main.py /home/user/Documents
    sudo python3 main.py /home/user --threshold 7.0
    
Note: Running with sudo enables process termination capabilities.
        """
    )
    
    parser.add_argument(
        'path',
        type=str,
        help='Directory path to monitor for ransomware activity'
    )
    
    parser.add_argument(
        '-t', '--threshold',
        type=float,
        default=7.5,
        help='Entropy threshold for detection (default: 7.5, range: 0-8)'
    )
    
    parser.add_argument(
        '-l', '--log-level',
        type=str,
        default='INFO',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        help='Logging level (default: INFO)'
    )
    
    parser.add_argument(
        '--no-log-file',
        action='store_true',
        help='Disable logging to file'
    )
    
    parser.add_argument(
        '--test-mode',
        action='store_true',
        help='Test mode: Ignores TRUSTED_APPLICATIONS list (allows terminating python, etc.)'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(
        log_level=args.log_level,
        log_to_file=not args.no_log_file
    )
    
    # Validate path
    watch_path = Path(args.path)
    if not watch_path.exists():
        print(f"Error: Path does not exist: {args.path}")
        sys.exit(1)
    
    if not watch_path.is_dir():
        print(f"Error: Path is not a directory: {args.path}")
        sys.exit(1)
    
    # Validate threshold
    if not 0 <= args.threshold <= 8:
        print(f"Error: Threshold must be between 0 and 8")
        sys.exit(1)
    
    # Start the guard
    guard = RansomwareGuard(args.path, args.threshold, test_mode=args.test_mode)
    guard.start()


if __name__ == "__main__":
    main()
