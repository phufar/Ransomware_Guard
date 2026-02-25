"""
FileMonitor - Unified File System Monitor for Ransomware Guard

Monitoring strategy (automatic selection):
    1. eBPF (primary)   - Kernel-level hooks via kprobes on vfs_write().
                          Requires Linux + root + BCC. Provides PID instantly.
    2. Watchdog (fallback) - User-space inotify/FSEvents via watchdog library.
                          Works on any OS, no root needed.

When a file modification is detected (by either backend):
    1. Create backup of the original file (BackupManager)
    2. Analyze entropy of the modified file (EntropyCalculator)
    3. Check magic bytes to reduce false positives (MagicBytesDetector)
    4. If entropy >= threshold:
       a. Kill the responsible process (ProcessMonitor)
       b. Restore the file from backup
    5. If entropy is normal:
       a. Remove the backup (no threat)
"""

import time
import os
import logging
import threading
import queue
from typing import Optional, Callable

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from .EntropyCalculator import EntropyCalculator
from .MagicBytesDetector import MagicBytesDetector
from .BackupManager import BackupManager

# Conditional import: eBPF is only available on Linux with BCC
try:
    from .EBPFMonitor import EBPFMonitor, EBPFFileEvent, EVENT_WRITE
    EBPF_AVAILABLE = True
except ImportError:
    EBPF_AVAILABLE = False

logger = logging.getLogger("ransomware_guard.monitor")

# --- Configuration ---
IGNORED_EXTENSIONS = {
    '.tmp', '.log', '.ini', '.dll', '.sys', '.pyc',
    '.part', '.crdownload', '.so', '.swp',
}
IGNORED_DIRS = {
    '/proc', '/sys', '/dev', '/run', '/snap',
    '/var/log', '/var/cache', '/var/tmp', '/tmp', '/lost+found',
    '.cache', '.local/share/Trash', '.mozilla', '.config/google-chrome',
    'node_modules', '__pycache__', '.git', '.venv', 'venv',
    '.vscode', '.idea',
    '.ransomware_guard_backups',  # Skip our own backup directory
}
MAX_QUEUE_SIZE = 1000
DEBOUNCE_SECONDS = 1.0


class FileMonitor:
    """
    Unified file system monitor with eBPF primary and Watchdog fallback.

    On start(), automatically tries eBPF first (kernel-level, gets PID
    directly). If eBPF is unavailable (no root, no BCC, not Linux),
    falls back to Watchdog (inotify/FSEvents).

    Both backends feed into the same analysis pipeline:
        event -> backup -> entropy check -> kill or allow
    """

    def __init__(self, path_to_watch: str,
                 callback_alert: Optional[Callable] = None,
                 process_monitor=None,
                 entropy_threshold: float = 7.5):
        """
        Args:
            path_to_watch:     Directory to monitor recursively
            callback_alert:    Function(file_path, entropy) called on detection
            process_monitor:   ProcessMonitor instance for killing processes
            entropy_threshold: Entropy value above which a file is suspicious
        """
        self.path_to_watch = os.path.abspath(path_to_watch)
        self.callback_alert = callback_alert
        self.process_monitor = process_monitor

        # Analysis components
        self.calculator = EntropyCalculator(threshold=entropy_threshold)
        self.magic_detector = MagicBytesDetector()
        self.backup_manager = BackupManager()

        # Monitor backends
        self._ebpf_monitor = None
        self._observer = None         # Watchdog observer
        self.use_ebpf = False

        # Watchdog queue (producer-consumer pattern for non-blocking analysis)
        self._event_queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)
        self._worker_thread = None
        self._running = False

        # Debounce: prevent analyzing the same file repeatedly
        self._last_checked = {}

    def start(self):
        """
        Start monitoring. Tries eBPF first, falls back to Watchdog.

        eBPF path:
            1. Compile eBPF C program
            2. Attach kprobe to vfs_write()
            3. Kernel sends events via perf buffer -> _on_ebpf_event()

        Watchdog path:
            1. Start inotify observer (Linux) or FSEvents (macOS)
            2. Events go into queue -> _analysis_worker() processes them
        """
        self._running = True

        # --- Try eBPF first ---
        if EBPF_AVAILABLE and self._try_start_ebpf():
            self.use_ebpf = True
            logger.info(f"Monitor started (eBPF mode): {self.path_to_watch}")
        else:
            # --- Fallback to Watchdog ---
            self.use_ebpf = False
            self._start_watchdog()
            logger.info(f"Monitor started (Watchdog mode): {self.path_to_watch}")

        # Start analysis worker thread (used by both backends)
        self._worker_thread = threading.Thread(
            target=self._analysis_worker, daemon=True,
            name="file-analysis-worker"
        )
        self._worker_thread.start()

    def stop(self):
        """Stop all monitoring and cleanup resources."""
        self._running = False

        if self._ebpf_monitor:
            self._ebpf_monitor.stop()
            self._ebpf_monitor = None

        if self._observer and self._observer.is_alive():
            self._observer.stop()
            self._observer.join()

        logger.info(f"Monitor stopped | Backup stats: {self.backup_manager.get_stats()}")

    @property
    def running(self) -> bool:
        return self._running

    # ------------------------------------------------------------------
    # eBPF Backend
    # ------------------------------------------------------------------

    def _try_start_ebpf(self) -> bool:
        """
        Attempt to start eBPF monitoring.

        Returns True if eBPF started successfully.
        Returns False if not available (caller should use Watchdog).
        """
        try:
            self._ebpf_monitor = EBPFMonitor(
                callback=self._on_ebpf_event,
                watch_path=self.path_to_watch,
            )
            return self._ebpf_monitor.start()
        except Exception as e:
            logger.warning(f"eBPF start failed: {e}")
            return False

    def _on_ebpf_event(self, event: 'EBPFFileEvent'):
        """
        Callback from EBPFMonitor when kernel detects a file operation.

        The event contains PID and process name directly from the kernel,
        so we don't need to scan /proc to find the writer.

        Args:
            event: EBPFFileEvent with pid, process_name, filename, etc.
        """
        # We only analyze WRITE events for entropy
        if event.event_type != EVENT_WRITE:
            return

        filename = event.filename

        # Apply same filtering as Watchdog
        if self._should_ignore(filename):
            return

        # Queue for analysis with PID info from eBPF
        try:
            self._event_queue.put_nowait((filename, event.pid, event.process_name))
        except queue.Full:
            pass  # Drop event if queue is full

    # ------------------------------------------------------------------
    # Watchdog Backend (fallback)
    # ------------------------------------------------------------------

    def _start_watchdog(self):
        """Start Watchdog observer for inotify/FSEvents monitoring."""
        self._observer = Observer()
        handler = _WatchdogHandler(self._event_queue, self.process_monitor)
        self._observer.schedule(handler, self.path_to_watch, recursive=True)
        self._observer.start()

    # ------------------------------------------------------------------
    # Shared Analysis Pipeline
    # ------------------------------------------------------------------

    def _analysis_worker(self):
        """
        Background worker: consumes file events from both eBPF and Watchdog,
        runs the backup -> entropy -> kill/allow pipeline.

        Queue items:
            - From eBPF:    (filename, pid, process_name)
            - From Watchdog: (file_path, None, None)
        """
        while self._running:
            try:
                item = self._event_queue.get(timeout=1)

                if isinstance(item, tuple) and len(item) == 3:
                    file_path, pid, process_name = item
                else:
                    file_path = item
                    pid = None
                    process_name = None

                # Debounce: skip if analyzed recently
                now = time.time()
                if file_path in self._last_checked:
                    if now - self._last_checked[file_path] < DEBOUNCE_SECONDS:
                        self._event_queue.task_done()
                        continue
                self._last_checked[file_path] = now

                # Prevent memory leak in debounce cache
                if len(self._last_checked) > 5000:
                    self._last_checked.clear()

                # Run analysis pipeline
                self._analyze_file(file_path, pid=pid, process_name=process_name)
                self._event_queue.task_done()

            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Worker error: {e}")

    def _analyze_file(self, file_path: str,
                      pid: Optional[int] = None,
                      process_name: Optional[str] = None):
        """
        Full analysis pipeline for a modified file.

        Steps:
            1. Create backup of the current file state
            2. Wait briefly for write to complete
            3. Calculate entropy
            4. Check magic bytes (reduce false positives)
            5. If suspicious: kill process + restore backup
            6. If safe: remove backup

        Args:
            file_path:    Path to the modified file
            pid:          PID from eBPF (None if from Watchdog)
            process_name: Process name from eBPF (None if from Watchdog)
        """
        if not os.path.exists(file_path):
            return

        # Step 1: Create backup BEFORE analysis
        backup_path = self.backup_manager.create_backup(file_path)

        # Step 2: Small delay to ensure file write is complete
        time.sleep(0.1)

        try:
            # Step 3: Calculate entropy
            result = self.calculator.calculate_file_entropy(file_path)

            if result['status'] != 'ok':
                # Analysis failed - keep backup as safety net
                return

            if result['suspicious']:
                # Step 4: Check magic bytes to reduce false positives
                magic_result = self.magic_detector.detect_file_type(file_path)

                if magic_result['naturally_high_entropy']:
                    # Known file type with naturally high entropy (images, etc.)
                    logger.debug(
                        f"Skipped (known type): {os.path.basename(file_path)} "
                        f"(type: {magic_result['detected_type']}, "
                        f"entropy: {result['entropy']:.2f})"
                    )
                    # Remove backup - this is a safe file
                    self.backup_manager.remove_backup(file_path)
                    return

                # Check for extension mismatch (possible disguise)
                mismatch = self.magic_detector.get_extension_mismatch(file_path)
                if mismatch:
                    logger.warning(
                        f"EXTENSION MISMATCH: {file_path} | "
                        f"ext='{mismatch['actual_extension']}' "
                        f"but detected as '{mismatch['detected_type']}'"
                    )

                # ---- THREAT DETECTED ----
                logger.warning(
                    f"THREAT DETECTED: {file_path} | "
                    f"Entropy: {result['entropy']:.4f} | "
                    f"PID: {pid} | Process: {process_name}"
                )

                # Step 5a: Kill the responsible process
                if self.process_monitor and pid:
                    # eBPF path: use PID directly (no /proc scanning)
                    kill_result = self.process_monitor \
                        .handle_ransomware_alert_with_pid(
                            file_path, result['entropy'], pid
                        )
                    logger.info(f"Kill result: {kill_result}")
                elif self.process_monitor:
                    # Watchdog path: scan /proc to find the writer
                    self.process_monitor.handle_ransomware_alert(
                        file_path, result['entropy']
                    )

                # Step 5b: Restore file from backup
                if backup_path:
                    restored = self.backup_manager.restore_backup(file_path)
                    if restored:
                        logger.info(f"File restored: {file_path}")
                    else:
                        logger.error(f"Failed to restore: {file_path}")

                # Trigger alert callback (for API/WebSocket broadcast)
                if self.callback_alert:
                    self.callback_alert(file_path, result['entropy'])

            else:
                # Step 6: Entropy is normal - remove backup
                self.backup_manager.remove_backup(file_path)
                logger.debug(
                    f"Safe file: {os.path.basename(file_path)} "
                    f"(entropy: {result['entropy']:.2f})"
                )

        except Exception as e:
            logger.error(f"Error analyzing {os.path.basename(file_path)}: {e}")

    def _should_ignore(self, filename: str) -> bool:
        """Check if a file should be skipped based on extension or path."""
        basename = os.path.basename(filename)

        # Ignore temp lock files (~$file.docx)
        if basename.startswith('~$'):
            return True

        # Ignore specific extensions
        ext = os.path.splitext(filename)[1].lower()
        if ext in IGNORED_EXTENSIONS:
            return True

        # Ignore specific directories
        if any(ignored in filename for ignored in IGNORED_DIRS):
            return True

        return False


class _WatchdogHandler(FileSystemEventHandler):
    """
    Watchdog event handler (fallback when eBPF is not available).

    Filters file events and pushes them to the analysis queue.
    Also tracks writing processes immediately via ProcessMonitor.
    """

    def __init__(self, event_queue: queue.Queue, process_monitor=None):
        self._queue = event_queue
        self._process_monitor = process_monitor

    def _process_event(self, event):
        """Filter and queue a file system event."""
        if event.is_directory:
            return

        filename = event.src_path
        basename = os.path.basename(filename)

        # Filter noise
        if basename.startswith('~$'):
            return
        ext = os.path.splitext(filename)[1].lower()
        if ext in IGNORED_EXTENSIONS:
            return
        if any(d in filename for d in IGNORED_DIRS):
            return

        # Track the writing process immediately (before file handle closes)
        if self._process_monitor:
            try:
                self._process_monitor.track_file_write(filename)
            except Exception:
                pass

        # Queue for analysis (pid=None, process_name=None for Watchdog)
        try:
            self._queue.put_nowait((filename, None, None))
        except queue.Full:
            pass

    def on_modified(self, event):
        self._process_event(event)

    def on_created(self, event):
        self._process_event(event)

    def on_moved(self, event):
        if event.is_directory:
            return
        filename = event.dest_path
        basename = os.path.basename(filename)
        if basename.startswith('~$'):
            return
        ext = os.path.splitext(filename)[1].lower()
        if ext in IGNORED_EXTENSIONS:
            return
        if any(d in filename for d in IGNORED_DIRS):
            return

        if self._process_monitor:
            try:
                self._process_monitor.track_file_write(filename)
            except Exception:
                pass

        try:
            self._queue.put_nowait((filename, None, None))
        except queue.Full:
            pass


# --- Standalone test ---
if __name__ == "__main__":
    def test_alert(file, entropy):
        print(f"ALERT: {file} (entropy: {entropy:.2f})")

    print("Starting FileMonitor...")
    monitor = FileMonitor(".", callback_alert=test_alert)

    try:
        monitor.start()
        mode = "eBPF" if monitor.use_ebpf else "Watchdog"
        print(f"Running in {mode} mode. Press Ctrl+C to stop.")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        monitor.stop()