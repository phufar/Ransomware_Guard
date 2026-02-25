"""
FileMonitor - Unified File System Monitor for Ransomware Guard

Monitoring strategy (automatic selection):
    1. eBPF (primary)   - Kernel-level hooks via kprobes on vfs_write().
                          Requires Linux + root + BCC. Provides PID instantly.
    2. Watchdog (fallback) - User-space inotify/FSEvents via watchdog library.
                          Works on any OS, no root needed.

Detection pipeline (SIGSTOP-first strategy):
    1. File write detected (eBPF or Watchdog)
    2. IMMEDIATELY freeze the writing process (SIGSTOP) — prevents further damage
    3. Analyze entropy of the modified file (EntropyCalculator)
    4. Check magic bytes to reduce false positives (MagicBytesDetector)
    5. If entropy >= threshold (ransomware):
       a. Kill the frozen process (SIGKILL)
       b. Restore the file from PROACTIVE backup (pre-write copy)
    6. If entropy is normal (safe):
       a. Resume the frozen process (SIGCONT)
       b. Update proactive backup with new file state

Proactive Backup System:
    - On startup, scans watched directory and backs up all existing files
    - Periodic refresh ensures new files get backed up before modification
    - When ransomware is detected, restores from the PRE-WRITE backup
      (not the post-modification copy, which would be the encrypted version)
"""

import time
import os
import signal
import logging
import threading
import queue
from typing import Optional, Callable, Set

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
PROACTIVE_BACKUP_INTERVAL = 300  # Seconds between proactive backup scans
PROACTIVE_BACKUP_MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB limit


class FileMonitor:
    """
    Unified file system monitor with eBPF primary and Watchdog fallback.

    On start(), automatically tries eBPF first (kernel-level, gets PID
    directly). If eBPF is unavailable (no root, no BCC, not Linux),
    falls back to Watchdog (inotify/FSEvents).

    Key improvements over naive approach:
        - SIGSTOP-first: freezes suspicious processes BEFORE analysis
        - Proactive backups: maintains pre-write copies for reliable restore
        - Interpreter detection: python/node/java are NOT trusted
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
        self._proactive_backup_thread = None
        self._running = False

        # Debounce: prevent analyzing the same file repeatedly
        self._last_checked = {}

        # SIGSTOP tracking: PIDs currently frozen for analysis
        self._frozen_pids: Set[int] = set()
        self._frozen_lock = threading.Lock()

    def start(self):
        """
        Start monitoring. Tries eBPF first, falls back to Watchdog.

        Startup sequence:
            1. Run proactive backup scan of watched directory
            2. Start eBPF or Watchdog backend
            3. Start analysis worker thread
            4. Start periodic proactive backup thread
        """
        self._running = True

        # --- Step 1: Proactive backup scan ---
        logger.info(f"Running initial proactive backup scan: {self.path_to_watch}")
        self._run_proactive_backup_scan()

        # --- Step 2: Try eBPF first ---
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

        # Start periodic proactive backup thread
        self._proactive_backup_thread = threading.Thread(
            target=self._proactive_backup_worker, daemon=True,
            name="proactive-backup-worker"
        )
        self._proactive_backup_thread.start()

    def stop(self):
        """Stop all monitoring and cleanup resources."""
        self._running = False

        # Resume any frozen processes before shutdown
        self._resume_all_frozen()

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
    # SIGSTOP-First Process Freezing
    # ------------------------------------------------------------------

    def _freeze_process(self, pid: int) -> bool:
        """
        Freeze a process via SIGSTOP to prevent further writes during analysis.

        This is the core of the SIGSTOP-first strategy: we freeze the
        process immediately when a suspicious write is detected, then
        analyze the file. If safe, we resume (SIGCONT). If malicious,
        we kill (SIGKILL).

        Args:
            pid: Process ID to freeze

        Returns:
            True if successfully frozen
        """
        if pid is None or pid <= 1:
            return False

        # Don't freeze our own process
        if pid == os.getpid():
            return False

        # Don't freeze already-frozen processes
        with self._frozen_lock:
            if pid in self._frozen_pids:
                return True

        # Don't freeze protected system processes
        if self.process_monitor:
            try:
                import psutil
                proc = psutil.Process(pid)
                proc_name = proc.name().lower()
                # Quick check against system-critical processes
                if proc_name in self.process_monitor.PROTECTED_PROCESSES:
                    logger.debug(f"Skipped freezing protected process: {proc_name} (PID: {pid})")
                    return False
            except Exception:
                pass

        try:
            os.kill(pid, signal.SIGSTOP)
            with self._frozen_lock:
                self._frozen_pids.add(pid)
            logger.info(f"Process frozen (SIGSTOP): PID {pid}")
            return True
        except ProcessLookupError:
            logger.debug(f"Cannot freeze PID {pid}: process no longer exists")
            return False
        except PermissionError:
            logger.warning(f"Cannot freeze PID {pid}: permission denied")
            return False
        except OSError as e:
            logger.error(f"Error freezing PID {pid}: {e}")
            return False

    def _resume_process(self, pid: int) -> bool:
        """
        Resume a frozen process via SIGCONT (file was safe).

        Args:
            pid: Process ID to resume

        Returns:
            True if successfully resumed
        """
        if pid is None:
            return False

        with self._frozen_lock:
            if pid not in self._frozen_pids:
                return False

        try:
            os.kill(pid, signal.SIGCONT)
            with self._frozen_lock:
                self._frozen_pids.discard(pid)
            logger.info(f"Process resumed (SIGCONT): PID {pid}")
            return True
        except ProcessLookupError:
            with self._frozen_lock:
                self._frozen_pids.discard(pid)
            return False
        except OSError as e:
            logger.error(f"Error resuming PID {pid}: {e}")
            return False

    def _resume_all_frozen(self):
        """Resume all frozen processes (called during shutdown)."""
        with self._frozen_lock:
            pids = list(self._frozen_pids)

        for pid in pids:
            self._resume_process(pid)

    # ------------------------------------------------------------------
    # Proactive Backup System
    # ------------------------------------------------------------------

    def _run_proactive_backup_scan(self):
        """
        Walk the watched directory and create proactive backups of all
        existing files. This ensures we have pre-write copies before
        any ransomware can modify them.
        """
        count = 0
        try:
            for root, dirs, files in os.walk(self.path_to_watch):
                if not self._running:
                    break

                # Skip ignored directories
                dirs[:] = [d for d in dirs
                           if not any(ign in os.path.join(root, d)
                                      for ign in IGNORED_DIRS)]

                for filename in files:
                    if not self._running:
                        break

                    filepath = os.path.join(root, filename)

                    # Skip ignored files
                    if self._should_ignore(filepath):
                        continue

                    # Skip files that are too large
                    try:
                        if os.path.getsize(filepath) > PROACTIVE_BACKUP_MAX_FILE_SIZE:
                            continue
                    except OSError:
                        continue

                    # Create proactive backup
                    if self.backup_manager.maintain_proactive_backup(filepath):
                        count += 1

        except Exception as e:
            logger.error(f"Proactive backup scan error: {e}")

        logger.info(f"Proactive backup scan complete: {count} files backed up")

    def _proactive_backup_worker(self):
        """
        Periodically refresh proactive backups for new/changed files.
        Runs every PROACTIVE_BACKUP_INTERVAL seconds.
        """
        while self._running:
            # Sleep in small increments so we can respond to stop()
            for _ in range(PROACTIVE_BACKUP_INTERVAL):
                if not self._running:
                    return
                time.sleep(1)

            if self._running:
                logger.debug("Running periodic proactive backup refresh")
                self._run_proactive_backup_scan()

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

        SIGSTOP-first: immediately freezes the writing process before
        queueing the file for entropy analysis.

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

        # eBPF provides full path if available (from dentry walk),
        # otherwise falls back to basename resolution.
        full_path = None
        if hasattr(event, 'fullpath') and event.fullpath:
            candidate = event.fullpath
            if candidate.startswith(self.path_to_watch):
                full_path = candidate

        if not full_path:
            full_path = self._resolve_ebpf_path(filename, event.pid)

        if not full_path:
            return

        # SIGSTOP-first: freeze the writing process immediately
        self._freeze_process(event.pid)

        # Queue for analysis with PID info from eBPF
        try:
            self._event_queue.put_nowait((full_path, event.pid, event.process_name))
        except queue.Full:
            # If queue is full, resume the process — we can't analyze it
            self._resume_process(event.pid)

    def _resolve_ebpf_path(self, basename: str, pid: int) -> str:
        """
        Resolve an eBPF basename to a full file path.

        eBPF captures filenames from kernel dentry which are basenames only
        (e.g., 'document.docx' not '/home/user/document.docx').

        Resolution strategy:
            1. Try /proc/<pid>/fd - read symlinks to find the actual open file
            2. Try /proc/<pid>/cwd + basename
            3. Search the watched directory for the basename (last resort)

        Args:
            basename: Filename from eBPF dentry (basename only)
            pid:      PID of the writing process

        Returns:
            Full file path, or None if not resolved within watch directory.
        """
        # Strategy 1: Check /proc/<pid>/fd for open file descriptors
        try:
            proc_fd_dir = f"/proc/{pid}/fd"
            if os.path.isdir(proc_fd_dir):
                for fd in os.listdir(proc_fd_dir):
                    try:
                        link = os.readlink(os.path.join(proc_fd_dir, fd))
                        if (link.startswith(self.path_to_watch) and
                                os.path.basename(link) == basename):
                            return link
                    except (OSError, PermissionError):
                        continue
        except (OSError, PermissionError):
            pass

        # Strategy 2: Try /proc/<pid>/cwd + basename
        try:
            cwd_link = os.readlink(f"/proc/{pid}/cwd")
            candidate = os.path.join(cwd_link, basename)
            if (candidate.startswith(self.path_to_watch) and
                    os.path.exists(candidate)):
                return candidate
        except (OSError, PermissionError):
            pass

        # Strategy 3: Search the watched directory for the basename
        # Use os.walk with a depth limit to avoid scanning too deep
        try:
            for root, dirs, files in os.walk(self.path_to_watch):
                # Skip ignored directories
                dirs[:] = [d for d in dirs
                           if not any(ign in os.path.join(root, d)
                                      for ign in IGNORED_DIRS)]
                if basename in files:
                    return os.path.join(root, basename)
                # Limit search depth (max 5 levels)
                depth = root[len(self.path_to_watch):].count(os.sep)
                if depth >= 5:
                    dirs.clear()
        except (OSError, PermissionError):
            pass

        return None

    # ------------------------------------------------------------------
    # Watchdog Backend (fallback)
    # ------------------------------------------------------------------

    def _start_watchdog(self):
        """Start Watchdog observer for inotify/FSEvents monitoring."""
        self._observer = Observer()
        handler = _WatchdogHandler(self._event_queue, self.process_monitor, self)
        self._observer.schedule(handler, self.path_to_watch, recursive=True)
        self._observer.start()

    # ------------------------------------------------------------------
    # Shared Analysis Pipeline
    # ------------------------------------------------------------------

    def _analysis_worker(self):
        """
        Background worker: consumes file events from both eBPF and Watchdog,
        runs the freeze -> entropy -> kill/resume pipeline.

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
                        # Resume if we froze this process
                        if pid:
                            self._resume_process(pid)
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

        SIGSTOP-first strategy:
            - Process is ALREADY frozen (SIGSTOP) when we get here
            - We analyze the file while the process can't do more damage
            - If safe: SIGCONT to resume the process
            - If malicious: SIGKILL + restore from proactive backup

        Steps:
            1. Calculate entropy (process already frozen)
            2. Check magic bytes (reduce false positives)
            3. If suspicious: kill process + restore from PROACTIVE backup
            4. If safe: resume process + update proactive backup

        Args:
            file_path:    Path to the modified file
            pid:          PID from eBPF (None if from Watchdog)
            process_name: Process name from eBPF (None if from Watchdog)
        """
        if not os.path.exists(file_path):
            if pid:
                self._resume_process(pid)
            return

        try:
            # Step 1: Calculate entropy (process is frozen, can't write more)
            result = self.calculator.calculate_file_entropy(file_path)

            if result['status'] != 'ok':
                # Analysis failed — resume process, keep proactive backup
                if pid:
                    self._resume_process(pid)
                return

            if result['suspicious']:
                # Step 2: Check magic bytes to reduce false positives
                magic_result = self.magic_detector.detect_file_type(file_path)

                if magic_result['naturally_high_entropy']:
                    # Known file type with naturally high entropy (images, etc.)
                    logger.debug(
                        f"Skipped (known type): {os.path.basename(file_path)} "
                        f"(type: {magic_result['detected_type']}, "
                        f"entropy: {result['entropy']:.2f})"
                    )
                    # Safe — resume the process
                    if pid:
                        self._resume_process(pid)
                    # Update proactive backup with new state
                    self.backup_manager.maintain_proactive_backup(file_path)
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

                # Step 3a: Kill the responsible process (already frozen)
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
                elif pid:
                    # No process monitor — just kill directly
                    try:
                        os.kill(pid, signal.SIGKILL)
                        logger.info(f"Process killed directly: PID {pid}")
                    except OSError:
                        pass

                # Remove from frozen set (it's been killed)
                with self._frozen_lock:
                    self._frozen_pids.discard(pid)

                # Step 3b: Restore file from PROACTIVE backup (pre-write copy)
                proactive_backup = self.backup_manager.get_proactive_backup(file_path)
                if proactive_backup:
                    # Use proactive backup — this is the PRE-MODIFICATION copy
                    try:
                        import shutil
                        shutil.copy2(proactive_backup, file_path)
                        logger.info(f"File restored from PROACTIVE backup: {file_path}")
                    except Exception as e:
                        logger.error(f"Proactive restore failed: {e}")
                        # Fallback: try reactive backup
                        restored = self.backup_manager.restore_backup(file_path)
                        if restored:
                            logger.info(f"File restored from reactive backup: {file_path}")
                        else:
                            logger.error(f"Failed to restore: {file_path}")
                else:
                    logger.warning(
                        f"No proactive backup for {file_path} — "
                        f"file may not be recoverable"
                    )

                # Trigger alert callback (for API/WebSocket broadcast)
                if self.callback_alert:
                    self.callback_alert(file_path, result['entropy'])

            else:
                # Step 4: Entropy is normal — resume the frozen process
                if pid:
                    self._resume_process(pid)

                # Update proactive backup with new (safe) file state
                self.backup_manager.maintain_proactive_backup(file_path)

                logger.debug(
                    f"Safe file: {os.path.basename(file_path)} "
                    f"(entropy: {result['entropy']:.2f})"
                )

        except Exception as e:
            logger.error(f"Error analyzing {os.path.basename(file_path)}: {e}")
            # On error, resume the process to avoid leaving it frozen
            if pid:
                self._resume_process(pid)

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
    Also tracks writing processes immediately via ProcessMonitor
    and freezes them via SIGSTOP for the analysis pipeline.
    """

    def __init__(self, event_queue: queue.Queue, process_monitor=None,
                 file_monitor=None):
        self._queue = event_queue
        self._process_monitor = process_monitor
        self._file_monitor = file_monitor

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
        writer_pid = None
        if self._process_monitor:
            try:
                self._process_monitor.track_file_write(filename)
                # Try to get the writer's PID for SIGSTOP
                cached = self._process_monitor.get_cached_writer(filename)
                if cached:
                    writer_pid = cached.pid
            except Exception:
                pass

        # SIGSTOP-first: freeze the writer if identified
        if writer_pid and self._file_monitor:
            self._file_monitor._freeze_process(writer_pid)

        # Queue for analysis (pid from cache, process_name=None for Watchdog)
        try:
            self._queue.put_nowait((filename, writer_pid, None))
        except queue.Full:
            # Can't analyze — resume the process
            if writer_pid and self._file_monitor:
                self._file_monitor._resume_process(writer_pid)

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

        writer_pid = None
        if self._process_monitor:
            try:
                self._process_monitor.track_file_write(filename)
                cached = self._process_monitor.get_cached_writer(filename)
                if cached:
                    writer_pid = cached.pid
            except Exception:
                pass

        if writer_pid and self._file_monitor:
            self._file_monitor._freeze_process(writer_pid)

        try:
            self._queue.put_nowait((filename, writer_pid, None))
        except queue.Full:
            if writer_pid and self._file_monitor:
                self._file_monitor._resume_process(writer_pid)


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