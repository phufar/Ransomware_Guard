import time
import os
import logging
import threading
import queue
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from .EntropyCalculator import EntropyCalculator
from .MagicBytesDetector import MagicBytesDetector

# Get logger for this module
logger = logging.getLogger("ransomware_guard.monitor")

# --- CONFIGURATION ---
# Extensions to ignore (Temporary files, System files, Logs)
IGNORED_EXTENSIONS = {'.tmp', '.log', '.ini', '.dll', '.sys', '.pyc', '.part', '.crdownload', '.so', '.swp'}
# Directories to ignore to prevent system instability (Linux-compatible)
IGNORED_DIRS = {
    # Linux system directories
    '/proc', '/sys', '/dev', '/run', '/snap',
    '/var/log', '/var/cache', '/var/tmp',
    '/tmp', '/lost+found',
    # User cache/config directories
    '.cache', '.local/share/Trash', '.mozilla', '.config/google-chrome',
    # Package managers
    'node_modules', '__pycache__', '.git', '.venv', 'venv',
    # IDE/Editor directories
    '.vscode', '.idea',
}
MAX_QUEUE_SIZE = 1000
DEBOUNCE_SECONDS = 1.0  # Time window to ignore repeated events for the same file

class FileMonitor:
    """
    High-Performance File System Monitor.
    Uses a Producer-Consumer pattern (Queue + Worker Thread) to prevent 
    blocking the Watchdog observer during intense file operations.
    
    CRITICAL FIX: Now tracks processes IMMEDIATELY when file events occur,
    before the file handle is closed.
    """
    def __init__(self, path_to_watch, callback_alert=None, process_monitor=None):
        self.path_to_watch = path_to_watch
        self.callback_alert = callback_alert  # Function to call when ransomware is detected
        self.process_monitor = process_monitor  # CRITICAL: For immediate process tracking
        
        self.observer = Observer()
        self.event_queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)
        self.calculator = EntropyCalculator(threshold=7.5)
        self.magic_detector = MagicBytesDetector()  # For false positive reduction
        self.running = False
        
        # Dictionary for Debouncing (prevents analyzing the same file multiple times per second)
        self.last_checked = {} 
        self.worker_thread = None

    def start(self):
        """Starts the monitoring process and the analysis worker thread."""
        self.running = True
        
        # 1. Start Watchdog (The Producer)
        # CRITICAL FIX: Pass process_monitor to handler for immediate tracking
        event_handler = MonitorHandler(self.event_queue, self.process_monitor)
        self.observer.schedule(event_handler, self.path_to_watch, recursive=True)
        self.observer.start()
        
        # 2. Start Worker Thread (The Consumer)
        # Daemon thread ensures it closes when the main app closes
        self.worker_thread = threading.Thread(target=self._analysis_worker, daemon=True)
        self.worker_thread.start()
        
        logger.info(f"Monitor started on: {self.path_to_watch}")

    def stop(self):
        """Stops the observer and worker thread safely."""
        self.running = False
        if self.observer.is_alive():
            self.observer.stop()
            self.observer.join()
        logger.info("Monitor stopped.")

    def _analysis_worker(self):
        """
        Background Worker: Consumes files from the queue and analyzes entropy.
        This prevents the main thread or UI from freezing.
        """
        while self.running:
            try:
                # Wait for a file from the queue (timeout allows checking self.running)
                file_path = self.event_queue.get(timeout=1)
                
                # --- PERFORMANCE CHECK: Debounce ---
                # Check if this file was recently analyzed
                current_time = time.time()
                if file_path in self.last_checked:
                    if current_time - self.last_checked[file_path] < DEBOUNCE_SECONDS:
                        self.event_queue.task_done()
                        continue # Skip: Analysis requested too frequently
                
                self.last_checked[file_path] = current_time
                
                # Cleanup cache occasionally to prevent memory leaks
                if len(self.last_checked) > 5000:
                    self.last_checked.clear()

                # --- PROCESS: Analyze the file ---
                self._analyze_file(file_path)
                
                self.event_queue.task_done()

            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Worker error: {e}")

    def _analyze_file(self, file_path):
        """Performs the actual entropy analysis using EntropyCalculator."""
        # 1. Quick check if file still exists (it might be a deleted temp file)
        if not os.path.exists(file_path):
            return
        
        # 2. Small delay to ensure file is fully written (prevents partial read)
        time.sleep(0.1)

        # 3. Analyze
        try:
            # Call the robust calculation method
            result = self.calculator.calculate_file_entropy(file_path)
            
            # Check for errors in result (EntropyCalculator handles exceptions internally)
            if result['status'] != 'ok':
                return

            if result['suspicious']:
                # --- MAGIC BYTES CHECK: Reduce false positives ---
                # If entropy is high, verify it's not a known file type
                # (images, videos, archives, etc. naturally have high entropy)
                magic_result = self.magic_detector.detect_file_type(file_path)
                
                if magic_result['naturally_high_entropy']:
                    logger.debug(
                        f"Skipped (known type): {os.path.basename(file_path)} "
                        f"(type: {magic_result['detected_type']}, entropy: {result['entropy']:.2f})"
                    )
                    return
                
                # Check for extension mismatch (possible ransomware disguise)
                mismatch = self.magic_detector.get_extension_mismatch(file_path)
                if mismatch:
                    logger.warning(
                        f"EXTENSION MISMATCH: {file_path} | "
                        f"ext='{mismatch['actual_extension']}' but detected as '{mismatch['detected_type']}'"
                    )

                logger.warning(f"THREAT DETECTED: {file_path} | Entropy: {result['entropy']:.4f}")
                
                # Trigger the callback (e.g., Update GUI or Kill Process)
                if self.callback_alert:
                    self.callback_alert(file_path, result['entropy'])
            else:
                logger.debug(f"Safe file: {os.path.basename(file_path)} (entropy: {result['entropy']:.2f})")

        except Exception as e:
            logger.error(f"Error analyzing {os.path.basename(file_path)}: {e}")

class MonitorHandler(FileSystemEventHandler):
    """
    Event Handler for Watchdog.
    Its ONLY job is to filter events and push them to the Queue immediately.
    
    CRITICAL FIX: Also tracks writing processes IMMEDIATELY before
    the file handle is closed. This is the key to reliable process detection.
    """
    def __init__(self, queue_instance, process_monitor=None):
        self.queue = queue_instance
        self.process_monitor = process_monitor  # For immediate process tracking

    def _process_event(self, event):
        if event.is_directory:
            return

        filename = event.src_path
        
        # --- FILTERING: Ignore noise ---
        # 1. Ignore Word/Excel temp lock files (~$Doc.docx)
        basename = os.path.basename(filename)
        if basename.startswith('~$'):
            return

        # 2. Ignore specific extensions
        ext = os.path.splitext(filename)[1].lower()
        if ext in IGNORED_EXTENSIONS:
            return
            
        # 3. Ignore specific system directories
        if any(ignored in filename for ignored in IGNORED_DIRS):
            return
        
        # CRITICAL FIX: Track the writing process IMMEDIATELY
        # This must happen BEFORE queuing, while file handle is still open!
        if self.process_monitor:
            try:
                self.process_monitor.track_file_write(filename)
            except Exception:
                pass  # Don't let tracking failures block event processing

        # Push to queue (Non-blocking)
        try:
            self.queue.put_nowait(filename)
        except queue.Full:
            pass # Drop event if queue is full to prevent freezing

    def on_modified(self, event):
        self._process_event(event)

    def on_created(self, event):
        self._process_event(event)
    
    def on_moved(self, event):
        if not event.is_directory:
            # Check the destination file (new name) - use dest_path, not src_path
            filename = event.dest_path
            
            # --- FILTERING: Ignore noise ---
            basename = os.path.basename(filename)
            if basename.startswith('~$'):
                return
            ext = os.path.splitext(filename)[1].lower()
            if ext in IGNORED_EXTENSIONS:
                return
            if any(ignored in filename for ignored in IGNORED_DIRS):
                return
            
            # CRITICAL FIX: Track the writing process IMMEDIATELY on move events too
            if self.process_monitor:
                try:
                    self.process_monitor.track_file_write(filename)
                except Exception:
                    pass
            
            try:
                self.queue.put_nowait(filename)
            except queue.Full:
                pass

# --- Test Execution (Run this file directly to test) ---
if __name__ == "__main__":
    def test_alert_callback(file, entropy):
        print(f"!!! ALERT CALLBACK TRIGGERED !!! -> File: {file}, Entropy: {entropy:.2f}")

    # Create monitor for current directory
    print("Initializing Monitor...")
    monitor = FileMonitor(".", callback_alert=test_alert_callback)
    
    try:
        monitor.start()
        print("Monitor is running. Press Ctrl+C to stop.")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        monitor.stop()