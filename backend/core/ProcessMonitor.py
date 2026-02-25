"""
ProcessMonitor - Process Identification and Termination Module
For Ransomware Guard: Terminates processes that write high-entropy files.
"""

import os
import logging
import psutil
import time
import threading
from typing import Optional, Dict, List, Set, Tuple
from dataclasses import dataclass
from enum import Enum

# Get logger for this module
logger = logging.getLogger("ransomware_guard.process")


class ProcessAction(Enum):
    """Actions that can be taken on a process."""
    NONE = "none"
    TERMINATE = "terminate"
    KILL = "kill"
    SUSPEND = "suspend"


@dataclass
class ProcessInfo:
    """Information about a detected process."""
    pid: int
    name: str
    exe: Optional[str]
    cmdline: List[str]
    username: Optional[str]
    create_time: float
    cpu_percent: float
    memory_percent: float


class ProcessMonitor:
    """
    Process Monitor for Ransomware Detection.
    Identifies processes accessing files and can terminate malicious ones.
    
    CRITICAL FIX: Uses a process tracking cache to capture file writers
    IMMEDIATELY when file events occur, before file handles are closed.
    """
    
    # System-critical processes that should NEVER be terminated (ALL LOWERCASE)
    PROTECTED_PROCESSES = {
        # Linux system processes
        'systemd', 'init', 'kthreadd', 'ksoftirqd', 'kworker',
        'rcu_sched', 'migration', 'watchdog', 'cpuhp',
        'netns', 'rcu_bh', 'lru-add-drain', 'writeback',
        'kcompactd', 'ksmd', 'khugepaged', 'crypto',
        'kintegrityd', 'kblockd', 'ata_sff', 'md', 'edac-poller',
        'devfreq_wq', 'kswapd', 'vmstat', 'ecryptfs-kthrea',
        # Desktop/Display (lowercase for consistent matching)
        'xorg', 'xwayland', 'gnome-shell', 'kwin', 'plasmashell',
        'gdm', 'sddm', 'lightdm',
        # Network (lowercase)
        'networkmanager', 'wpa_supplicant', 'dhclient', 'dnsmasq',
        # Audio
        'pulseaudio', 'pipewire', 'wireplumber',
        # System services
        'dbus-daemon', 'polkitd', 'rsyslogd', 'cron', 'atd',
        'sshd', 'cupsd', 'bluetoothd', 'udisksd',
        # Security
        'apparmor', 'auditd', 'selinux',
    }
    
    # Trusted applications (add yours here)
    TRUSTED_APPLICATIONS = {
        # Browsers (may create encrypted cache)
        'firefox', 'chrome', 'chromium', 'brave', 'opera',
        # Office applications
        'libreoffice', 'soffice.bin',
        # Archive tools (create compressed/encrypted files)
        'zip', 'unzip', 'gzip', 'bzip2', 'xz', '7z', 'tar',
        # Development tools
        'python', 'python3', 'node', 'npm', 'java', 'javac',
        'gcc', 'g++', 'clang', 'rustc', 'cargo', 'go',
        'code', 'code-oss', 'vscodium',  # VS Code
        # Package managers
        'apt', 'apt-get', 'dpkg', 'dnf', 'yum', 'pacman', 'snap',
        # Backup tools
        'rsync', 'borg', 'restic', 'duplicity',
    }
    
    def __init__(self, whitelist: Optional[Set[str]] = None, test_mode: bool = False):
        """
        Initialize ProcessMonitor.
        
        Args:
            whitelist: Additional process names to trust (won't be terminated)
            test_mode: If True, ignores TRUSTED_APPLICATIONS (for testing with python scripts)
        """
        self.whitelist = whitelist or set()
        self.test_mode = test_mode  # Allows terminating trusted apps in test mode
        self.terminated_pids: Dict[int, float] = {}  # Track terminated PIDs
        self.action_log: List[Dict] = []  # Log of all actions taken
        
        # CRITICAL FIX: Process tracking cache
        # Stores writers IMMEDIATELY when file events occur
        # Structure: { "/path/to/file": [(pid, name, timestamp), ...] }
        self.recent_file_writers: Dict[str, List[tuple]] = {}
        self._cache_lock = threading.Lock()  # Thread-safe access
        self._cache_max_age = 30.0  # Seconds to keep entries
        
        # Directory-based tracking for better reliability
        # Structure: { "/path/to/directory": [(pid, name, timestamp), ...] }
        self.recent_dir_writers: Dict[str, List[tuple]] = {}
    
    def track_file_write(self, file_path: str):
        """
        CRITICAL FIX: Track which process is writing to a file IMMEDIATELY.
        Called by FileMonitor when a file event is detected, BEFORE entropy analysis.
        
        Args:
            file_path: Path to the file being written
        """
        abs_path = os.path.abspath(file_path)
        current_time = time.time()
        
        # Find current process writing to this file
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                open_files = proc.open_files()
                for f in open_files:
                    if f.path == abs_path:
                        with self._cache_lock:
                            if abs_path not in self.recent_file_writers:
                                self.recent_file_writers[abs_path] = []
                            
                            # Add this writer
                            self.recent_file_writers[abs_path].append(
                                (proc.pid, proc.name(), current_time)
                            )
                            
                            # Keep only recent entries
                            self.recent_file_writers[abs_path] = [
                                (p, n, t) for p, n, t in self.recent_file_writers[abs_path]
                                if current_time - t < self._cache_max_age
                            ]
                        logger.debug(f"Tracked writer: {proc.name()} (PID: {proc.pid}) -> {abs_path}")
                        
                        # Also track by directory for fallback
                        dir_path = os.path.dirname(abs_path)
                        if dir_path not in self.recent_dir_writers:
                            self.recent_dir_writers[dir_path] = []
                        self.recent_dir_writers[dir_path].append(
                            (proc.pid, proc.name(), current_time)
                        )
                        return
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception:
                continue
    
    def get_cached_writer(self, file_path: str) -> Optional[ProcessInfo]:
        """
        CRITICAL FIX: Get process that wrote to this file from cache.
        This is the primary method - checks cache FIRST before live search.
        
        Args:
            file_path: Path to the suspicious file
            
        Returns:
            ProcessInfo if found in cache, None otherwise
        """
        abs_path = os.path.abspath(file_path)
        
        with self._cache_lock:
            if abs_path in self.recent_file_writers:
                writers = self.recent_file_writers[abs_path]
                if writers:
                    # Get most recent writer
                    pid, name, timestamp = writers[-1]
                    try:
                        proc = psutil.Process(pid)
                        logger.debug(f"Found cached writer: {name} (PID: {pid})")
                        return self._get_process_info(proc)
                    except psutil.NoSuchProcess:
                        logger.debug(f"Cached process {pid} no longer exists")
                        pass
        
        return None
    
    def cleanup_cache(self):
        """Remove old entries from the process tracking cache."""
        current_time = time.time()
        with self._cache_lock:
            # Remove old entries
            expired_paths = []
            for path, writers in self.recent_file_writers.items():
                writers[:] = [(p, n, t) for p, n, t in writers if current_time - t < self._cache_max_age]
                if not writers:
                    expired_paths.append(path)
            
            for path in expired_paths:
                del self.recent_file_writers[path]
    
    def find_process_by_file(self, file_path: str) -> Optional[ProcessInfo]:
        """
        Find the process that has a file open for writing.
        FIXED: Now checks for write mode before returning.
        
        Args:
            file_path: Path to the file being written
            
        Returns:
            ProcessInfo if found, None otherwise
        """
        abs_path = os.path.abspath(file_path)
        
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                # Get open files for this process
                open_files = proc.open_files()
                
                for f in open_files:
                    if f.path == abs_path:
                        # CRITICAL FIX: Check if opened for writing
                        write_modes = ('w', 'a', 'r+', 'w+', 'a+', 'rb+', 'wb', 'ab', 'wb+', 'ab+')
                        
                        if hasattr(f, 'mode') and f.mode:
                            if f.mode in write_modes or 'w' in f.mode or 'a' in f.mode:
                                return self._get_process_info(proc)
                        else:
                            # If mode not available, return it anyway (better safe than sorry)
                            return self._get_process_info(proc)
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception:
                continue
        
        return None
    
    def find_recent_writers(self, file_path: str, time_window: float = 2.0) -> List[ProcessInfo]:
        """
        Find processes that recently modified files in the same directory.
        Useful when the exact writing process can't be determined.
        
        Args:
            file_path: Path to the suspicious file
            time_window: How far back to look (seconds)
            
        Returns:
            List of ProcessInfo for suspicious processes
        """
        directory = os.path.dirname(os.path.abspath(file_path))
        current_time = time.time()
        suspects = []
        
        for proc in psutil.process_iter(['pid', 'name', 'create_time']):
            try:
                # CRITICAL FIX: Now actually uses time_window parameter!
                # Skip processes older than the time window
                if current_time - proc.create_time() > time_window:
                    continue
                    
                open_files = proc.open_files()
                
                for f in open_files:
                    # Check if process has files open in same directory
                    if os.path.dirname(f.path) == directory:
                        info = self._get_process_info(proc)
                        if info and info not in suspects:
                            suspects.append(info)
                        break
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception:
                continue
        
        return suspects
    
    def _get_process_info(self, proc: psutil.Process) -> Optional[ProcessInfo]:
        """Extract detailed process information safely."""
        try:
            with proc.oneshot():
                # CRITICAL FIX: Handle exe() that might raise exception
                try:
                    exe = proc.exe()
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    exe = None
                
                return ProcessInfo(
                    pid=proc.pid,
                    name=proc.name(),
                    exe=exe,
                    cmdline=proc.cmdline(),
                    username=proc.username(),
                    create_time=proc.create_time(),
                    cpu_percent=proc.cpu_percent(),
                    memory_percent=proc.memory_percent()
                )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None
    
    def is_protected(self, process_info: ProcessInfo) -> bool:
        """Check if a process should be protected from termination."""
        name_lower = process_info.name.lower()
        
        # Check system-critical processes (ALWAYS protected)
        if name_lower in self.PROTECTED_PROCESSES:
            return True
        
        # Check trusted applications (skip in test mode)
        if not self.test_mode and name_lower in self.TRUSTED_APPLICATIONS:
            return True
        
        # Check user whitelist
        if name_lower in self.whitelist:
            return True
        
        # Protect root/system-owned processes (optional safety)
        if process_info.username in ('root', 'system'):
            # Only protect if it's a system process, not a script run as root
            if process_info.exe and process_info.exe.startswith(('/usr', '/bin', '/sbin')):
                return True
        
        return False
    
    def terminate_process(self, process_info: ProcessInfo, force: bool = False) -> Dict:
        """
        Terminate a process safely.
        
        Args:
            process_info: Information about the process to terminate
            force: If True, use SIGKILL instead of SIGTERM
            
        Returns:
            Dictionary with action result
        """
        result = {
            'pid': process_info.pid,
            'name': process_info.name,
            'action': ProcessAction.NONE.value,
            'success': False,
            'message': '',
            'timestamp': time.time()
        }
        
        # Safety check: Don't terminate protected processes
        if self.is_protected(process_info):
            result['message'] = f"Process '{process_info.name}' is protected and cannot be terminated"
            logger.info(f"Skipped protected process: {process_info.name} (PID: {process_info.pid})")
            self.action_log.append(result)
            return result
        
        # Safety check: Don't terminate ourselves
        if process_info.pid == os.getpid():
            result['message'] = "Cannot terminate self"
            self.action_log.append(result)
            return result
        
        try:
            proc = psutil.Process(process_info.pid)
            
            if force:
                proc.kill()  # SIGKILL - immediate termination
                result['action'] = ProcessAction.KILL.value
            else:
                proc.terminate()  # SIGTERM - graceful termination
                result['action'] = ProcessAction.TERMINATE.value
            
            try:
                proc.wait(timeout=3)
                result['success'] = True
                result['message'] = f"Process {process_info.pid} ({process_info.name}) terminated successfully"
                logger.info(f"Process terminated: {process_info.name} (PID: {process_info.pid})")
            except psutil.TimeoutExpired:
                if not force:
                    # Try force kill if graceful termination failed
                    proc.kill()
                    proc.wait(timeout=2)
                    result['success'] = True
                    result['action'] = ProcessAction.KILL.value
                    result['message'] = f"Process {process_info.pid} force-killed after timeout"
                else:
                    result['message'] = f"Process {process_info.pid} did not terminate"
            
            self.terminated_pids[process_info.pid] = time.time()
            
        except psutil.NoSuchProcess:
            result['success'] = True
            result['message'] = f"Process {process_info.pid} already terminated"
            logger.debug(f"Process already terminated: PID {process_info.pid}")
        except psutil.AccessDenied:
            result['message'] = f"Access denied: Cannot terminate {process_info.pid} (try running as root)"
            logger.error(f"Access denied terminating PID {process_info.pid}")
        except Exception as e:
            result['message'] = f"Error terminating process: {str(e)}"
            logger.error(f"Error terminating PID {process_info.pid}: {e}")
        
        self.action_log.append(result)
        return result
    
    def suspend_process(self, process_info: ProcessInfo) -> Dict:
        """
        Suspend a process instead of terminating it.
        Useful for quarantine/investigation.
        """
        result = {
            'pid': process_info.pid,
            'name': process_info.name,
            'action': ProcessAction.SUSPEND.value,
            'success': False,
            'message': '',
            'timestamp': time.time()
        }
        
        if self.is_protected(process_info):
            result['message'] = f"Process '{process_info.name}' is protected"
            self.action_log.append(result)
            return result
        
        try:
            proc = psutil.Process(process_info.pid)
            proc.suspend()
            result['success'] = True
            result['message'] = f"Process {process_info.pid} suspended"
        except psutil.NoSuchProcess:
            result['message'] = f"Process {process_info.pid} no longer exists"
        except psutil.AccessDenied:
            result['message'] = f"Access denied: Cannot suspend {process_info.pid}"
        except Exception as e:
            result['message'] = f"Error: {str(e)}"
        
        self.action_log.append(result)
        return result
    
    def handle_ransomware_alert_with_pid(self, file_path: str,
                                             entropy: float,
                                             pid: int) -> Dict:
        """
        Handle ransomware alert with a known PID from eBPF.

        Called when eBPF provides the PID directly from the kernel,
        bypassing the expensive /proc scan entirely.

        Args:
            file_path: Path to the high-entropy file
            entropy:   Calculated entropy value
            pid:       Process ID from eBPF kprobe (trusted, kernel-provided)

        Returns:
            Dictionary with detection and action results
        """
        result = {
            'file_path': file_path,
            'entropy': entropy,
            'process_found': False,
            'process_info': None,
            'action_taken': None,
            'timestamp': time.time(),
            'detection_method': 'ebpf',
        }

        try:
            import psutil
            proc = psutil.Process(pid)
            process_info = self._get_process_info(proc)

            if process_info:
                result['process_found'] = True
                result['process_info'] = {
                    'pid': process_info.pid,
                    'name': process_info.name,
                    'exe': process_info.exe,
                    'cmdline': ' '.join(process_info.cmdline),
                    'username': process_info.username,
                }

                # Terminate the process
                action_result = self.terminate_process(process_info)
                result['action_taken'] = action_result

                logger.critical(
                    f"RANSOMWARE BLOCKED (eBPF): {process_info.name} "
                    f"(PID: {pid})"
                )
        except psutil.NoSuchProcess:
            logger.warning(f"eBPF PID {pid} no longer exists")
        except Exception as e:
            logger.error(f"Error handling eBPF alert for PID {pid}: {e}")

        return result

    def handle_ransomware_alert(self, file_path: str, entropy: float) -> Dict:
        """
        Main handler called when ransomware is detected.
        Finds and terminates the responsible process.
        
        Args:
            file_path: Path to the high-entropy file
            entropy: Calculated entropy value
            
        Returns:
            Dictionary with detection and action results
        """
        result = {
            'file_path': file_path,
            'entropy': entropy,
            'process_found': False,
            'process_info': None,
            'action_taken': None,
            'timestamp': time.time()
        }
        
        # CRITICAL FIX: Check cache FIRST (most reliable method)
        process_info = self.get_cached_writer(file_path)
        
        if not process_info:
            # Second attempt: Try live file handle search
            process_info = self.find_process_by_file(file_path)
        
        if not process_info:
            # Fallback: Look for recent writers in the same directory
            # Increased time window to 60 seconds for better detection
            suspects = self.find_recent_writers(file_path, time_window=60.0)
            if suspects:
                # Take the most recent non-protected process
                for suspect in suspects:
                    if not self.is_protected(suspect):
                        process_info = suspect
                        break
        
        if process_info:
            result['process_found'] = True
            result['process_info'] = {
                'pid': process_info.pid,
                'name': process_info.name,
                'exe': process_info.exe,
                'cmdline': ' '.join(process_info.cmdline),
                'username': process_info.username
            }
            
            # Terminate the process
            action_result = self.terminate_process(process_info)
            result['action_taken'] = action_result
            
            logger.critical(f"RANSOMWARE BLOCKED: {process_info.name} (PID: {process_info.pid})")
            logger.info(f"  File: {file_path}")
            logger.info(f"  Entropy: {entropy:.4f}")
            logger.info(f"  Action: {action_result['message']}")
        else:
            logger.warning(f"HIGH ENTROPY DETECTED but process not found")
            logger.warning(f"  File: {file_path}")
            logger.warning(f"  Entropy: {entropy:.4f}")
        
        return result
    
    def get_action_log(self) -> List[Dict]:
        """Return the log of all actions taken."""
        return self.action_log.copy()
    
    def add_to_whitelist(self, process_name: str):
        """Add a process name to the whitelist."""
        self.whitelist.add(process_name.lower())
    
    def remove_from_whitelist(self, process_name: str):
        """Remove a process name from the whitelist."""
        self.whitelist.discard(process_name.lower())


# --- Integration Helper ---
def create_alert_callback(process_monitor: ProcessMonitor):
    """
    Creates a callback function for FileMonitor integration.
    
    Usage:
        pm = ProcessMonitor()
        fm = FileMonitor("/path/to/watch", callback_alert=create_alert_callback(pm))
    """
    def callback(file_path: str, entropy: float):
        return process_monitor.handle_ransomware_alert(file_path, entropy)
    return callback


# --- Test Execution ---
if __name__ == "__main__":
    print("=== ProcessMonitor Test ===\n")
    
    pm = ProcessMonitor()
    
    # Test 1: List some running processes
    print("Sample running processes:")
    for i, proc in enumerate(psutil.process_iter(['pid', 'name'])):
        if i >= 20:
            break
        try:
            info = pm._get_process_info(proc)
            if info:
                protected = "🛡️ PROTECTED" if pm.is_protected(info) else ""
                print(f"  PID {info.pid}: {info.name} {protected}")
        except:
            pass
    
    # Test 2: Integration example
    print("\n--- Integration Example ---")
    print("from ProcessMonitor import ProcessMonitor, create_alert_callback")
    print("from FileMonitor import FileMonitor")
    print("")
    print("pm = ProcessMonitor()")
    print("fm = FileMonitor('/home/user/Documents', callback_alert=create_alert_callback(pm))")
    print("fm.start()")
    
    print("\n✅ ProcessMonitor ready!")
