"""
Guard Service
Manages the ransomware guard lifecycle and integrates with WebSocket.
"""

import os
import sys
import time
import asyncio
import threading
import logging
import psutil
from typing import Optional, Dict, Any, List

# Add parent directory for core imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from core.EntropyCalculator import EntropyCalculator
from core.FileMonitor import FileMonitor
from core.ProcessMonitor import ProcessMonitor, create_alert_callback

logger = logging.getLogger("ransomware_guard.service")


class GuardService:
    """
    Service layer for managing the ransomware guard.
    Bridges the core detection logic with the API/WebSocket layer.
    """
    
    def __init__(self, websocket_manager=None):
        self.websocket_manager = websocket_manager
        self.is_running = False
        self.watch_path: Optional[str] = None
        self.start_time: Optional[float] = None
        
        # Core components
        self.entropy_calculator: Optional[EntropyCalculator] = None
        self.process_monitor: Optional[ProcessMonitor] = None
        self.file_monitor: Optional[FileMonitor] = None
        
        # Tracking
        self.alerts: List[Dict[str, Any]] = []
        self.alert_id_counter = 0
        self.stats = {
            'files_scanned': 0,
            'threats_detected': 0,
            'processes_terminated': 0,
            'alerts_total': 0
        }
        
        # Event loop for async operations
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._process_broadcast_task: Optional[asyncio.Task] = None
    
    @property
    def uptime(self) -> float:
        """Get uptime in seconds."""
        if self.start_time and self.is_running:
            return time.time() - self.start_time
        return 0.0
    
    async def start(self, watch_path: str, entropy_threshold: float = 7.5):
        """Start the ransomware guard."""
        if self.is_running:
            raise RuntimeError("Guard is already running")
        
        # Validate path
        if not os.path.exists(watch_path):
            raise ValueError(f"Path does not exist: {watch_path}")
        if not os.path.isdir(watch_path):
            raise ValueError(f"Path is not a directory: {watch_path}")
        
        self.watch_path = os.path.abspath(watch_path)
        self.start_time = time.time()
        self._loop = asyncio.get_event_loop()
        
        # Initialize core components
        self.entropy_calculator = EntropyCalculator(threshold=entropy_threshold)
        self.process_monitor = ProcessMonitor()
        
        # Create alert callback that broadcasts via WebSocket
        def alert_callback(file_path: str, entropy: float, result=None):
            if result is None:
                result = self.process_monitor.handle_ransomware_alert(file_path, entropy)
            self._handle_alert(file_path, entropy, result)
        
        self.file_monitor = FileMonitor(
            self.watch_path,
            callback_alert=alert_callback,
            process_monitor=self.process_monitor
        )
        
        # Start monitoring in background thread
        self.file_monitor.start()
        self.is_running = True
        
        logger.info(f"Guard started monitoring: {self.watch_path}")
        
        # Start periodic process broadcast
        self._process_broadcast_task = asyncio.create_task(self._broadcast_processes_loop())
        
        # Broadcast status update
        if self.websocket_manager:
            await self.websocket_manager.broadcast_status({
                'running': True,
                'watch_path': self.watch_path
            })
    
    async def stop(self) -> Dict[str, Any]:
        """Stop the ransomware guard and return final stats."""
        if not self.is_running:
            raise RuntimeError("Guard is not running")
        
        # Cancel process broadcast task
        if self._process_broadcast_task:
            self._process_broadcast_task.cancel()
            self._process_broadcast_task = None
        
        # Stop monitoring
        if self.file_monitor:
            self.file_monitor.stop()
        
        self.is_running = False
        final_stats = self.get_stats()
        
        logger.info("Guard stopped")
        
        # Broadcast status update
        if self.websocket_manager:
            await self.websocket_manager.broadcast_status({
                'running': False,
                'final_stats': final_stats
            })
        
        return final_stats
    
    def _handle_alert(self, file_path: str, entropy: float, result: Dict[str, Any]):
        """Handle a ransomware alert - store and broadcast."""
        self.alert_id_counter += 1
        
        alert = {
            'id': self.alert_id_counter,
            'file_path': file_path,
            'entropy': entropy,
            'timestamp': time.time(),
            'process_found': result.get('process_found', False),
            'process_name': result.get('process_info', {}).get('name') if result.get('process_info') else None,
            'process_pid': result.get('process_info', {}).get('pid') if result.get('process_info') else None,
            'action_taken': result.get('action_taken', {}).get('action') if result.get('action_taken') else None,
            'action_success': result.get('action_taken', {}).get('success', False) if result.get('action_taken') else False
        }
        
        # Store alert
        self.alerts.append(alert)
        
        # Update stats
        self.stats['threats_detected'] += 1
        self.stats['alerts_total'] += 1
        if alert['action_success']:
            self.stats['processes_terminated'] += 1
        
        # Broadcast via WebSocket (run in event loop)
        if self.websocket_manager and self._loop:
            asyncio.run_coroutine_threadsafe(
                self.websocket_manager.broadcast_alert(alert),
                self._loop
            )
        
        logger.warning(f"Alert #{alert['id']}: {file_path} (entropy: {entropy:.4f})")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current statistics."""
        return {
            **self.stats,
            'uptime': self.uptime
        }
    
    def get_alerts(self, limit: int = 0) -> List[Dict[str, Any]]:
        """Get alerts. If limit > 0, return only the most recent N."""
        if limit > 0:
            return list(reversed(self.alerts[-limit:]))
        return list(reversed(self.alerts))
    
    def get_process_list(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get list of running processes with protection status."""
        processes = []
        for proc in psutil.process_iter(['pid', 'name']):
            if limit > 0 and len(processes) >= limit:
                break
            try:
                with proc.oneshot():
                    try:
                        exe = proc.exe()
                    except (psutil.AccessDenied, psutil.ZombieProcess):
                        exe = None
                    
                    name_lower = proc.name().lower()
                    is_protected = name_lower in (self.process_monitor.PROTECTED_PROCESSES if self.process_monitor else set())
                    is_trusted = name_lower in (self.process_monitor.TRUSTED_APPLICATIONS if self.process_monitor else set())
                    
                    processes.append({
                        'pid': proc.pid,
                        'name': proc.name(),
                        'exe': exe,
                        'cmdline': ' '.join(proc.cmdline()) if proc.cmdline() else '',
                        'username': proc.username(),
                        'cpu_percent': proc.cpu_percent(),
                        'memory_percent': round(proc.memory_percent(), 2),
                        'is_protected': is_protected,
                        'is_trusted': is_trusted,
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        processes.sort(key=lambda p: p['cpu_percent'], reverse=True)
        return processes
    
    async def _broadcast_processes_loop(self):
        """Periodically broadcast process list to WebSocket clients."""
        try:
            while self.is_running:
                await asyncio.sleep(5)
                if self.websocket_manager and self.websocket_manager.connection_count > 0:
                    process_list = self.get_process_list(limit=0)
                    await self.websocket_manager.broadcast_processes({
                        'total': len(process_list),
                        'processes': process_list
                    })
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Process broadcast error: {e}")
