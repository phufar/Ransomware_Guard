"""
REST API Routes
Endpoints for controlling and monitoring the ransomware guard.
"""

from fastapi import APIRouter, HTTPException, Request
from typing import Optional
import asyncio
from pathlib import Path
from .schemas import (
    StatusResponse, 
    StatsResponse, 
    AlertResponse, 
    GuardStartRequest,
    GuardStartResponse,
    GuardStopResponse,
    ProcessResponse,
    ActionLogResponse,
    ProcessListResponse
)
import sys
import time as _time
import secrets
import tempfile
import shutil
import psutil
import os as _os

router = APIRouter()


@router.get("/processes", response_model=ProcessListResponse)
async def get_processes(request: Request, limit: int = 100):
    """
    List running processes with protection/trust status.
    Returns processes sorted by CPU usage descending.
    """
    guard_service = request.app.state.guard_service
    process_monitor = guard_service.process_monitor

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
                is_protected = name_lower in (process_monitor.PROTECTED_PROCESSES if process_monitor else set())
                is_trusted = name_lower in (process_monitor.TRUSTED_APPLICATIONS if process_monitor else set())

                processes.append(ProcessResponse(
                    pid=proc.pid,
                    name=proc.name(),
                    exe=exe,
                    cmdline=' '.join(proc.cmdline()) if proc.cmdline() else '',
                    username=proc.username(),
                    cpu_percent=proc.cpu_percent(),
                    memory_percent=round(proc.memory_percent(), 2),
                    is_protected=is_protected,
                    is_trusted=is_trusted,
                ))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    # Sort by CPU usage descending
    processes.sort(key=lambda p: p.cpu_percent, reverse=True)

    return ProcessListResponse(total=len(processes), processes=processes)


@router.get("/processes/action-log", response_model=list[ActionLogResponse])
async def get_action_log(request: Request, limit: int = 50):
    """Get the action log (terminated/suspended processes)."""
    guard_service = request.app.state.guard_service
    process_monitor = guard_service.process_monitor

    if not process_monitor:
        return []

    log = process_monitor.get_action_log()
    entries = []
    for entry in reversed(log[-limit:]):
        entries.append(ActionLogResponse(
            pid=entry.get('pid', 0),
            name=entry.get('name', 'unknown'),
            action=entry.get('action', 'none'),
            success=entry.get('success', False),
            message=entry.get('message', ''),
            timestamp=entry.get('timestamp', 0),
        ))
    return entries


@router.get("/status", response_model=StatusResponse)
async def get_status(request: Request):
    """Get current guard status."""
    guard_service = request.app.state.guard_service
    
    return StatusResponse(
        running=guard_service.is_running,
        watch_path=guard_service.watch_path,
        uptime=guard_service.uptime,
        websocket_clients=request.app.state.websocket_manager.connection_count
    )


@router.get("/stats", response_model=StatsResponse)
async def get_stats(request: Request):
    """Get current detection statistics."""
    guard_service = request.app.state.guard_service
    stats = guard_service.get_stats()
    
    return StatsResponse(**stats)


@router.get("/alerts", response_model=list[AlertResponse])
async def get_alerts(request: Request, limit: int = 0):
    """Get all alerts, or pass ?limit=N to cap the result."""
    guard_service = request.app.state.guard_service
    alerts = guard_service.get_alerts(limit=limit)
    
    return [AlertResponse(**alert) for alert in alerts]


@router.post("/guard/start", response_model=GuardStartResponse)
async def start_guard(request: Request, body: GuardStartRequest):
    """Start the ransomware guard on specified path."""
    guard_service = request.app.state.guard_service
    
    if guard_service.is_running:
        raise HTTPException(status_code=400, detail="Guard is already running")
    
    try:
        await guard_service.start(
            watch_path=body.watch_path,
            entropy_threshold=body.entropy_threshold
        )
        return GuardStartResponse(
            success=True,
            message=f"Guard started monitoring: {body.watch_path}",
            watch_path=body.watch_path
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/guard/stop", response_model=GuardStopResponse)
async def stop_guard(request: Request):
    """Stop the ransomware guard."""
    guard_service = request.app.state.guard_service
    
    if not guard_service.is_running:
        raise HTTPException(status_code=400, detail="Guard is not running")
    
    try:
        stats = await guard_service.stop()
        return GuardStopResponse(
            success=True,
            message="Guard stopped",
            final_stats=stats
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/test/alert")
async def trigger_test_alert(request: Request):
    """
    Trigger a REAL ransomware simulation test.
    Creates a normal file, then encrypts it (overwrites with random bytes)
    to simulate actual ransomware behavior and trigger the detection pipeline.
    
    When the guard is running: writes inside the watch path so FileMonitor
    detects the file and ProcessMonitor identifies the writing process.
    
    When the guard is NOT running: uses a temp directory with manual
    entropy calculation and WebSocket broadcast.
    """ 
    from core.EntropyCalculator import EntropyCalculator
    
    guard_service = request.app.state.guard_service
    websocket_manager = request.app.state.websocket_manager
    
    timestamp = int(_time.time())
    victim_name = f"document_{timestamp}.txt"
    encrypted_name = f"{victim_name}.encrypted"
    
    if guard_service.is_running and guard_service.watch_path:
        # === GUARD IS RUNNING: Write inside watch path for full pipeline ===
        watch_dir = Path(guard_service.watch_path)
        work_dir = watch_dir / "ransomware_test"
        
        try:
            work_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            # Watch path not writable or doesn't exist — fall back to system temp dir
            work_dir = Path(tempfile.mkdtemp(prefix="ransomware_test_"))
        
        try:
            # Step 1: Create a normal text file (the victim)
            victim_path = work_dir / victim_name
            victim_path.write_text("This is a normal document with important content. " * 500)
            original_size = victim_path.stat().st_size
            
            # Step 2: "Encrypt" it — overwrite with random bytes (like real ransomware)
            encrypted_path = work_dir / encrypted_name
            
            # Pre-register current process as the file writer in guard's ProcessMonitor
            # This simulates what happens in real ransomware: the writing process is
            # captured WHILE the file handle is open. Since write_bytes() is synchronous
            # and completes before watchdog fires, we register manually.
            if guard_service.process_monitor:
                abs_encrypted = str(encrypted_path.resolve())
                current_pid = _os.getpid()
                current_time = _time.time()
                proc_name = "python3"
                try:
                    proc_name = psutil.Process(current_pid).name()
                except Exception:
                    pass
                
                with guard_service.process_monitor._cache_lock:
                    if abs_encrypted not in guard_service.process_monitor.recent_file_writers:
                        guard_service.process_monitor.recent_file_writers[abs_encrypted] = []
                    guard_service.process_monitor.recent_file_writers[abs_encrypted].append(
                        (current_pid, proc_name, current_time)
                    )
                    # Also register by directory for fallback
                    dir_path = str(work_dir.resolve())
                    if dir_path not in guard_service.process_monitor.recent_dir_writers:
                        guard_service.process_monitor.recent_dir_writers[dir_path] = []
                    guard_service.process_monitor.recent_dir_writers[dir_path].append(
                        (current_pid, proc_name, current_time)
                    )
            
            encrypted_data = secrets.token_bytes(original_size)
            encrypted_path.write_bytes(encrypted_data)
            victim_path.unlink()  # ransomware deletes the original
            
            # Step 3: Wait for FileMonitor + ProcessMonitor pipeline to detect it
            # The pipeline: FileMonitor -> track_file_write -> entropy check ->
            #               ProcessMonitor.handle_ransomware_alert -> _handle_alert -> WebSocket
            triggered_alert = None
            for _ in range(6):  # Wait up to 3 seconds (6 x 0.5s)
                await asyncio.sleep(0.5)
                for alert in reversed(guard_service.alerts):
                    if encrypted_name in alert.get('file_path', ''):
                        triggered_alert = alert
                        break
                if triggered_alert:
                    break
            
            if triggered_alert:
                # Full pipeline worked — alert has real process info
                return {
                    "success": True,
                    "message": "Ransomware simulation: full pipeline detected the threat",
                    "mode": "guard_pipeline",
                    "original_file": victim_name,
                    "encrypted_file": str(encrypted_path),
                    "alert": triggered_alert
                }
            else:
                # Pipeline didn't fire (e.g. FileMonitor filtered it) — manual fallback
                calc = EntropyCalculator(threshold=7.5)
                encrypted_result = calc.calculate_file_entropy(str(encrypted_path))
                
                guard_service.alert_id_counter += 1
                alert = {
                    'id': guard_service.alert_id_counter,
                    'file_path': str(encrypted_path),
                    'entropy': encrypted_result['entropy'],
                    'timestamp': _time.time(),
                    'process_found': False,
                    'process_name': None,
                    'process_pid': None,
                    'action_taken': None,
                    'action_success': False
                }
                guard_service.alerts.append(alert)
                guard_service.stats['threats_detected'] += 1
                guard_service.stats['alerts_total'] += 1
                await websocket_manager.broadcast_alert(alert)
                
                return {
                    "success": True,
                    "message": "Ransomware simulation: manual fallback (pipeline timeout)",
                    "mode": "manual_fallback",
                    "original_file": victim_name,
                    "encrypted_file": str(encrypted_path),
                    "entropy": encrypted_result['entropy'],
                    "alert": alert
                }
        except OSError as e:
            raise HTTPException(status_code=500, detail=f"Cannot write to watch path: {e}")
    
    else:
        # === GUARD NOT RUNNING: temp dir with manual entropy + broadcast ===
        work_dir = Path(tempfile.mkdtemp(prefix="ransomware_test_"))
        
        try:
            victim_path = work_dir / victim_name
            victim_path.write_text("This is a normal document with important content. " * 500)
            original_size = victim_path.stat().st_size
            
            encrypted_path = work_dir / encrypted_name
            encrypted_data = secrets.token_bytes(original_size)
            encrypted_path.write_bytes(encrypted_data)
            victim_path.unlink()
            
            calc = EntropyCalculator(threshold=7.5)
            encrypted_result = calc.calculate_file_entropy(str(encrypted_path))
            
            guard_service.alert_id_counter += 1
            alert = {
                'id': guard_service.alert_id_counter,
                'file_path': str(encrypted_path),
                'entropy': encrypted_result['entropy'],
                'timestamp': _time.time(),
                'process_found': False,
                'process_name': None,
                'process_pid': None,
                'action_taken': None,
                'action_success': False
            }
            
            guard_service.alerts.append(alert)
            guard_service.stats['threats_detected'] += 1
            guard_service.stats['alerts_total'] += 1
            await websocket_manager.broadcast_alert(alert)
            
            return {
                "success": True,
                "message": "Ransomware simulation: alert broadcast (guard not running)",
                "mode": "standalone",
                "original_file": victim_name,
                "encrypted_file": str(encrypted_path),
                "entropy": encrypted_result['entropy'],
                "suspicious": encrypted_result['suspicious'],
                "alert": alert
            }
        finally:
            shutil.rmtree(work_dir, ignore_errors=True)

