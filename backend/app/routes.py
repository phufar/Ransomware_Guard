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
    Trigger a ransomware simulation test.

    Creates a test folder with document files, then spawns a SUBPROCESS
    to encrypt them. The subprocess has a different PID so the guard's
    eBPF monitor (which ignores its own PID) detects the writes naturally.
    """
    import subprocess

    guard_service = request.app.state.guard_service

    timestamp = int(_time.time())

    # --- Determine work directory ---
    if guard_service.is_running and guard_service.watch_path:
        work_dir = Path(guard_service.watch_path) / "ransomware_test"
    else:
        work_dir = Path(tempfile.mkdtemp(prefix="ransomware_test_"))

    try:
        work_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        raise HTTPException(status_code=500, detail=f"Cannot create test dir: {e}")

    # --- Step 1: Create victim files (in-process, these are normal writes) ---
    victim_files = {
        f"report_{timestamp}.docx": "Quarterly financial report with sensitive data. " * 200,
        f"photo_{timestamp}.jpg": "JFIF" + ("X" * 5000),
        f"database_{timestamp}.csv": ("id,name,email,balance\n" + "1,John,john@example.com,50000\n" * 300),
        f"notes_{timestamp}.txt": "Meeting notes from the board session. " * 150,
        f"presentation_{timestamp}.pptx": "Slide content with charts and analysis. " * 250,
    }

    created_files = []
    for name, content in victim_files.items():
        path = work_dir / name
        path.write_text(content)
        created_files.append({"name": name, "path": str(path), "size": path.stat().st_size})

    # --- Step 2: Encrypt files in a SUBPROCESS (different PID = detected by guard) ---
    # The subprocess writes slowly (like real ransomware iterating through files)
    # so the guard can resolve paths via /proc/<pid>/fd while the process is alive.
    encrypt_script = f"""
import os, secrets, sys, time
work_dir = {str(work_dir)!r}
files = {[f["name"] for f in created_files]!r}
for name in files:
    original = os.path.join(work_dir, name)
    encrypted = original + ".encrypted"
    try:
        size = os.path.getsize(original)
        data = secrets.token_bytes(size)
        with open(encrypted, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        time.sleep(0.5)
        os.unlink(original)
        print(f"Encrypted: {{name}} -> {{name}}.encrypted")
    except Exception as e:
        print(f"Error: {{name}}: {{e}}", file=sys.stderr)
time.sleep(1)
"""

    proc = subprocess.Popen(
        [sys.executable, "-c", encrypt_script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    encrypted_files = [
        {
            "original": f["name"],
            "encrypted": f"{f['name']}.encrypted",
            "path": str(Path(f["path"]).parent / f"{f['name']}.encrypted"),
            "size": f["size"],
        }
        for f in created_files
    ]

    return {
        "success": True,
        "message": f"Ransomware simulation launched: {len(encrypted_files)} files being encrypted by subprocess PID {proc.pid}",
        "test_dir": str(work_dir),
        "ransomware_pid": proc.pid,
        "files_created": len(created_files),
        "files_encrypting": len(encrypted_files),
        "encrypted_files": encrypted_files,
    }

