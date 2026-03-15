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


@router.get("/events")
async def get_events(what: str = "", limit: int = 500):
    """
    Get structured detection events from detection_events.log.

    Query params:
        what:  Filter by event type (e.g. WRITE_DETECTED, THREAT_DETECTED, FILE_SAFE)
        limit: Max number of events to return (default 500, 0 = all)
    """
    import json

    log_path = Path(__file__).parent.parent / "logs" / "detection_events.log"

    if not log_path.exists():
        return []

    events = []
    try:
        with open(log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    if what and event.get("what", "") != what.upper():
                        continue
                    events.append(event)
                except json.JSONDecodeError:
                    continue
    except OSError:
        return []

    # Return newest first
    events.reverse()

    if limit > 0:
        events = events[:limit]

    return events


