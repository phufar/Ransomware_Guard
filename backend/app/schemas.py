"""
Pydantic Schemas
Request and response models for API validation.
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime


# === Status ===
class StatusResponse(BaseModel):
    """Guard status response."""
    running: bool
    watch_path: Optional[str] = None
    uptime: float = 0.0  # seconds
    websocket_clients: int = 0


# === Statistics ===
class StatsResponse(BaseModel):
    """Detection statistics response."""
    files_scanned: int = 0
    threats_detected: int = 0
    processes_terminated: int = 0
    alerts_total: int = 0
    uptime: float = 0.0


# === Alerts ===
class AlertResponse(BaseModel):
    """Single alert response."""
    id: int
    file_path: str
    entropy: float
    timestamp: float
    process_found: bool = False
    process_name: Optional[str] = None
    process_pid: Optional[int] = None
    action_taken: Optional[str] = None
    action_success: bool = False


# === Guard Control ===
class GuardStartRequest(BaseModel):
    """Request to start the guard."""
    watch_path: str = Field(..., description="Directory path to monitor")
    entropy_threshold: float = Field(default=7.5, ge=0.0, le=8.0)


class GuardStartResponse(BaseModel):
    """Response after starting guard."""
    success: bool
    message: str
    watch_path: str


class GuardStopResponse(BaseModel):
    """Response after stopping guard."""
    success: bool
    message: str
    final_stats: Optional[Dict[str, Any]] = None


# === Processes ===
class ProcessResponse(BaseModel):
    """Single process information."""
    pid: int
    name: str
    exe: Optional[str] = None
    cmdline: str = ""
    username: Optional[str] = None
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    is_protected: bool = False
    is_trusted: bool = False


class ActionLogResponse(BaseModel):
    """Single action log entry."""
    pid: int
    name: str
    action: str
    success: bool
    message: str
    timestamp: float


class ProcessListResponse(BaseModel):
    """List of processes with count."""
    total: int
    processes: List[ProcessResponse]


# === WebSocket Messages ===
class WebSocketMessage(BaseModel):
    """WebSocket message format."""
    type: str  # "alert", "stats", "status", "processes"
    data: Dict[str, Any]
