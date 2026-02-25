"""
WebSocket Connection Manager
Handles multiple client connections and broadcasts alerts in real-time.
"""

from fastapi import WebSocket
from typing import List, Dict, Any
import json
import logging

logger = logging.getLogger("ransomware_guard.websocket")


class ConnectionManager:
    """Manages WebSocket connections for real-time updates."""
    
    def __init__(self):
        self.active_connections: List[WebSocket] = []
    
    async def connect(self, websocket: WebSocket):
        """Accept and track a new WebSocket connection."""
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"Client connected. Total connections: {len(self.active_connections)}")
    
    def disconnect(self, websocket: WebSocket):
        """Remove a disconnected client."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger.info(f"Client disconnected. Total connections: {len(self.active_connections)}")
    
    async def send_personal_message(self, message: str, websocket: WebSocket):
        """Send message to a specific client."""
        await websocket.send_text(message)
    
    async def broadcast(self, message: Dict[str, Any]):
        """Broadcast message to all connected clients."""
        if not self.active_connections:
            return
        
        json_message = json.dumps(message)
        disconnected = []
        
        for connection in self.active_connections:
            try:
                await connection.send_text(json_message)
            except Exception as e:
                logger.warning(f"Failed to send to client: {e}")
                disconnected.append(connection)
        
        # Clean up disconnected clients
        for conn in disconnected:
            self.disconnect(conn)
    
    async def broadcast_alert(self, alert: Dict[str, Any]):
        """Broadcast a ransomware alert to all clients."""
        await self.broadcast({
            "type": "alert",
            "data": alert
        })
        logger.info(f"Alert broadcasted to {len(self.active_connections)} clients")
    
    async def broadcast_stats(self, stats: Dict[str, Any]):
        """Broadcast updated statistics to all clients."""
        await self.broadcast({
            "type": "stats",
            "data": stats
        })
    
    async def broadcast_status(self, status: Dict[str, Any]):
        """Broadcast guard status change."""
        await self.broadcast({
            "type": "status",
            "data": status
        })
    
    async def broadcast_processes(self, processes: Dict[str, Any]):
        """Broadcast process list update."""
        await self.broadcast({
            "type": "processes",
            "data": processes
        })
    
    @property
    def connection_count(self) -> int:
        """Get number of active connections."""
        return len(self.active_connections)
