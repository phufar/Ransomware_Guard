"""
Ransomware Guard - FastAPI Application
Real-time monitoring API with WebSocket support
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import asyncio
import logging

from .routes import router
from .websocket import ConnectionManager
from .services.guard_service import GuardService
try:
    import setproctitle
except ImportError:
    setproctitle = None

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ransomware_guard.api")

# Create FastAPI app
app = FastAPI(
    title="Ransomware Guard API",
    description="Real-time ransomware detection and monitoring API",
    version="1.0.0"
)

# CORS - Allow frontend to connect
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# WebSocket connection manager
manager = ConnectionManager()

# Guard service instance
guard_service = GuardService(websocket_manager=manager)


# Middleware to log POST request data
@app.middleware("http")
async def log_requests(request, call_next):
    """Log incoming POST request data."""
    if request.method == "POST":
        # Read and log the body
        body = await request.body()
        if body:
            logger.info(f"📥 POST {request.url.path}")
            logger.info(f"   Body: {body.decode('utf-8', errors='ignore')}")
        else:
            logger.info(f"📥 POST {request.url.path} (no body)")
    
    response = await call_next(request)
    
    if request.method == "POST":
        logger.info(f"📤 Response: {response.status_code}")
    
    return response


# Include REST routes
app.include_router(router, prefix="/api")


@app.get("/")
async def root():
    """Health check endpoint."""
    return {"status": "ok", "message": "Ransomware Guard API is running"}


@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    """WebSocket endpoint for real-time alerts."""
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive, messages sent via manager.broadcast()
            data = await websocket.receive_text()
            # Echo back for testing (optional)
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        logger.info("Client disconnected from WebSocket")


@app.on_event("startup")
async def startup_event():
    """Initialize services on startup."""
    if setproctitle:
        setproctitle.setproctitle("Ransomware-Guard")
    
    logger.info("Ransomware Guard API starting...")
    # Make guard_service available to routes
    app.state.guard_service = guard_service
    app.state.websocket_manager = manager


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    logger.info("Ransomware Guard API shutting down...")
    if guard_service.is_running:
        await guard_service.stop()
