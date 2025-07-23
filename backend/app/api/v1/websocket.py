"""
WebSocket endpoints for real-time dashboard updates
Provides real-time notifications for scan progress, vulnerability discoveries, and system events
"""

import json
import asyncio
from datetime import datetime
from typing import Dict, Set, Optional, Any
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, Query
from sqlalchemy.orm import Session

from app.config.database import get_db
from app.config.logging import get_logger
from app.models.user import User
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.utils.security import JWTManager

# Setup logging
logger = get_logger("websocket")

# WebSocket router
router = APIRouter()

# Connection manager for WebSocket connections
class ConnectionManager:
    """Manages WebSocket connections for real-time updates"""
    
    def __init__(self):
        # Store active connections by user_id
        self.active_connections: Dict[int, Set[WebSocket]] = {}
        # Store connection metadata
        self.connection_metadata: Dict[WebSocket, Dict[str, Any]] = {}
    
    async def connect(self, websocket: WebSocket, user_id: int, user_info: Dict[str, Any]):
        """Accept WebSocket connection and register user"""
        await websocket.accept()
        
        # Initialize user connections if not exists
        if user_id not in self.active_connections:
            self.active_connections[user_id] = set()
        
        # Add connection
        self.active_connections[user_id].add(websocket)
        self.connection_metadata[websocket] = {
            "user_id": user_id,
            "username": user_info.get("username", "unknown"),
            "connected_at": datetime.utcnow(),
            "last_ping": datetime.utcnow()
        }
        
        logger.info(f"WebSocket connected: user_id={user_id}, username={user_info.get('username')}")
        
        # Send welcome message
        await self.send_personal_message({
            "type": "connection_established",
            "message": "WebSocket connection established",
            "timestamp": datetime.utcnow().isoformat(),
            "user_id": user_id
        }, websocket)
    
    def disconnect(self, websocket: WebSocket):
        """Remove WebSocket connection"""
        if websocket in self.connection_metadata:
            metadata = self.connection_metadata[websocket]
            user_id = metadata["user_id"]
            username = metadata["username"]
            
            # Remove from active connections
            if user_id in self.active_connections:
                self.active_connections[user_id].discard(websocket)
                
                # Clean up empty user connection sets
                if not self.active_connections[user_id]:
                    del self.active_connections[user_id]
            
            # Remove metadata
            del self.connection_metadata[websocket]
            
            logger.info(f"WebSocket disconnected: user_id={user_id}, username={username}")
    
    async def send_personal_message(self, message: Dict[str, Any], websocket: WebSocket):
        """Send message to specific WebSocket connection"""
        try:
            await websocket.send_text(json.dumps(message, default=str))
        except Exception as e:
            logger.error(f"Failed to send message to WebSocket: {e}")
            self.disconnect(websocket)
    
    async def send_to_user(self, message: Dict[str, Any], user_id: int):
        """Send message to all connections of a specific user"""
        if user_id in self.active_connections:
            disconnected_connections = []
            
            for websocket in self.active_connections[user_id].copy():
                try:
                    await websocket.send_text(json.dumps(message, default=str))
                except Exception as e:
                    logger.error(f"Failed to send message to user {user_id}: {e}")
                    disconnected_connections.append(websocket)
            
            # Clean up disconnected connections
            for websocket in disconnected_connections:
                self.disconnect(websocket)
    
    async def broadcast_to_all(self, message: Dict[str, Any]):
        """Send message to all connected users"""
        for user_id in list(self.active_connections.keys()):
            await self.send_to_user(message, user_id)
    
    def get_connected_users_count(self) -> int:
        """Get total number of connected users"""
        return len(self.active_connections)
    
    def get_total_connections_count(self) -> int:
        """Get total number of WebSocket connections"""
        return sum(len(connections) for connections in self.active_connections.values())
    
    def is_user_connected(self, user_id: int) -> bool:
        """Check if user has any active connections"""
        return user_id in self.active_connections and len(self.active_connections[user_id]) > 0

# Global connection manager instance
manager = ConnectionManager()

async def authenticate_websocket(token: str, db: Session) -> Optional[User]:
    """Authenticate WebSocket connection using JWT token"""
    try:
        # Verify JWT token
        payload = JWTManager.verify_token(token, "access")
        if not payload:
            return None
        
        # Get user from database
        username = payload.get("sub")
        user = db.query(User).filter(User.username == username).first()
        
        if not user or not user.is_active:
            return None
        
        return user
    except Exception as e:
        logger.error(f"WebSocket authentication failed: {e}")
        return None

@router.websocket("/ws/dashboard")
async def websocket_dashboard_endpoint(
    websocket: WebSocket,
    token: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """
    WebSocket endpoint for real-time dashboard updates
    Requires authentication via JWT token in query parameter
    """
    
    # Authenticate user
    if not token:
        await websocket.close(code=4001, reason="Authentication token required")
        return
    
    user = await authenticate_websocket(token, db)
    if not user:
        await websocket.close(code=4001, reason="Invalid or expired token")
        return
    
    # Connect user
    await manager.connect(websocket, user.id, {
        "username": user.username,
        "email": user.email
    })
    
    try:
        # Send initial dashboard data
        await send_dashboard_update(user.id, db)
        
        # Listen for messages
        while True:
            try:
                # Wait for message with timeout
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                message = json.loads(data)
                
                # Handle different message types
                await handle_websocket_message(websocket, user, message, db)
                
            except asyncio.TimeoutError:
                # Send ping to keep connection alive
                await manager.send_personal_message({
                    "type": "ping",
                    "timestamp": datetime.utcnow().isoformat()
                }, websocket)
                
            except json.JSONDecodeError:
                await manager.send_personal_message({
                    "type": "error",
                    "message": "Invalid JSON format",
                    "timestamp": datetime.utcnow().isoformat()
                }, websocket)
                
    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected normally: user_id={user.id}")
    except Exception as e:
        logger.error(f"WebSocket error for user {user.id}: {e}")
    finally:
        manager.disconnect(websocket)

async def handle_websocket_message(websocket: WebSocket, user: User, message: Dict[str, Any], db: Session):
    """Handle incoming WebSocket messages from client"""
    message_type = message.get("type")
    
    if message_type == "ping":
        # Respond to ping
        await manager.send_personal_message({
            "type": "pong",
            "timestamp": datetime.utcnow().isoformat()
        }, websocket)
        
    elif message_type == "request_dashboard_update":
        # Send fresh dashboard data
        await send_dashboard_update(user.id, db)
        
    elif message_type == "subscribe_to_scan":
        # Subscribe to specific scan updates
        scan_id = message.get("scan_id")
        if scan_id:
            await send_scan_update(user.id, scan_id, db)
    
    else:
        await manager.send_personal_message({
            "type": "error",
            "message": f"Unknown message type: {message_type}",
            "timestamp": datetime.utcnow().isoformat()
        }, websocket)

async def send_dashboard_update(user_id: int, db: Session):
    """Send dashboard statistics update to user"""
    try:
        # Get user's scans
        scans = db.query(Scan).filter(Scan.user_id == user_id).all()
        
        # Get user's vulnerabilities
        vulnerabilities = db.query(Vulnerability).join(Scan).filter(
            Scan.user_id == user_id
        ).all()
        
        # Calculate statistics
        total_scans = len(scans)
        active_scans = len([s for s in scans if s.status in ['pending', 'running']])
        total_vulnerabilities = len(vulnerabilities)
        critical_vulnerabilities = len([v for v in vulnerabilities if v.risk == 'critical'])
        
        # Send update
        await manager.send_to_user({
            "type": "dashboard_update",
            "data": {
                "total_scans": total_scans,
                "active_scans": active_scans,
                "total_vulnerabilities": total_vulnerabilities,
                "critical_vulnerabilities": critical_vulnerabilities,
                "last_updated": datetime.utcnow().isoformat()
            },
            "timestamp": datetime.utcnow().isoformat()
        }, user_id)
        
    except Exception as e:
        logger.error(f"Failed to send dashboard update to user {user_id}: {e}")

async def send_scan_update(user_id: int, scan_id: int, db: Session):
    """Send specific scan update to user"""
    try:
        scan = db.query(Scan).filter(
            Scan.id == scan_id,
            Scan.user_id == user_id
        ).first()
        
        if not scan:
            return
        
        await manager.send_to_user({
            "type": "scan_update",
            "data": {
                "scan_id": scan.id,
                "status": scan.status,
                "progress": scan.progress,
                "total_vulnerabilities": scan.total_vulnerabilities,
                "target_url": scan.target_url,
                "last_updated": datetime.utcnow().isoformat()
            },
            "timestamp": datetime.utcnow().isoformat()
        }, user_id)
        
    except Exception as e:
        logger.error(f"Failed to send scan update to user {user_id}: {e}")

# Utility functions for triggering WebSocket events from other parts of the application

async def notify_scan_started(scan_id: int, user_id: int, db: Session):
    """Notify user when a scan starts"""
    if manager.is_user_connected(user_id):
        await send_scan_update(user_id, scan_id, db)
        await manager.send_to_user({
            "type": "notification",
            "data": {
                "title": "Scan Started",
                "message": f"Security scan has been initiated",
                "scan_id": scan_id,
                "severity": "info"
            },
            "timestamp": datetime.utcnow().isoformat()
        }, user_id)

async def notify_scan_completed(scan_id: int, user_id: int, db: Session):
    """Notify user when a scan completes"""
    if manager.is_user_connected(user_id):
        await send_scan_update(user_id, scan_id, db)
        await send_dashboard_update(user_id, db)
        await manager.send_to_user({
            "type": "notification",
            "data": {
                "title": "Scan Completed",
                "message": f"Security scan has finished",
                "scan_id": scan_id,
                "severity": "success"
            },
            "timestamp": datetime.utcnow().isoformat()
        }, user_id)

async def notify_vulnerability_found(vulnerability_id: int, scan_id: int, user_id: int, db: Session):
    """Notify user when a vulnerability is found"""
    if manager.is_user_connected(user_id):
        vulnerability = db.query(Vulnerability).filter(Vulnerability.id == vulnerability_id).first()
        if vulnerability:
            await send_dashboard_update(user_id, db)
            await manager.send_to_user({
                "type": "notification",
                "data": {
                    "title": "Vulnerability Found",
                    "message": f"{vulnerability.risk.title()} risk: {vulnerability.title}",
                    "vulnerability_id": vulnerability_id,
                    "scan_id": scan_id,
                    "severity": "warning" if vulnerability.risk in ['critical', 'high'] else "info"
                },
                "timestamp": datetime.utcnow().isoformat()
            }, user_id)
