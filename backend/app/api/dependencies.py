"""
FastAPI dependencies for authentication and authorization
Middleware and dependency injection for secure API access
"""

from datetime import datetime
from typing import Optional
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from app.config.database import get_db
from app.config.logging import auth_logger, security_logger
from app.models.user import User, UserSession
from app.utils.security import JWTManager


# HTTP Bearer token scheme
security = HTTPBearer(auto_error=False)


class AuthenticationError(HTTPException):
    """Custom authentication error"""
    def __init__(self, detail: str = "Authentication failed"):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            headers={"WWW-Authenticate": "Bearer"},
        )


class AuthorizationError(HTTPException):
    """Custom authorization error"""
    def __init__(self, detail: str = "Insufficient permissions"):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=detail,
        )


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    """
    Get current authenticated user from JWT token
    Enhanced with security logging and session validation
    """
    
    if not credentials:
        security_logger.warning(f"Authentication attempt without token from {request.client.host}")
        raise AuthenticationError("Authentication token required")
    
    # Verify JWT token
    token_payload = JWTManager.verify_token(credentials.credentials, "access")
    if not token_payload:
        security_logger.warning(f"Invalid token attempt from {request.client.host}")
        raise AuthenticationError("Invalid or expired token")
    
    # Get user from database
    username = token_payload.get("sub")
    if not username:
        security_logger.warning("Token missing subject claim")
        raise AuthenticationError("Invalid token format")
    
    user = db.query(User).filter(User.username == username).first()
    if not user:
        security_logger.warning(f"Token for non-existent user: {username}")
        raise AuthenticationError("User not found")
    
    # Check if user is active
    if not user.is_active:
        security_logger.warning(f"Inactive user login attempt: {username}")
        raise AuthenticationError("User account is inactive")
    
    # Check if account is locked
    if user.is_account_locked():
        security_logger.warning(f"Locked account login attempt: {username}")
        raise AuthenticationError("Account is temporarily locked")
    
    # Validate session if session_id is in token
    session_id = token_payload.get("session_id")
    if session_id:
        session = db.query(UserSession).filter(
            UserSession.id == session_id,
            UserSession.user_id == user.id
        ).first()
        
        if not session or not session.is_valid():
            security_logger.warning(f"Invalid session for user: {username}")
            raise AuthenticationError("Session expired or invalid")
    
    # Log successful authentication
    auth_logger.info(f"User authenticated: {username} from {request.client.host}")
    
    return user


async def get_current_active_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """Get current active user (additional check)"""
    if not current_user.is_active:
        raise AuthenticationError("User account is inactive")
    return current_user


async def get_current_superuser(
    current_user: User = Depends(get_current_active_user)
) -> User:
    """Get current superuser (admin access required)"""
    if not current_user.is_superuser:
        security_logger.warning(f"Unauthorized admin access attempt by: {current_user.username}")
        raise AuthorizationError("Superuser access required")
    return current_user


def get_client_ip(request: Request) -> str:
    """Get client IP address with proxy support"""
    # Check for forwarded headers (reverse proxy)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Take the first IP in the chain
        return forwarded_for.split(",")[0].strip()
    
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip
    
    # Fallback to direct connection
    return request.client.host if request.client else "unknown"


def get_user_agent(request: Request) -> str:
    """Get user agent string"""
    return request.headers.get("User-Agent", "unknown")


class RateLimitDependency:
    """Rate limiting dependency"""
    
    def __init__(self, max_requests: int = 60, window_minutes: int = 1):
        self.max_requests = max_requests
        self.window_minutes = window_minutes
        self.requests = {}  # In production, use Redis
    
    async def __call__(self, request: Request):
        client_ip = get_client_ip(request)
        current_time = datetime.utcnow()
        
        # Clean old entries (simplified for demo)
        self.requests = {
            ip: times for ip, times in self.requests.items()
            if any(current_time.timestamp() - t < self.window_minutes * 60 for t in times)
        }
        
        # Check rate limit
        if client_ip in self.requests:
            recent_requests = [
                t for t in self.requests[client_ip]
                if current_time.timestamp() - t < self.window_minutes * 60
            ]
            
            if len(recent_requests) >= self.max_requests:
                security_logger.warning(f"Rate limit exceeded for IP: {client_ip}")
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Rate limit exceeded"
                )
            
            self.requests[client_ip] = recent_requests + [current_time.timestamp()]
        else:
            self.requests[client_ip] = [current_time.timestamp()]


# Rate limiting instances
# More permissive for testing environment
auth_rate_limit = RateLimitDependency(max_requests=100, window_minutes=1)  # Permissive for testing
api_rate_limit = RateLimitDependency(max_requests=200, window_minutes=1)  # General API
