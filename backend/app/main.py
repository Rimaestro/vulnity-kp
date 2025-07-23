"""
Vulnity Backend Main Application
FastAPI application with authentication system and security enhancements
Phase 1: Authentication & Login System Implementation
"""

import sys
import os
from pathlib import Path
import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

# Add parent directory to Python path for imports
current_dir = Path(__file__).parent.parent
if str(current_dir) not in sys.path:
    sys.path.insert(0, str(current_dir))

from app.config.settings import settings
from app.config.database import create_tables
from app.config.logging import setup_logging, get_logger
from app.api.v1.auth import router as auth_router
from app.api.v1.scan import router as scan_router
from app.api.v1.vulnerability import router as vulnerability_router
from app.api.v1.websocket import router as websocket_router

# Try to import uvloop for better performance (Linux/Mac only)
try:
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    logger_available = True
except ImportError:
    # uvloop not available on Windows, use default event loop
    logger_available = False

# Setup logging
setup_logging()
logger = get_logger("main")

if not logger_available:
    logger.info("uvloop not available, using default asyncio event loop")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events"""
    # Startup
    logger.info("Starting Vulnity Backend...")
    
    # Create database tables
    create_tables()
    logger.info("Database tables created/verified")
    
    # Additional startup tasks can be added here
    logger.info("Vulnity Backend started successfully")
    
    yield
    
    # Shutdown
    logger.info("Shutting down Vulnity Backend...")


# Create FastAPI application
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Vulnerability Scanner with Web Interface - SQL Injection Detection Engine",
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
    openapi_url="/openapi.json" if settings.DEBUG else None,
    lifespan=lifespan
)


# Security Middleware
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["localhost", "127.0.0.1", "*.localhost", "testserver"] if settings.DEBUG else ["yourdomain.com"]
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.get_allowed_origins_list(),
    allow_credentials=True,
    allow_methods=settings.get_allowed_methods_list(),
    allow_headers=settings.get_allowed_headers_list(),
)


# Custom middleware for security headers
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add security headers to all responses"""
    response = await call_next(request)
    
    # Security headers based on DVWA analysis findings
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    
    if not settings.DEBUG:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    
    # Remove server header
    if "server" in response.headers:
        del response.headers["server"]
    
    return response


# Request logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all requests for security monitoring"""
    start_time = asyncio.get_event_loop().time()
    
    # Log request
    client_ip = request.headers.get("X-Forwarded-For", request.client.host if request.client else "unknown")
    logger.info(f"Request: {request.method} {request.url.path} from {client_ip}")
    
    response = await call_next(request)
    
    # Log response
    process_time = asyncio.get_event_loop().time() - start_time
    logger.info(f"Response: {response.status_code} in {process_time:.4f}s")
    
    return response


# Exception handlers
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """Handle HTTP exceptions"""
    logger.warning(f"HTTP {exc.status_code}: {exc.detail} - {request.method} {request.url.path}")
    
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": "HTTP Error",
            "message": exc.detail,
            "status_code": exc.status_code
        }
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle request validation errors"""
    logger.warning(f"Validation error: {exc.errors()} - {request.method} {request.url.path}")

    # Convert errors to JSON-serializable format
    errors = []
    for error in exc.errors():
        error_dict = {
            "type": error.get("type", "unknown"),
            "loc": error.get("loc", []),
            "msg": str(error.get("msg", "Validation error")),
            "input": str(error.get("input", "")) if error.get("input") is not None else ""
        }
        errors.append(error_dict)

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "Validation Error",
            "message": "Request validation failed",
            "details": errors
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle general exceptions"""
    logger.error(f"Unhandled exception: {str(exc)} - {request.method} {request.url.path}", exc_info=True)
    
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal Server Error",
            "message": "An unexpected error occurred" if not settings.DEBUG else str(exc)
        }
    )


# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT
    }


# Root endpoint
@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": f"Welcome to {settings.APP_NAME}",
        "version": settings.APP_VERSION,
        "docs": "/docs" if settings.DEBUG else "Documentation not available in production",
        "health": "/health"
    }


# Include routers
app.include_router(auth_router, prefix="/api/v1")
app.include_router(scan_router, prefix="/api/v1")
app.include_router(vulnerability_router, prefix="/api/v1")
app.include_router(websocket_router)  # WebSocket routes don't need prefix


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.RELOAD and settings.DEBUG,
        log_level=settings.LOG_LEVEL.lower(),
        access_log=True
    )
