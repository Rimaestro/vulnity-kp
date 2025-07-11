"""
Vulnity Web Vulnerability Scanner - Simple Demo API
"""

import sys
from pathlib import Path

# Add app directory to path
app_dir = Path(__file__).parent / "app"
sys.path.insert(0, str(app_dir))

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
import logging

# Simple logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastAPI application
app = FastAPI(
    title="Vulnity Web Vulnerability Scanner API",
    description="API untuk scanning kerentanan web aplikasi - Demo Mode",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Simple CORS setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Import dependencies
from config.database import get_db, create_tables
from core.services.scan_service import ScanService
from core.models.scan import ScanCreate, ScanResponse

# Create database tables on startup
try:
    create_tables()
    logger.info("✅ Database tables created")
except Exception as e:
    logger.error(f"Database error: {e}")


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "Vulnity Web Vulnerability Scanner API",
        "version": "1.0.0",
        "status": "running"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": "2025-01-11T00:00:00Z"
    }


# Simple scan endpoints
@app.post("/api/v1/scan/start", response_model=ScanResponse)
async def start_scan(
    scan_data: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Start a new vulnerability scan (Demo mode)"""
    try:
        scan_service = ScanService(db)
        
        # Validasi input
        if not scan_data.target_url:
            raise HTTPException(status_code=400, detail="Target URL is required")
        
        # Buat scan baru dengan demo user ID (1)
        demo_user_id = 1
        scan = await scan_service.create_scan(scan_data, demo_user_id)
        
        # Jalankan scan di background
        background_tasks.add_task(scan_service.execute_scan, scan.id)
        
        logger.info(f"Scan started for {scan_data.target_url} in demo mode")
        
        return scan
        
    except Exception as e:
        logger.error(f"Error starting scan: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to start scan")


@app.get("/api/v1/scan/status/{scan_id}", response_model=ScanResponse)
async def get_scan_status(
    scan_id: int,
    db: Session = Depends(get_db)
):
    """Get scan status by ID (Demo mode)"""
    try:
        scan_service = ScanService(db)
        scan = await scan_service.get_scan_by_id_demo(scan_id)
        
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        return scan
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting scan status: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get scan status")


@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """Global HTTP exception handler"""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": True,
            "message": exc.detail,
            "status_code": exc.status_code
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """Global exception handler"""
    logger.error(f"Unhandled exception: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={
            "error": True,
            "message": "Internal server error",
            "status_code": 500
        }
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
