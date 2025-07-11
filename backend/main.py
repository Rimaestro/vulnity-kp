import logging
import uvicorn
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import router as api_router
from core.plugin_manager import plugin_manager

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("main")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Memulai aplikasi Vulnity Web Vulnerability Scanner")
    plugin_manager.discover_plugins()
    available_plugins = plugin_manager.get_plugin_names()
    logger.info(f"Plugin tersedia: {available_plugins}")
    
    yield
    
    # Shutdown
    logger.info("Mematikan aplikasi Vulnity Web Vulnerability Scanner")
    await plugin_manager.cleanup_all()

# Create FastAPI app
app = FastAPI(
    title="Vulnity Web Vulnerability Scanner",
    description="Web vulnerability scanner dengan pendekatan plugin",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Untuk pengembangan, ganti dengan domain sebenarnya di produksi
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API router
app.include_router(api_router, prefix="/api")

# Main entry point
if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    ) 