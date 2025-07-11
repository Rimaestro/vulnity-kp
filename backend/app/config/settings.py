"""
Application Settings and Configuration
"""

import os
from typing import List
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """Application settings"""
    
    # Application
    APP_NAME: str = "Vulnity Web Vulnerability Scanner"
    VERSION: str = "1.0.0"
    ENVIRONMENT: str = Field(default="development", env="ENVIRONMENT")
    DEBUG: bool = Field(default=True, env="DEBUG")
    
    # Server
    HOST: str = Field(default="0.0.0.0", env="HOST")
    PORT: int = Field(default=8000, env="PORT")
    
    # Security
    SECRET_KEY: str = Field(default="your-secret-key-change-this", env="SECRET_KEY")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=30, env="ACCESS_TOKEN_EXPIRE_MINUTES")
    ALGORITHM: str = "HS256"
    
    # Database
    DATABASE_URL: str = Field(
        default="sqlite:///./vulnity.db", 
        env="DATABASE_URL"
    )
    
    # Redis (for caching and task queue)
    REDIS_URL: str = Field(default="redis://localhost:6379", env="REDIS_URL")
    
    # CORS
    CORS_ORIGINS: List[str] = Field(
        default=["http://localhost:3000", "http://localhost:5173"],
        env="CORS_ORIGINS"
    )
    
    # Scanning Configuration
    MAX_CONCURRENT_SCANS: int = Field(default=5, env="MAX_CONCURRENT_SCANS")
    SCAN_TIMEOUT: int = Field(default=300, env="SCAN_TIMEOUT")  # 5 minutes
    MAX_SCAN_DEPTH: int = Field(default=3, env="MAX_SCAN_DEPTH")
    
    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = Field(default=60, env="RATE_LIMIT_PER_MINUTE")
    
    # Logging
    LOG_LEVEL: str = Field(default="INFO", env="LOG_LEVEL")
    LOG_FILE: str = Field(default="logs/vulnity.log", env="LOG_FILE")
    
    # File Upload
    MAX_FILE_SIZE: int = Field(default=10 * 1024 * 1024, env="MAX_FILE_SIZE")  # 10MB
    UPLOAD_DIR: str = Field(default="uploads", env="UPLOAD_DIR")
    
    # External APIs (jika diperlukan)
    SHODAN_API_KEY: str = Field(default="", env="SHODAN_API_KEY")
    VIRUSTOTAL_API_KEY: str = Field(default="", env="VIRUSTOTAL_API_KEY")
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True


# Create settings instance
settings = Settings()


def get_database_url() -> str:
    """Get database URL with proper formatting"""
    return settings.DATABASE_URL


def is_production() -> bool:
    """Check if running in production environment"""
    return settings.ENVIRONMENT.lower() == "production"


def is_development() -> bool:
    """Check if running in development environment"""
    return settings.ENVIRONMENT.lower() == "development"
