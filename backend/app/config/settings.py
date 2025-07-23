"""
Configuration settings for Vulnity Backend
Environment-based configuration management with security best practices
"""

import os
from typing import Optional, List
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache


class Settings(BaseSettings):
    """Application settings with environment variable support"""
    
    # Application Settings
    APP_NAME: str = "Vulnity Backend"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = False
    ENVIRONMENT: str = "development"
    
    # Server Settings
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    RELOAD: bool = True
    
    # Database Settings
    DATABASE_URL: str = "sqlite:///./database/vulnity_kp.db"
    DATABASE_ECHO: bool = False
    
    # Security Settings - Based on DVWA Analysis Findings
    SECRET_KEY: str = "your-secret-key-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # Password Security (Enhanced based on DVWA findings)
    PASSWORD_MIN_LENGTH: int = 8
    PASSWORD_REQUIRE_UPPERCASE: bool = True
    PASSWORD_REQUIRE_LOWERCASE: bool = True
    PASSWORD_REQUIRE_NUMBERS: bool = True
    PASSWORD_REQUIRE_SPECIAL: bool = True
    
    # Session Security (Based on DVWA session analysis)
    SESSION_COOKIE_SECURE: bool = True
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = "strict"
    
    # CORS Settings
    ALLOWED_ORIGINS: str = "http://localhost:3000,http://127.0.0.1:3000"
    ALLOWED_METHODS: str = "GET,POST,PUT,DELETE,OPTIONS"
    ALLOWED_HEADERS: str = "*"
    
    # Rate Limiting (Based on research findings)
    RATE_LIMIT_REQUESTS_PER_MINUTE: int = 60
    RATE_LIMIT_BURST_SIZE: int = 10
    
    # Logging Settings
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    # Redis Settings (for caching and rate limiting)
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_EXPIRE_TIME: int = 3600

    # Scanner Settings (Based on DVWA analysis findings)
    SCANNER_MAX_CONCURRENT_REQUESTS: int = 5
    SCANNER_REQUEST_TIMEOUT: int = 30
    SCANNER_REQUEST_DELAY: float = 1.0
    SCANNER_MAX_PAYLOADS_PER_PARAM: int = 50
    SCANNER_CONFIDENCE_THRESHOLD: float = 0.7
    SCANNER_RATE_LIMIT_PER_TARGET: int = 10  # requests per second

    # SQL Injection Detection Settings (from DVWA findings)
    SQLI_ERROR_PATTERNS: List[str] = [
        r"SQL syntax.*error",
        r"mysqli_sql_exception",
        r"You have an error in your SQL syntax",
        r"Warning: mysql_",
        r"mysql_fetch_array",  # DVWA specific
        r"mysql_num_rows",     # DVWA specific
        r"ORA-01756",  # Oracle
        r"Microsoft OLE DB Provider"  # SQL Server
    ]
    SQLI_UNION_MAX_COLUMNS: int = 20
    SQLI_BOOLEAN_BASELINE_REQUESTS: int = 3

    # Security Settings for Scanner
    SCANNER_ALLOWED_PROTOCOLS: List[str] = ["http", "https"]
    SCANNER_BLOCKED_HOSTS: List[str] = [
        "localhost", "127.0.0.1", "0.0.0.0", "::1",
        "10.", "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
        "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
        "172.30.", "172.31.", "192.168."
    ]
    SCANNER_MAX_SCAN_DURATION: int = 3600  # 1 hour
    
    @field_validator("SECRET_KEY")
    @classmethod
    def validate_secret_key(cls, v: str) -> str:
        if v == "your-secret-key-change-in-production":
            raise ValueError("Please change the default secret key in production")
        if len(v) < 32:
            raise ValueError("Secret key must be at least 32 characters long")
        return v
    
    @field_validator("DATABASE_URL")
    @classmethod
    def validate_database_url(cls, v: str) -> str:
        if not v:
            raise ValueError("Database URL is required")
        return v

    def get_allowed_origins_list(self) -> List[str]:
        """Convert ALLOWED_ORIGINS string to list"""
        return [origin.strip() for origin in self.ALLOWED_ORIGINS.split(",")]

    def get_allowed_methods_list(self) -> List[str]:
        """Convert ALLOWED_METHODS string to list"""
        return [method.strip() for method in self.ALLOWED_METHODS.split(",")]

    def get_allowed_headers_list(self) -> List[str]:
        """Convert ALLOWED_HEADERS string to list"""
        if self.ALLOWED_HEADERS == "*":
            return ["*"]
        return [header.strip() for header in self.ALLOWED_HEADERS.split(",")]
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True
    )


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance"""
    return Settings()


# Export settings instance
settings = get_settings()
