"""
Logging configuration for Vulnity-KP Backend
Comprehensive logging setup for development and production
"""

import logging
import logging.config
import sys
from pathlib import Path
from typing import Dict, Any

from .settings import settings


def setup_logging() -> None:
    """Setup logging configuration"""
    
    # Create logs directory if it doesn't exist
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    # Logging configuration
    logging_config: Dict[str, Any] = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "default": {
                "format": settings.LOG_FORMAT,
                "datefmt": "%Y-%m-%d %H:%M:%S",
            },
            "detailed": {
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(module)s - %(funcName)s - %(lineno)d - %(message)s",
                "datefmt": "%Y-%m-%d %H:%M:%S",
            },
            "json": {
                "format": '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "logger": "%(name)s", "message": "%(message)s"}',
                "datefmt": "%Y-%m-%d %H:%M:%S",
            }
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "level": settings.LOG_LEVEL,
                "formatter": "default",
                "stream": sys.stdout,
            },
            "file": {
                "class": "logging.handlers.RotatingFileHandler",
                "level": "INFO",
                "formatter": "detailed",
                "filename": "logs/vulnity_kp.log",
                "maxBytes": 10485760,  # 10MB
                "backupCount": 5,
            },
            "error_file": {
                "class": "logging.handlers.RotatingFileHandler",
                "level": "ERROR",
                "formatter": "detailed",
                "filename": "logs/vulnity_kp_errors.log",
                "maxBytes": 10485760,  # 10MB
                "backupCount": 5,
            },
            "security_file": {
                "class": "logging.handlers.RotatingFileHandler",
                "level": "WARNING",
                "formatter": "json",
                "filename": "logs/security.log",
                "maxBytes": 10485760,  # 10MB
                "backupCount": 10,
            }
        },
        "loggers": {
            "vulnity_kp": {
                "level": settings.LOG_LEVEL,
                "handlers": ["console", "file", "error_file"],
                "propagate": False,
            },
            "vulnity_kp.security": {
                "level": "WARNING",
                "handlers": ["console", "security_file"],
                "propagate": False,
            },
            "vulnity_kp.auth": {
                "level": "INFO",
                "handlers": ["console", "file", "security_file"],
                "propagate": False,
            },
            "sqlalchemy.engine": {
                "level": "WARNING",
                "handlers": ["console"],
                "propagate": False,
            },
            "uvicorn": {
                "level": "INFO",
                "handlers": ["console"],
                "propagate": False,
            },
            "uvicorn.error": {
                "level": "INFO",
                "handlers": ["console", "error_file"],
                "propagate": False,
            },
            "uvicorn.access": {
                "level": "INFO",
                "handlers": ["console"],
                "propagate": False,
            }
        },
        "root": {
            "level": settings.LOG_LEVEL,
            "handlers": ["console", "file"],
        }
    }
    
    # Apply logging configuration
    logging.config.dictConfig(logging_config)


def get_logger(name: str) -> logging.Logger:
    """Get logger instance with proper configuration"""
    return logging.getLogger(f"vulnity_kp.{name}")


# Security logger for authentication and authorization events
security_logger = get_logger("security")
auth_logger = get_logger("auth")
