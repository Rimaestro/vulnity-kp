"""
Database configuration and connection management
SQLAlchemy setup with async support for optimal performance
"""

from sqlalchemy import create_engine, MetaData
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from typing import Generator

from .settings import settings


# Database engine configuration
if settings.DATABASE_URL.startswith("sqlite"):
    # SQLite configuration for development
    engine = create_engine(
        settings.DATABASE_URL,
        echo=settings.DATABASE_ECHO,
        connect_args={
            "check_same_thread": False,
            "timeout": 20
        },
        poolclass=StaticPool,
    )
else:
    # PostgreSQL/MySQL configuration for production
    engine = create_engine(
        settings.DATABASE_URL,
        echo=settings.DATABASE_ECHO,
        pool_pre_ping=True,
        pool_recycle=300,
        pool_size=10,
        max_overflow=20
    )

# Session factory
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

# Base class for all models
Base = declarative_base()

# Metadata for migrations
metadata = MetaData()


def get_db() -> Generator:
    """
    Database dependency for FastAPI
    Provides database session with automatic cleanup
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_tables():
    """Create all database tables"""
    # Import all models to ensure they're registered with Base.metadata
    from app.models.user import User, UserSession
    from app.models.scan import Scan
    from app.models.vulnerability import Vulnerability

    Base.metadata.create_all(bind=engine)


def drop_tables():
    """Drop all database tables (use with caution)"""
    Base.metadata.drop_all(bind=engine)
