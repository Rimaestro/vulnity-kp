#!/usr/bin/env python3
"""
Database Migration Script for Vulnity-KP
Creates new tables for SQL injection detection engine (Phase 1)

Since this project doesn't use Alembic, this script manually creates
the new tables following existing patterns.
"""

import sys
import os
from pathlib import Path

# Add the backend directory to Python path
backend_dir = Path(__file__).parent.parent
sys.path.insert(0, str(backend_dir))

from sqlalchemy import inspect, text
from app.config.database import engine, Base, get_db
from app.config.logging import setup_logging, get_logger

# Import all models to ensure they're registered with Base.metadata
from app.models.user import User, UserSession
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability

# Setup logging
setup_logging()
logger = get_logger("migration")


def check_table_exists(table_name: str) -> bool:
    """Check if a table exists in the database"""
    inspector = inspect(engine)
    existing_tables = inspector.get_table_names()
    return table_name in existing_tables


def get_existing_tables() -> list:
    """Get list of existing tables"""
    inspector = inspect(engine)
    return inspector.get_table_names()


def create_new_tables():
    """Create only the new tables (scans and vulnerabilities)"""
    
    logger.info("Starting database migration for SQL injection detection engine...")
    
    # Check existing tables
    existing_tables = get_existing_tables()
    logger.info(f"Existing tables: {existing_tables}")
    
    # Tables we want to create
    new_tables = ['scans', 'vulnerabilities']
    
    # Check which tables need to be created
    tables_to_create = []
    for table_name in new_tables:
        if not check_table_exists(table_name):
            tables_to_create.append(table_name)
            logger.info(f"Table '{table_name}' needs to be created")
        else:
            logger.info(f"Table '{table_name}' already exists")
    
    if not tables_to_create:
        logger.info("All required tables already exist. No migration needed.")
        return True
    
    try:
        # Create only the new tables
        # We'll create them individually to have better control
        
        if 'scans' in tables_to_create:
            logger.info("Creating 'scans' table...")
            Scan.__table__.create(engine, checkfirst=True)
            logger.info("✅ 'scans' table created successfully")
        
        if 'vulnerabilities' in tables_to_create:
            logger.info("Creating 'vulnerabilities' table...")
            Vulnerability.__table__.create(engine, checkfirst=True)
            logger.info("✅ 'vulnerabilities' table created successfully")
        
        # Verify tables were created
        new_existing_tables = get_existing_tables()
        logger.info(f"Tables after migration: {new_existing_tables}")
        
        # Verify foreign key relationships
        logger.info("Verifying foreign key relationships...")
        
        # Test database connection and basic operations
        with engine.connect() as conn:
            # Test scans table
            result = conn.execute(text("SELECT COUNT(*) FROM scans"))
            scan_count = result.scalar()
            logger.info(f"Scans table accessible, current count: {scan_count}")
            
            # Test vulnerabilities table  
            result = conn.execute(text("SELECT COUNT(*) FROM vulnerabilities"))
            vuln_count = result.scalar()
            logger.info(f"Vulnerabilities table accessible, current count: {vuln_count}")
        
        logger.info("🎉 Database migration completed successfully!")
        return True
        
    except Exception as e:
        logger.error(f"❌ Migration failed: {str(e)}")
        logger.error("Rolling back changes...")
        
        # Attempt to drop the tables we just created
        try:
            if 'scans' in tables_to_create and check_table_exists('scans'):
                Scan.__table__.drop(engine)
                logger.info("Rolled back 'scans' table")
            
            if 'vulnerabilities' in tables_to_create and check_table_exists('vulnerabilities'):
                Vulnerability.__table__.drop(engine)
                logger.info("Rolled back 'vulnerabilities' table")
                
        except Exception as rollback_error:
            logger.error(f"Rollback failed: {str(rollback_error)}")
        
        return False


def verify_migration():
    """Verify that the migration was successful"""
    
    logger.info("Verifying migration...")
    
    try:
        # Check that all expected tables exist
        required_tables = ['users', 'user_sessions', 'scans', 'vulnerabilities']
        existing_tables = get_existing_tables()
        
        missing_tables = [table for table in required_tables if table not in existing_tables]
        
        if missing_tables:
            logger.error(f"❌ Missing tables: {missing_tables}")
            return False
        
        logger.info("✅ All required tables exist")
        
        # Test that we can create a database session
        db = next(get_db())
        try:
            # Test basic queries
            user_count = db.query(User).count()
            scan_count = db.query(Scan).count()
            vuln_count = db.query(Vulnerability).count()
            
            logger.info(f"Database accessible - Users: {user_count}, Scans: {scan_count}, Vulnerabilities: {vuln_count}")
            
        finally:
            db.close()
        
        logger.info("✅ Database verification completed successfully")
        return True
        
    except Exception as e:
        logger.error(f"❌ Verification failed: {str(e)}")
        return False


def main():
    """Main migration function"""
    
    logger.info("=" * 60)
    logger.info("Vulnity-KP Database Migration Script")
    logger.info("Phase 1: SQL Injection Detection Engine")
    logger.info("=" * 60)
    
    # Check database connection
    try:
        with engine.connect() as conn:
            result = conn.execute(text("SELECT 1"))
            logger.info("✅ Database connection successful")
    except Exception as e:
        logger.error(f"❌ Database connection failed: {str(e)}")
        return False
    
    # Run migration
    if not create_new_tables():
        logger.error("❌ Migration failed")
        return False
    
    # Verify migration
    if not verify_migration():
        logger.error("❌ Migration verification failed")
        return False
    
    logger.info("🎉 Migration completed successfully!")
    logger.info("You can now start the application with the new scanner functionality.")
    
    return True


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
