#!/bin/bash

# Database Migration Script for Vulnity-KP
# Phase 1: SQL Injection Detection Engine

echo "=========================================="
echo "Vulnity-KP Database Migration"
echo "Phase 1: SQL Injection Detection Engine"
echo "=========================================="

# Change to backend directory
cd "$(dirname "$0")/.."

# Check if virtual environment is activated
if [[ "$VIRTUAL_ENV" == "" ]]; then
    echo "⚠️  Warning: No virtual environment detected"
    echo "Please activate your virtual environment first:"
    echo "source venv/bin/activate  # or your venv path"
    echo ""
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Check if required packages are installed
echo "Checking dependencies..."
python -c "import sqlalchemy, fastapi, pydantic" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "❌ Required packages not found. Please install dependencies:"
    echo "pip install -r requirements.txt"
    exit 1
fi
echo "✅ Dependencies check passed"

# Backup database if it exists (for SQLite)
if [ -f "vulnity.db" ]; then
    backup_file="vulnity_backup_$(date +%Y%m%d_%H%M%S).db"
    echo "📦 Creating database backup: $backup_file"
    cp vulnity.db "$backup_file"
    echo "✅ Backup created successfully"
fi

# Run migration
echo ""
echo "🚀 Starting database migration..."
python scripts/migrate_database.py

# Check migration result
if [ $? -eq 0 ]; then
    echo ""
    echo "🎉 Migration completed successfully!"
    echo ""
    echo "Next steps:"
    echo "1. Start the application: python -m app.main"
    echo "2. Test the new scanner endpoints at /docs"
    echo "3. Create a user account and test scan functionality"
else
    echo ""
    echo "❌ Migration failed!"
    echo ""
    echo "Troubleshooting:"
    echo "1. Check the logs above for specific error messages"
    echo "2. Ensure database is not in use by another process"
    echo "3. Verify database permissions"
    echo "4. If using SQLite, check file permissions"
    
    # Restore backup if migration failed and backup exists
    if [ -f "$backup_file" ]; then
        echo ""
        read -p "Restore from backup? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            cp "$backup_file" vulnity.db
            echo "✅ Database restored from backup"
        fi
    fi
    
    exit 1
fi
