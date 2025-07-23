# Database Directory

This directory contains all database-related files for the Vulnity-KP backend application.

## Structure

```
database/
├── vulnity_kp.db          # Main SQLite database file
├── migrations/            # Database migration scripts
├── backups/              # Database backup files
└── README.md             # This documentation
```

## Database Files

### vulnity_kp.db
- **Type**: SQLite database
- **Purpose**: Main application database
- **Contains**: Users, scans, vulnerabilities, and application data
- **Backup**: Automatically backed up before migrations

## Migrations

The `migrations/` directory contains database schema migration scripts:
- Migration scripts should be numbered sequentially
- Each migration should have both up and down scripts
- Use the migration script in `../scripts/migrate_database.py`

## Backups

The `backups/` directory contains database backup files:
- Backups are created automatically before migrations
- Manual backups can be created using SQLite tools
- Backup naming convention: `vulnity_kp_backup_YYYYMMDD_HHMMSS.db`

## Security Notes

- Database files should never be committed to version control
- Ensure proper file permissions (600) for database files
- Regular backups should be maintained
- Consider encryption for sensitive production data

## Usage

### Connecting to Database
The application automatically connects to `database/vulnity_kp.db` using the configured database URL.

### Manual Database Access
```bash
# Access database directly
sqlite3 database/vulnity_kp.db

# Create backup
cp database/vulnity_kp.db database/backups/vulnity_kp_backup_$(date +%Y%m%d_%H%M%S).db

# View database schema
sqlite3 database/vulnity_kp.db ".schema"
```

## Environment Configuration

Update your `.env` file to point to the new database location:
```
DATABASE_URL=sqlite:///./database/vulnity_kp.db
```
