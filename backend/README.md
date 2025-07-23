# Vulnity Backend - Sistem Pemindai Kerentanan Web

Backend API untuk aplikasi pemindai kerentanan web yang komprehensif dengan fokus pada deteksi SQL injection dan keamanan aplikasi web.

## 🎯 Gambaran Umum

Vulnity Backend adalah sistem backend yang dirancang khusus untuk melakukan pemindaian kerentanan pada aplikasi web, dengan fokus utama pada deteksi SQL injection berdasarkan analisis mendalam terhadap DVWA (Damn Vulnerable Web Application). Sistem ini dibangun dengan arsitektur modern menggunakan FastAPI dan menyediakan API yang aman serta real-time monitoring.

### ✨ Fitur Utama

#### 🔐 Sistem Autentikasi & Otorisasi
- **Registrasi Pengguna Aman** dengan validasi password yang ketat
- **Autentikasi JWT** dengan access dan refresh tokens
- **Manajemen Sesi** dengan pembersihan otomatis
- **Perlindungan Akun** dengan lockout setelah percobaan login gagal
- **Kebijakan Password** yang komprehensif sesuai standar keamanan

#### 🛡️ Fitur Keamanan Berlapis
- **Rate Limiting** untuk mencegah serangan brute force
- **Security Headers** lengkap (XSS Protection, Content Type Options, Frame Options)
- **Validasi Input** menggunakan Pydantic schemas
- **Pencegahan SQL Injection** dengan SQLAlchemy ORM
- **Konfigurasi CORS** yang aman untuk cross-origin requests
- **Logging Keamanan** yang komprehensif untuk monitoring

#### 🔍 Engine Pemindai Kerentanan
- **SQL Injection Scanner** dengan multiple detection methods
- **Error-based Detection** untuk mendeteksi syntax errors
- **Boolean-based Blind Injection** dengan analisis response
- **Union-based Injection** untuk ekstraksi data
- **Time-based Blind Injection** dengan pengukuran delay
- **XSS Scanner** untuk deteksi Cross-Site Scripting

#### 🏗️ Arsitektur Modern
- **Desain Modular** dengan arsitektur plugin-ready
- **Implementasi Async-First** menggunakan FastAPI dan asyncio
- **Abstraksi Database** dengan SQLAlchemy ORM
- **Manajemen Konfigurasi** berbasis environment variables
- **Testing Komprehensif** dengan pytest dan coverage

## 📁 Struktur Codebase

```
backend/
├── app/                          # Aplikasi utama
│   ├── api/                      # API endpoints
│   │   ├── dependencies.py       # Dependencies untuk autentikasi & rate limiting
│   │   └── v1/                   # API versi 1
│   │       ├── auth.py           # Endpoint autentikasi (login, register, logout)
│   │       ├── scan.py           # Endpoint manajemen scan
│   │       ├── vulnerability.py  # Endpoint manajemen vulnerability
│   │       └── websocket.py      # Real-time WebSocket endpoints
│   ├── config/                   # Konfigurasi aplikasi
│   │   ├── database.py           # Konfigurasi database & session
│   │   ├── logging.py            # Setup logging komprehensif
│   │   └── settings.py           # Environment-based settings
│   ├── models/                   # Database models
│   │   ├── database.py           # Base models & mixins
│   │   ├── user.py               # Model user dengan security features
│   │   ├── scan.py               # Model scan dengan status tracking
│   │   └── vulnerability.py      # Model vulnerability dengan risk classification
│   ├── schemas/                  # Pydantic schemas untuk validasi
│   │   ├── auth.py               # Schemas untuk autentikasi
│   │   ├── scan.py               # Schemas untuk scan management
│   │   └── vulnerability.py      # Schemas untuk vulnerability data
│   ├── services/                 # Business logic & services
│   │   └── scanner/              # Vulnerability scanner engine
│   │       ├── base.py           # Abstract base scanner
│   │       ├── sql_injection.py  # SQL injection scanner
│   │       └── xss_scanner.py    # XSS vulnerability scanner
│   ├── utils/                    # Utility functions
│   │   └── security.py           # JWT management & password validation
│   └── main.py                   # FastAPI application entry point
├── database/                     # Database files & migrations
├── logs/                         # Application logs
├── tests/                        # Test suite
└── requirements.txt              # Python dependencies
```

## 🚀 Quick Start

### Prasyarat Sistem
- **Python 3.8+** (Direkomendasikan Python 3.11)
- **pip** atau **poetry** untuk manajemen dependencies
- **SQLite** (default untuk development) atau **PostgreSQL/MySQL** (production)
- **Git** untuk version control

### Instalasi & Setup

#### 1. Clone Repository
```bash
git clone <repository-url>
cd vulnity-kp/backend
```

#### 2. Buat Virtual Environment
```bash
# Menggunakan venv (built-in Python)
python -m venv venv

# Aktivasi virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate
```

#### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

#### 4. Setup Environment Variables
```bash
# Copy template environment file
cp .env.example .env

# Edit file .env dengan konfigurasi Anda
# Minimal configuration yang diperlukan:
SECRET_KEY="your-super-secret-key-minimum-32-characters"
DATABASE_URL="sqlite:///./database/vulnity_kp.db"
DEBUG=true
```

#### 5. Jalankan Aplikasi
```bash
python -m app.main
```

Aplikasi akan berjalan di `http://localhost:8000`

### 📚 Dokumentasi API
- **Swagger UI**: `http://localhost:8000/docs` - Interactive API documentation
- **ReDoc**: `http://localhost:8000/redoc` - Alternative API documentation
- **Health Check**: `http://localhost:8000/health` - Status aplikasi

## 🔐 Sistem Keamanan yang Diimplementasi

### Autentikasi & Otorisasi

#### JWT Token System
```python
# Contoh response login berhasil
{
  "user": {
    "id": 1,
    "username": "admin",
    "email": "admin@example.com",
    "is_active": true
  },
  "tokens": {
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "token_type": "bearer",
    "expires_in": 1800
  },
  "message": "Login successful"
}
```

#### Account Security Features
- **Account Lockout**: Akun terkunci selama 30 menit setelah 5 kali percobaan login gagal
- **Password Policy**: Minimum 8 karakter dengan kombinasi huruf besar, kecil, angka, dan simbol
- **Session Management**: Automatic session cleanup dan tracking
- **Two-Factor Authentication**: Support untuk 2FA (dalam pengembangan)

### Security Headers
Setiap response dilengkapi dengan security headers:
```http
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Strict-Transport-Security: max-age=31536000; includeSubDomains (production)
```

### Input Validation & Sanitization
- **Pydantic Schemas**: Validasi input yang ketat pada semua endpoints
- **XSS Prevention**: Sanitasi input untuk mencegah Cross-Site Scripting
- **SQL Injection Prevention**: Penggunaan SQLAlchemy ORM dengan parameterized queries
- **CSRF Protection**: Token-based CSRF protection

### Rate Limiting
```python
# Konfigurasi rate limiting
AUTH_RATE_LIMIT = 100 requests/minute  # Authentication endpoints
API_RATE_LIMIT = 200 requests/minute   # General API endpoints
```

## 🔍 Vulnerability Scanner Engine

### Arsitektur Scanner

#### Base Scanner Class
Scanner engine dibangun dengan arsitektur modular menggunakan abstract base class:

```python
class BaseScanner(ABC):
    """
    Abstract base class untuk semua vulnerability scanners
    Menyediakan functionality umum seperti HTTP client management,
    rate limiting, dan DVWA authentication
    """

    def __init__(self):
        self.session_timeout = 30
        self.max_concurrent_requests = 5
        self.request_delay = 1.0

    @abstractmethod
    async def scan(self, target_url: str, **kwargs) -> Dict[str, Any]:
        """Method yang harus diimplementasi oleh concrete scanners"""
        pass
```

### SQL Injection Scanner

#### Detection Methods
Scanner SQL injection menggunakan 4 metode deteksi utama:

##### 1. Error-based Detection
Mendeteksi SQL syntax errors dalam response:
```python
# Contoh payload error-based
payloads = [
    "'",                    # Single quote untuk trigger syntax error
    '"',                    # Double quote untuk trigger syntax error
    "1' OR '1'='1",        # Boolean injection
]

# Pattern error yang dideteksi
error_patterns = [
    r"SQL syntax.*error",
    r"mysqli_sql_exception",
    r"You have an error in your SQL syntax",
    r"Warning: mysql_",
    r"mysql_fetch_array"
]
```

##### 2. Boolean-based Blind Injection
Menganalisis perbedaan response untuk kondisi true/false:
```python
# Payload boolean-based
true_payload = "1' OR '1'='1"   # Kondisi selalu true
false_payload = "1' AND '1'='2" # Kondisi selalu false

# Analisis response length dan content
if true_response_length > baseline_length * 1.5:
    # Kemungkinan vulnerable
    confidence = 0.8
```

##### 3. Union-based Injection
Mendeteksi kemampuan ekstraksi data menggunakan UNION SELECT:
```python
# Payload union-based
union_payloads = [
    "1' UNION SELECT null,version()--",
    "1' UNION SELECT null,database()--",
    "1' UNION SELECT null,user()--"
]

# Deteksi data extraction
if 'mysql' in response.text.lower() or 'version' in response.text.lower():
    vulnerability_detected = True
    confidence = 0.9
```

##### 4. Time-based Blind Injection
Mengukur response time untuk mendeteksi time delays:
```python
# Payload time-based
time_payloads = [
    "1' AND SLEEP(5)--",           # MySQL
    "1'; SELECT pg_sleep(5)--"     # PostgreSQL
]

# Analisis response time
if malicious_time - baseline_time > 4.0:  # 5 detik - tolerance
    vulnerability_detected = True
    confidence = 0.9
```

#### Confidence Scoring System
Scanner menggunakan sistem scoring untuk menentukan tingkat kepercayaan:
- **0.9-1.0**: High confidence (error patterns detected, clear indicators)
- **0.7-0.8**: Medium confidence (response differences, probable indicators)
- **0.5-0.6**: Low confidence (minor differences, possible indicators)
- **< 0.5**: Not vulnerable (threshold tidak tercapai)

## 📊 Database Schema

### Tabel Users
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    full_name VARCHAR(255),

    -- Security fields
    is_active BOOLEAN DEFAULT TRUE,
    is_superuser BOOLEAN DEFAULT FALSE,
    failed_login_attempts INTEGER DEFAULT 0,
    account_locked_until DATETIME,
    password_changed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    must_change_password BOOLEAN DEFAULT FALSE,

    -- Two-factor authentication
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    two_factor_secret VARCHAR(32),

    -- Session tracking
    last_login_at DATETIME,
    last_login_ip VARCHAR(45),

    -- Timestamps
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    -- Soft delete
    is_deleted BOOLEAN DEFAULT FALSE,
    deleted_at DATETIME
);
```

### Tabel Scans
```sql
CREATE TABLE scans (
    id INTEGER PRIMARY KEY,
    target_url VARCHAR(2048) NOT NULL,
    scan_name VARCHAR(255),
    description TEXT,

    -- Scan configuration
    scan_types JSON NOT NULL,           -- ['sql_injection', 'xss']
    max_depth INTEGER DEFAULT 3,
    max_requests INTEGER DEFAULT 1000,
    request_delay FLOAT DEFAULT 1.0,

    -- Scan status dan progress
    status VARCHAR(20) DEFAULT 'pending', -- pending, running, completed, failed, cancelled
    progress INTEGER DEFAULT 0,          -- 0-100%
    current_phase VARCHAR(100),

    -- Timing information
    started_at DATETIME,
    completed_at DATETIME,
    estimated_completion DATETIME,

    -- Results summary
    total_vulnerabilities INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,

    -- Error handling
    error_message TEXT,
    error_details JSON,

    -- User relationship
    user_id INTEGER NOT NULL REFERENCES users(id),

    -- Timestamps & soft delete
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_deleted BOOLEAN DEFAULT FALSE,
    deleted_at DATETIME
);
```

### Tabel Vulnerabilities
```sql
CREATE TABLE vulnerabilities (
    id INTEGER PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    vulnerability_type VARCHAR(50) NOT NULL, -- sql_injection, xss, csrf, etc.
    risk VARCHAR(20) NOT NULL,               -- critical, high, medium, low, info
    status VARCHAR(20) DEFAULT 'open',       -- open, confirmed, false_positive, fixed

    -- Location information
    endpoint VARCHAR(2048) NOT NULL,
    parameter VARCHAR(255),
    method VARCHAR(10) DEFAULT 'GET',

    -- Detection information
    payload TEXT,                    -- Payload yang memicu vulnerability
    confidence FLOAT NOT NULL,       -- Confidence score (0.0 - 1.0)

    -- Evidence dan proof
    evidence JSON,                   -- Structured evidence data
    request_data JSON,               -- HTTP request yang menemukan vulnerability
    response_data JSON,              -- HTTP response yang mengkonfirmasi vulnerability

    -- Technical details
    cwe_id VARCHAR(20),              -- CWE identifier (e.g., "CWE-89")
    cvss_score FLOAT,                -- CVSS score jika applicable
    owasp_category VARCHAR(100),     -- OWASP Top 10 category

    -- Remediation information
    remediation TEXT,
    references JSON,                 -- List of reference URLs

    -- Verification information
    verified BOOLEAN DEFAULT FALSE,
    verified_at DATETIME,
    verification_notes TEXT,

    -- Scan relationship
    scan_id INTEGER NOT NULL REFERENCES scans(id),

    -- Timestamps
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

## 🔄 Real-time Features dengan WebSocket

### WebSocket Connection
Aplikasi menyediakan real-time updates menggunakan WebSocket untuk:

#### Dashboard Updates
```javascript
// Contoh koneksi WebSocket dari frontend
const ws = new WebSocket('ws://localhost:8000/ws/dashboard?token=your_jwt_token');

ws.onmessage = function(event) {
    const data = JSON.parse(event.data);

    switch(data.type) {
        case 'dashboard_update':
            updateDashboardStats(data.data);
            break;
        case 'scan_update':
            updateScanProgress(data.data);
            break;
        case 'notification':
            showNotification(data.data);
            break;
    }
};
```

#### Supported Message Types
1. **dashboard_update**: Update statistik dashboard secara real-time
2. **scan_update**: Progress update untuk scan yang sedang berjalan
3. **notification**: Notifikasi untuk events penting (scan completed, vulnerability found)
4. **ping/pong**: Keep-alive messages untuk menjaga koneksi

#### Connection Management
```python
class ConnectionManager:
    """Manages WebSocket connections untuk real-time updates"""

    def __init__(self):
        self.active_connections: Dict[int, Set[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, user_id: int):
        """Accept WebSocket connection dan register user"""
        await websocket.accept()
        # Store connection by user_id untuk targeted messaging

    async def send_to_user(self, message: Dict[str, Any], user_id: int):
        """Send message ke semua connections dari user tertentu"""
        # Implementation untuk targeted messaging
```

## 🧪 Testing Infrastructure

### Test Coverage
Testing suite mencakup:

#### Unit Tests
- **Authentication Tests** (`test_auth.py`): Login, register, logout, token refresh
- **Scanner Tests** (`test_sql_injection_scanner.py`): SQL injection detection methods
- **Model Tests**: Database model validation dan relationships

#### Integration Tests
- **Scan Integration** (`test_scan_integration.py`): End-to-end scan workflow
- **DVWA Integration** (`test_dvwa_base_url_validation.py`): DVWA authentication dan scanning
- **Scanner Output Validation** (`test_scanner_output_validation.py`): Validasi format output scanner

#### Menjalankan Tests
```bash
# Run semua tests
pytest

# Run dengan coverage report
pytest --cov=app --cov-report=html

# Run specific test file
pytest tests/test_auth.py -v

# Run tests dengan output detail
pytest -v -s
```

### Test Configuration
```python
# conftest.py - Test configuration
@pytest.fixture
def test_client():
    """Create test client untuk testing API endpoints"""
    return TestClient(app)

@pytest.fixture
def test_db():
    """Create test database untuk isolated testing"""
    # Setup test database
    yield db
    # Cleanup after test
```

## ⚙️ Konfigurasi Environment

### Environment Variables
File `.env` configuration yang diperlukan:

```env
# === SECURITY SETTINGS (WAJIB DIUBAH DI PRODUCTION!) ===
SECRET_KEY="your-super-secret-key-minimum-32-characters-long"
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7

# === DATABASE CONFIGURATION ===
DATABASE_URL="sqlite:///./database/vulnity_kp.db"
DATABASE_ECHO=false

# === APPLICATION SETTINGS ===
APP_NAME="Vulnity Backend"
APP_VERSION="1.0.0"
DEBUG=true
ENVIRONMENT="development"
HOST="0.0.0.0"
PORT=8000

# === PASSWORD SECURITY REQUIREMENTS ===
PASSWORD_MIN_LENGTH=8
PASSWORD_REQUIRE_UPPERCASE=true
PASSWORD_REQUIRE_LOWERCASE=true
PASSWORD_REQUIRE_NUMBERS=true
PASSWORD_REQUIRE_SPECIAL=true

# === SCANNER CONFIGURATION ===
SCANNER_MAX_CONCURRENT_REQUESTS=5
SCANNER_REQUEST_TIMEOUT=30
SCANNER_REQUEST_DELAY=1.0
SCANNER_CONFIDENCE_THRESHOLD=0.7

# === CORS SETTINGS ===
ALLOWED_ORIGINS="http://localhost:3000,http://127.0.0.1:3000"
ALLOWED_METHODS="GET,POST,PUT,DELETE,OPTIONS"
ALLOWED_HEADERS="*"

# === LOGGING CONFIGURATION ===
LOG_LEVEL="INFO"
```

## 📡 API Endpoints & Dokumentasi

### Authentication Endpoints

#### POST `/api/v1/auth/register` - Registrasi User Baru
```bash
curl -X POST "http://localhost:8000/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "SecurePass123!",
    "confirm_password": "SecurePass123!",
    "full_name": "Test User"
  }'
```

#### POST `/api/v1/auth/login` - Login User
```bash
curl -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "SecurePass123!",
    "remember_me": false
  }'
```

#### GET `/api/v1/auth/me` - Profile User Saat Ini
```bash
curl -X GET "http://localhost:8000/api/v1/auth/me" \
  -H "Authorization: Bearer your_access_token"
```

### Scan Management Endpoints

#### POST `/api/v1/scan/start` - Memulai Scan Baru
```bash
curl -X POST "http://localhost:8000/api/v1/scan/start" \
  -H "Authorization: Bearer your_access_token" \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "http://localhost/dvwa/vulnerabilities/sqli/?id=1",
    "scan_name": "DVWA SQL Injection Test",
    "description": "Testing SQL injection pada DVWA",
    "scan_types": ["sql_injection"],
    "max_depth": 3,
    "max_requests": 100,
    "request_delay": 1.0
  }'
```

#### GET `/api/v1/scan/` - List Semua Scan User
```bash
curl -X GET "http://localhost:8000/api/v1/scan/?skip=0&limit=10" \
  -H "Authorization: Bearer your_access_token"
```

#### GET `/api/v1/scan/{scan_id}` - Detail Scan Tertentu
```bash
curl -X GET "http://localhost:8000/api/v1/scan/1" \
  -H "Authorization: Bearer your_access_token"
```

### Vulnerability Management Endpoints

#### GET `/api/v1/vulnerability/` - List Vulnerabilities
```bash
curl -X GET "http://localhost:8000/api/v1/vulnerability/?risk_level=critical&limit=20" \
  -H "Authorization: Bearer your_access_token"
```

#### GET `/api/v1/vulnerability/{vuln_id}` - Detail Vulnerability
```bash
curl -X GET "http://localhost:8000/api/v1/vulnerability/1" \
  -H "Authorization: Bearer your_access_token"
```

#### PATCH `/api/v1/vulnerability/{vuln_id}` - Update Status Vulnerability
```bash
curl -X PATCH "http://localhost:8000/api/v1/vulnerability/1" \
  -H "Authorization: Bearer your_access_token" \
  -H "Content-Type: application/json" \
  -d '{
    "status": "confirmed",
    "verification_notes": "Vulnerability telah diverifikasi dan dikonfirmasi"
  }'
```

### Health Check & Monitoring

#### GET `/health` - Status Kesehatan Aplikasi
```bash
curl -X GET "http://localhost:8000/health"

# Response:
{
  "status": "healthy",
  "service": "Vulnity Backend",
  "version": "1.0.0",
  "environment": "development"
}
```

### Response Format Examples

#### Successful Scan Response
```json
{
  "scan_id": 1,
  "target_url": "http://localhost/dvwa/vulnerabilities/sqli/?id=1",
  "scan_name": "DVWA SQL Injection Test",
  "status": "running",
  "progress": 45,
  "current_phase": "Testing parameter: id",
  "started_at": "2025-01-23T10:30:00Z",
  "estimated_completion": "2025-01-23T10:35:00Z",
  "message": "Scan initiated successfully"
}
```

#### Vulnerability Detail Response
```json
{
  "id": 1,
  "title": "SQL Injection - Boolean OR True",
  "description": "Boolean-based injection dengan always true condition",
  "vulnerability_type": "boolean_blind_sql_injection",
  "risk": "high",
  "status": "open",
  "endpoint": "http://localhost/dvwa/vulnerabilities/sqli/",
  "parameter": "id",
  "method": "GET",
  "payload": "1' OR '1'='1",
  "confidence": 0.8,
  "evidence": {
    "baseline_length": 1234,
    "malicious_length": 2456,
    "length_difference": 1222,
    "length_ratio": 1.99
  },
  "cwe_id": "CWE-89",
  "owasp_category": "A03:2021 – Injection",
  "verified": false,
  "created_at": "2025-01-23T10:32:15Z"
}
```

## 🚀 Deployment Instructions

### Development Environment

#### 1. Setup Database
```bash
# Untuk SQLite (default development)
# Database akan dibuat otomatis saat aplikasi pertama kali dijalankan

# Untuk PostgreSQL (production)
# 1. Install PostgreSQL
# 2. Buat database baru
createdb vulnity_production

# 3. Update DATABASE_URL di .env
DATABASE_URL="postgresql://username:password@localhost/vulnity_production"
```

#### 2. Jalankan Development Server
```bash
# Dengan auto-reload untuk development
python -m app.main

# Atau menggunakan uvicorn langsung
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Production Deployment

#### 1. Setup Production Environment
```bash
# 1. Clone repository di server production
git clone <repository-url> /opt/vulnity-backend
cd /opt/vulnity-backend/backend

# 2. Buat virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Setup environment variables
cp .env.example .env.production
# Edit .env.production dengan konfigurasi production
```

#### 2. Production Environment Variables
```env
# .env.production
SECRET_KEY="production-secret-key-32-characters-minimum"
DEBUG=false
ENVIRONMENT="production"
DATABASE_URL="postgresql://user:pass@localhost/vulnity_prod"
ALLOWED_ORIGINS="https://yourdomain.com"
LOG_LEVEL="WARNING"
```

#### 3. Setup dengan Systemd (Linux)
```ini
# /etc/systemd/system/vulnity-backend.service
[Unit]
Description=Vulnity Backend API
After=network.target

[Service]
Type=exec
User=vulnity
Group=vulnity
WorkingDirectory=/opt/vulnity-backend/backend
Environment=PATH=/opt/vulnity-backend/backend/venv/bin
EnvironmentFile=/opt/vulnity-backend/backend/.env.production
ExecStart=/opt/vulnity-backend/backend/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

```bash
# Enable dan start service
sudo systemctl enable vulnity-backend
sudo systemctl start vulnity-backend
sudo systemctl status vulnity-backend
```

#### 4. Setup Reverse Proxy dengan Nginx
```nginx
# /etc/nginx/sites-available/vulnity-backend
server {
    listen 80;
    server_name api.yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # WebSocket support
    location /ws/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

#### 5. Setup SSL dengan Let's Encrypt
```bash
# Install certbot
sudo apt install certbot python3-certbot-nginx

# Dapatkan SSL certificate
sudo certbot --nginx -d api.yourdomain.com

# Auto-renewal
sudo crontab -e
# Tambahkan line berikut:
0 12 * * * /usr/bin/certbot renew --quiet
```

### Docker Deployment (Alternative)

#### 1. Dockerfile
```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create non-root user
RUN useradd --create-home --shell /bin/bash vulnity
USER vulnity

# Expose port
EXPOSE 8000

# Run application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

#### 2. Docker Compose
```yaml
# docker-compose.yml
version: '3.8'

services:
  backend:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://vulnity:password@db:5432/vulnity
      - SECRET_KEY=your-production-secret-key
      - DEBUG=false
    depends_on:
      - db
    volumes:
      - ./logs:/app/logs

  db:
    image: postgres:15
    environment:
      - POSTGRES_DB=vulnity
      - POSTGRES_USER=vulnity
      - POSTGRES_PASSWORD=password
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  postgres_data:
```

```bash
# Deploy dengan Docker Compose
docker-compose up -d
```

## 🔧 Monitoring & Maintenance

### Log Management
```bash
# View application logs
tail -f logs/vulnity_kp.log

# View security logs
tail -f logs/security.log

# View error logs
tail -f logs/vulnity_kp_errors.log

# Log rotation sudah dikonfigurasi otomatis (10MB per file, 5 backup files)
```

### Database Maintenance
```bash
# Backup database (SQLite)
cp database/vulnity_kp.db database/backup_$(date +%Y%m%d_%H%M%S).db

# Backup database (PostgreSQL)
pg_dump vulnity_production > backup_$(date +%Y%m%d_%H%M%S).sql
```

### Performance Monitoring
```python
# Health check endpoint memberikan informasi status
GET /health

# Response:
{
  "status": "healthy",
  "service": "Vulnity Backend",
  "version": "1.0.0",
  "environment": "production",
  "database_status": "connected",
  "uptime": "2 days, 14:32:15"
}
```

## 🛠️ Development Guide

### Menambahkan Scanner Baru

#### 1. Buat Scanner Class Baru
```python
# app/services/scanner/new_scanner.py
from .base import BaseScanner

class NewVulnerabilityScanner(BaseScanner):
    """Scanner untuk vulnerability type baru"""

    def __init__(self):
        super().__init__()
        self.logger = get_logger("scanner.new_vulnerability")

    async def scan(self, target_url: str, **kwargs) -> Dict[str, Any]:
        """Implementasi scanning logic"""
        scan_results = {
            'target_url': target_url,
            'scan_type': 'new_vulnerability',
            'vulnerabilities': [],
            'scan_summary': {
                'total_tests': 0,
                'vulnerabilities_found': 0
            }
        }

        # Implementasi detection logic di sini

        return scan_results
```

#### 2. Registrasi Scanner di Scan Service
```python
# app/api/v1/scan.py - dalam execute_vulnerability_scan function
elif scan_type == ScanType.NEW_VULNERABILITY.value:
    scanner = NewVulnerabilityScanner()
    scan_results = await scanner.scan(target_url)
```

#### 3. Update Enum Types
```python
# app/models/scan.py
class ScanType(enum.Enum):
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    NEW_VULNERABILITY = "new_vulnerability"  # Tambahkan type baru

# app/models/vulnerability.py
class VulnerabilityType(enum.Enum):
    # ... existing types
    NEW_VULNERABILITY_TYPE = "new_vulnerability_type"
```

### Menambahkan API Endpoint Baru

#### 1. Buat Schema untuk Request/Response
```python
# app/schemas/new_feature.py
from pydantic import BaseModel

class NewFeatureRequest(BaseModel):
    parameter1: str
    parameter2: int

class NewFeatureResponse(BaseModel):
    result: str
    status: str
```

#### 2. Implementasi Endpoint
```python
# app/api/v1/new_feature.py
from fastapi import APIRouter, Depends
from app.schemas.new_feature import NewFeatureRequest, NewFeatureResponse

router = APIRouter(prefix="/new-feature", tags=["new-feature"])

@router.post("/", response_model=NewFeatureResponse)
async def create_new_feature(
    request: NewFeatureRequest,
    current_user: User = Depends(get_current_user)
):
    # Implementasi business logic
    return NewFeatureResponse(result="success", status="completed")
```

#### 3. Registrasi Router
```python
# app/main.py
from app.api.v1.new_feature import router as new_feature_router

app.include_router(new_feature_router, prefix="/api/v1")
```

### Code Style & Best Practices

#### 1. Naming Conventions
- **Files**: snake_case (e.g., `sql_injection_scanner.py`)
- **Classes**: PascalCase (e.g., `SQLInjectionScanner`)
- **Functions/Variables**: snake_case (e.g., `scan_target_url`)
- **Constants**: UPPER_SNAKE_CASE (e.g., `MAX_CONCURRENT_REQUESTS`)

#### 2. Error Handling
```python
# Selalu gunakan try-catch dengan logging yang proper
try:
    result = await risky_operation()
    logger.info(f"Operation successful: {result}")
    return result
except SpecificException as e:
    logger.error(f"Specific error occurred: {str(e)}")
    raise HTTPException(status_code=400, detail="Specific error message")
except Exception as e:
    logger.error(f"Unexpected error: {str(e)}", exc_info=True)
    raise HTTPException(status_code=500, detail="Internal server error")
```

#### 3. Security Considerations
```python
# Selalu validasi input
@field_validator('url')
@classmethod
def validate_url(cls, v: str) -> str:
    if not v.startswith(('http://', 'https://')):
        raise ValueError('URL must start with http:// or https://')
    return v

# Gunakan rate limiting untuk endpoints sensitif
@router.post("/sensitive-endpoint", dependencies=[Depends(auth_rate_limit)])
async def sensitive_operation():
    pass
```

## 🔍 Troubleshooting

### Common Issues & Solutions

#### 1. Database Connection Error
```bash
# Error: "database is locked"
# Solution: Pastikan tidak ada proses lain yang menggunakan database
lsof database/vulnity_kp.db
kill -9 <process_id>
```

#### 2. Authentication Issues
```bash
# Error: "Invalid or expired token"
# Solution: Check SECRET_KEY dan token expiration
# Regenerate token dengan login ulang
```

#### 3. Scanner Timeout
```bash
# Error: "Request timeout"
# Solution: Increase SCANNER_REQUEST_TIMEOUT di .env
SCANNER_REQUEST_TIMEOUT=60
```

#### 4. DVWA Authentication Failed
```bash
# Error: "DVWA authentication failed"
# Solution:
# 1. Pastikan DVWA running di localhost
# 2. Check default credentials (admin/password)
# 3. Verify DVWA security level (set ke 'low' untuk testing)
```

### Debug Mode
```bash
# Enable debug logging
LOG_LEVEL=DEBUG python -m app.main

# Check logs untuk detailed information
tail -f logs/vulnity_kp.log | grep DEBUG
```

## 📚 Resources & References

### Documentation Links
- **FastAPI Documentation**: https://fastapi.tiangolo.com/
- **SQLAlchemy Documentation**: https://docs.sqlalchemy.org/
- **Pydantic Documentation**: https://docs.pydantic.dev/
- **OWASP Top 10**: https://owasp.org/www-project-top-ten/
- **CWE Database**: https://cwe.mitre.org/

### Security Resources
- **DVWA Setup Guide**: https://github.com/digininja/DVWA
- **SQL Injection Prevention**: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- **JWT Best Practices**: https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/

### Testing Resources
- **pytest Documentation**: https://docs.pytest.org/
- **httpx Documentation**: https://www.python-httpx.org/

## 🤝 Contributing

### Development Workflow
1. **Fork repository** dan buat branch baru untuk feature
2. **Follow code style** dan naming conventions
3. **Add comprehensive tests** untuk semua new features
4. **Update documentation** sesuai dengan perubahan
5. **Submit pull request** dengan deskripsi yang jelas

### Code Review Checklist
- [ ] Code mengikuti style guide yang ada
- [ ] Tests coverage minimal 80%
- [ ] Documentation telah diupdate
- [ ] Security considerations telah dipertimbangkan
- [ ] Error handling yang proper
- [ ] Logging yang adequate

## 📄 License

MIT License - Lihat file LICENSE untuk detail lengkap.

---

**Vulnity Backend** - Dikembangkan dengan ❤️ untuk keamanan aplikasi web yang lebih baik.
