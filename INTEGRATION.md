# 🔗 Vulnity Frontend-Backend Integration Guide

Panduan lengkap untuk menjalankan dan menggunakan integrasi frontend-backend Vulnity Web Vulnerability Scanner.

## 🚀 Quick Start

### Prerequisites
- Python 3.8+ dengan pip
- Node.js 16+ dengan npm
- Git

### 1. Setup Backend
```bash
cd backend

# Activate virtual environment
source venv/bin/activate  # Linux/Mac
# atau
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt

# Run integration tests
python test_integration.py

# Start backend server
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### 2. Setup Frontend
```bash
cd frontend

# Install dependencies
npm install

# Start development server
npm run dev
```

### 3. Access Application
- **Frontend**: http://localhost:5173
- **Backend API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs

## 🔧 Integration Features

### ✅ Implemented Features

#### Authentication Flow
- [x] User registration and login
- [x] JWT token management
- [x] Protected routes
- [x] Automatic token refresh
- [x] Logout functionality

#### Scan Management
- [x] Start new vulnerability scans
- [x] Real-time scan progress tracking
- [x] Scan status monitoring
- [x] Results visualization
- [x] Vulnerability details display

#### API Integration
- [x] Axios HTTP client with interceptors
- [x] Error handling and user feedback
- [x] Loading states
- [x] Type-safe API calls

#### Data Flow
- [x] TypeScript interfaces matching backend models
- [x] Proper error handling
- [x] Real-time updates via polling

## 📡 API Endpoints

### Authentication
```
POST /api/v1/auth/register    - Register new user
POST /api/v1/auth/login       - Login user (form data)
POST /api/v1/auth/login/json  - Login user (JSON)
GET  /api/v1/auth/me          - Get current user
```

### Scanning
```
POST /api/v1/scan/start       - Start new scan
GET  /api/v1/scan/status/{id} - Get scan status
GET  /api/v1/scan/list        - List user scans
```

### Reports
```
GET  /api/v1/reports/{id}/export - Export scan report
```

## 🧪 Testing Integration

### Run Integration Tests
```bash
cd backend
python test_integration.py
```

### Test Workflow
1. **Database Setup**: Creates tables and connections
2. **Authentication**: Tests user creation and login
3. **Scan Service**: Tests scan creation and management
4. **Scanner Integration**: Tests core scanner functionality

### Manual Testing
1. Start both backend and frontend
2. Navigate to http://localhost:5173
3. Register a new account
4. Login with credentials
5. Start a new scan with target URL
6. Monitor scan progress in real-time
7. View results when scan completes

## 🔄 Data Flow

### Scan Workflow
```
Frontend (ScanPage) 
    ↓ POST /api/v1/scan/start
Backend (ScanService)
    ↓ Background Task
Scanner (VulnityScanner)
    ↓ Real-time Updates
Frontend (ResultsPage)
    ↓ Polling GET /api/v1/scan/status/{id}
Results Display
```

### Authentication Flow
```
Frontend (LoginPage)
    ↓ POST /api/v1/auth/login/json
Backend (AuthService)
    ↓ JWT Token
Frontend (AuthContext)
    ↓ Store Token
Protected Routes Access
```

## 🛠️ Development

### Backend Development
```bash
cd backend
source venv/bin/activate
python -m uvicorn app.main:app --reload
```

### Frontend Development
```bash
cd frontend
npm run dev
```

### Database Management
```bash
# Reset database
rm backend/vulnity.db

# Run integration tests to recreate
python backend/test_integration.py
```

## 🐛 Troubleshooting

### Common Issues

#### CORS Errors
- Ensure backend CORS settings include frontend URL
- Check `backend/app/config/settings.py` CORS_ORIGINS

#### Authentication Issues
- Clear browser localStorage
- Check JWT token expiration
- Verify backend auth endpoints

#### Scan Failures
- Ensure target URL is accessible
- Check scanner configuration
- Verify DVWA is running (if testing with DVWA)

#### Database Issues
- Delete `backend/vulnity.db` and restart
- Run integration tests to recreate tables

### Debug Mode
```bash
# Backend with debug logging
LOG_LEVEL=DEBUG python -m uvicorn app.main:app --reload

# Frontend with debug
npm run dev -- --debug
```

## 📊 Performance

### Optimization Features
- Real-time scan progress updates (3-second polling)
- Background scan execution
- Efficient database queries
- JWT token caching
- Component-level loading states

### Monitoring
- Backend logs in `backend/logs/vulnity.log`
- Browser console for frontend errors
- Network tab for API call monitoring

## 🔒 Security

### Implemented Security
- JWT token authentication
- Password hashing with bcrypt
- CORS protection
- SQL injection prevention
- Input validation

### Security Headers
- Automatic HTTPS redirect (production)
- Content Security Policy
- XSS protection

## 📈 Next Steps

### Potential Enhancements
- [ ] WebSocket for real-time updates
- [ ] Scan scheduling
- [ ] Report export (PDF/JSON)
- [ ] User management dashboard
- [ ] Scan history and analytics
- [ ] Multiple vulnerability types
- [ ] Scan templates

---

**Vulnity Scanner** - Professional web vulnerability assessment with integrated frontend-backend architecture.
