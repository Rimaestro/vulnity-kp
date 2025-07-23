"""
Integration tests for Scan API endpoints with SQL injection scanner
Testing end-to-end functionality from API to database
"""

import pytest
import asyncio
from unittest.mock import patch, AsyncMock, Mock
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.config.database import get_db
from app.models.user import User
from app.models.scan import Scan, ScanStatus, ScanType
from app.models.vulnerability import Vulnerability, VulnerabilityType, VulnerabilityRisk
from tests.conftest import TestingSessionLocal, override_get_db


class TestScanIntegration:
    """Integration tests for scan functionality"""
    
    @pytest.fixture
    def client(self):
        """Create test client with database override"""
        app.dependency_overrides[get_db] = override_get_db
        return TestClient(app)
    
    @pytest.fixture
    def test_user(self, db_session: Session):
        """Create test user"""
        user = User(
            username="testuser",
            email="test@example.com",
            is_active=True
        )
        user.set_password("testpassword123")
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)
        return user
    
    @pytest.fixture
    def auth_headers(self, client: TestClient, test_user: User):
        """Get authentication headers"""
        login_data = {
            "username": "testuser",
            "password": "testpassword123"
        }
        response = client.post("/api/v1/auth/login", json=login_data)
        assert response.status_code == 200

        token = response.json()["tokens"]["access_token"]
        return {"Authorization": f"Bearer {token}"}
    
    def test_start_scan_endpoint(self, client: TestClient, auth_headers: dict):
        """Test scan start endpoint"""
        scan_data = {
            "target_url": "http://example.com/test?id=1",
            "scan_name": "Test SQL Injection Scan",
            "description": "Integration test scan",
            "scan_types": ["sql_injection"],
            "max_depth": 3,
            "max_requests": 100,
            "request_delay": 1.0
        }
        
        response = client.post(
            "/api/v1/scan/start",
            json=scan_data,
            headers=auth_headers
        )
        
        assert response.status_code == 200
        result = response.json()
        
        assert "scan_id" in result
        assert result["target_url"] == scan_data["target_url"]
        assert result["scan_name"] == scan_data["scan_name"]
        assert result["status"] == "pending"
        assert result["progress"] == 0
    
    def test_start_scan_invalid_url(self, client: TestClient, auth_headers: dict):
        """Test scan start with invalid URL"""
        scan_data = {
            "target_url": "http://localhost/test?id=1",  # Blocked internal URL
            "scan_types": ["sql_injection"]
        }
        
        response = client.post(
            "/api/v1/scan/start",
            json=scan_data,
            headers=auth_headers
        )
        
        assert response.status_code == 422  # Validation error
    
    def test_start_scan_concurrent_limit(self, client: TestClient, auth_headers: dict, db_session: Session, test_user: User):
        """Test concurrent scan limit"""
        # Create 3 running scans (limit is 3)
        for i in range(3):
            scan = Scan(
                target_url=f"http://example.com/test{i}?id=1",
                scan_types=["sql_injection"],
                status=ScanStatus.RUNNING,
                user_id=test_user.id
            )
            db_session.add(scan)
        db_session.commit()
        
        # Try to start another scan
        scan_data = {
            "target_url": "http://example.com/test4?id=1",
            "scan_types": ["sql_injection"]
        }
        
        response = client.post(
            "/api/v1/scan/start",
            json=scan_data,
            headers=auth_headers
        )
        
        assert response.status_code == 429  # Too many requests
        response_data = response.json()
        # Check if response has detail field or message field
        error_message = response_data.get("detail", response_data.get("message", "")).lower()
        assert "concurrent" in error_message or "maximum" in error_message
    
    def test_list_scans_endpoint(self, client: TestClient, auth_headers: dict, db_session: Session, test_user: User):
        """Test scan list endpoint"""
        # Create test scans
        scans = []
        for i in range(3):
            scan = Scan(
                target_url=f"http://example.com/test{i}?id=1",
                scan_name=f"Test Scan {i}",
                scan_types=["sql_injection"],
                status=ScanStatus.COMPLETED,
                total_vulnerabilities=i,
                user_id=test_user.id
            )
            db_session.add(scan)
            scans.append(scan)
        db_session.commit()
        
        response = client.get("/api/v1/scan/", headers=auth_headers)
        
        assert response.status_code == 200
        result = response.json()
        
        assert len(result) == 3
        assert all("id" in scan for scan in result)
        assert all("target_url" in scan for scan in result)
        assert all("status" in scan for scan in result)
    
    def test_get_scan_detail_endpoint(self, client: TestClient, auth_headers: dict, db_session: Session, test_user: User):
        """Test scan detail endpoint"""
        # Create test scan
        scan = Scan(
            target_url="http://example.com/test?id=1",
            scan_name="Detailed Test Scan",
            description="Test scan for detail endpoint",
            scan_types=["sql_injection"],
            status=ScanStatus.COMPLETED,
            total_vulnerabilities=2,
            critical_count=1,
            high_count=1,
            user_id=test_user.id
        )
        db_session.add(scan)
        db_session.commit()
        db_session.refresh(scan)
        
        response = client.get(f"/api/v1/scan/{scan.id}", headers=auth_headers)
        
        assert response.status_code == 200
        result = response.json()
        
        assert result["id"] == scan.id
        assert result["target_url"] == scan.target_url
        assert result["scan_name"] == scan.scan_name
        assert result["description"] == scan.description
        assert result["status"] == scan.status.value
        assert result["total_vulnerabilities"] == 2
        assert result["critical_count"] == 1
        assert result["high_count"] == 1
    
    def test_scan_stats_endpoint(self, client: TestClient, auth_headers: dict, db_session: Session, test_user: User):
        """Test scan statistics endpoint"""
        # Create test scans with different statuses
        scans_data = [
            {"status": ScanStatus.COMPLETED, "vulnerabilities": 5, "critical": 2, "high": 3},
            {"status": ScanStatus.RUNNING, "vulnerabilities": 0, "critical": 0, "high": 0},
            {"status": ScanStatus.FAILED, "vulnerabilities": 0, "critical": 0, "high": 0},
            {"status": ScanStatus.COMPLETED, "vulnerabilities": 3, "critical": 1, "high": 2}
        ]

        for scan_data in scans_data:
            scan = Scan(
                target_url="http://example.com/test?id=1",
                scan_types=["sql_injection"],
                status=scan_data["status"],
                total_vulnerabilities=scan_data["vulnerabilities"],
                critical_count=scan_data["critical"],
                high_count=scan_data["high"],
                user_id=test_user.id
            )
            db_session.add(scan)
        db_session.commit()
        
        response = client.get("/api/v1/scan/stats/summary", headers=auth_headers)
        
        assert response.status_code == 200
        result = response.json()
        
        assert result["total_scans"] == 4
        assert result["running_scans"] == 1
        assert result["completed_scans"] == 2
        assert result["failed_scans"] == 1
        assert result["total_vulnerabilities"] == 8
        assert result["critical_vulnerabilities"] == 3  # 2 + 1 = 3
        assert result["high_vulnerabilities"] == 5  # 3 + 2 = 5
    
    @pytest.mark.asyncio
    async def test_background_scan_execution(self, db_session: Session, test_user: User):
        """Test background scan execution with mocked scanner"""
        from app.api.v1.scan import execute_vulnerability_scan
        
        # Create test scan
        scan = Scan(
            target_url="http://example.com/test?id=1",
            scan_types=["sql_injection"],
            status=ScanStatus.PENDING,
            user_id=test_user.id
        )
        db_session.add(scan)
        db_session.commit()
        db_session.refresh(scan)
        
        # Mock the SQL injection scanner
        mock_scan_results = {
            'vulnerabilities': [
                {
                    'title': 'SQL Injection - Error Based',
                    'description': 'Error-based SQL injection vulnerability',
                    'vulnerability_type': VulnerabilityType.ERROR_BASED_SQLI.value,
                    'risk': VulnerabilityRisk.HIGH.value,
                    'endpoint': 'http://example.com/test?id=1',
                    'parameter': 'id',
                    'method': 'GET',
                    'payload': "'",
                    'confidence': 0.9,
                    'evidence': {'detected_errors': ['SQL syntax error']},
                    'request_data': {'url': 'http://example.com/test?id=1', 'parameter': 'id', 'payload': "'"},
                    'response_data': {'baseline_status': 200, 'malicious_status': 500}
                }
            ]
        }
        
        with patch('app.services.scanner.SQLInjectionScanner') as mock_scanner_class:
            mock_scanner = AsyncMock()
            mock_scanner.scan.return_value = mock_scan_results
            mock_scanner.cleanup.return_value = None
            mock_scanner_class.return_value = mock_scanner

            # Execute background scan
            await execute_vulnerability_scan(
                scan.id, scan.target_url, scan.scan_types, db_session
            )
        
        # Refresh scan from database
        db_session.refresh(scan)
        
        # Verify scan completion
        assert scan.status == ScanStatus.COMPLETED
        assert scan.total_vulnerabilities == 1
        assert scan.high_count == 1
        assert scan.progress == 100
        assert scan.current_phase == "Scan completed"
        
        # Verify vulnerability creation
        vulnerabilities = db_session.query(Vulnerability).filter(
            Vulnerability.scan_id == scan.id
        ).all()
        
        assert len(vulnerabilities) == 1
        vuln = vulnerabilities[0]
        assert vuln.title == 'SQL Injection - Error Based'
        assert vuln.vulnerability_type == VulnerabilityType.ERROR_BASED_SQLI
        assert vuln.risk == VulnerabilityRisk.HIGH
        assert vuln.parameter == 'id'
        assert vuln.payload == "'"
        assert vuln.confidence == 0.9
    
    def test_unauthorized_access(self, client: TestClient):
        """Test unauthorized access to scan endpoints"""
        # Test without authentication
        response = client.get("/api/v1/scan/")
        assert response.status_code == 401
        
        response = client.post("/api/v1/scan/start", json={
            "target_url": "http://example.com/test?id=1",
            "scan_types": ["sql_injection"]
        })
        assert response.status_code == 401
    
    def test_scan_ownership_protection(self, client: TestClient, db_session: Session):
        """Test that users can only access their own scans"""
        # Create two users
        user1 = User(username="user1", email="user1@example.com", is_active=True)
        user1.set_password("password123")
        user2 = User(username="user2", email="user2@example.com", is_active=True)
        user2.set_password("password123")
        
        db_session.add_all([user1, user2])
        db_session.commit()
        db_session.refresh(user1)
        db_session.refresh(user2)
        
        # Create scan for user1
        scan = Scan(
            target_url="http://example.com/test?id=1",
            scan_types=["sql_injection"],
            status=ScanStatus.COMPLETED,
            user_id=user1.id
        )
        db_session.add(scan)
        db_session.commit()
        db_session.refresh(scan)
        
        # Login as user2
        login_data = {"username": "user2", "password": "password123"}
        response = client.post("/api/v1/auth/login", json=login_data)
        token = response.json()["tokens"]["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # Try to access user1's scan
        response = client.get(f"/api/v1/scan/{scan.id}", headers=headers)
        assert response.status_code == 404  # Should not find scan
