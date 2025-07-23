"""
Authentication API tests
Test cases for login, registration, and token management
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.user import User


class TestAuthentication:
    """Test authentication endpoints"""
    
    def test_user_registration(self, client: TestClient, db_session: Session):
        """Test user registration"""
        user_data = {
            "username": "newuser",
            "email": "newuser@example.com",
            "password": "SecureTestPass4$7!",
            "confirm_password": "SecureTestPass4$7!",
            "full_name": "New User"
        }
        
        response = client.post("/api/v1/auth/register", json=user_data)
        assert response.status_code == 200
        
        data = response.json()
        assert data["user"]["username"] == "newuser"
        assert data["user"]["email"] == "newuser@example.com"
        assert "tokens" in data
        assert "access_token" in data["tokens"]
        assert "refresh_token" in data["tokens"]
    
    def test_user_registration_duplicate_username(self, client: TestClient, test_user: User):
        """Test registration with duplicate username"""
        user_data = {
            "username": test_user.username,
            "email": "different@example.com",
            "password": "SecureTestPass4$7!",
            "confirm_password": "SecureTestPass4$7!"
        }
        
        response = client.post("/api/v1/auth/register", json=user_data)
        assert response.status_code == 409
        assert "Username already registered" in response.json()["message"]
    
    def test_user_registration_weak_password(self, client: TestClient):
        """Test registration with weak password"""
        user_data = {
            "username": "newuser",
            "email": "newuser@example.com",
            "password": "weak",
            "confirm_password": "weak"
        }
        
        response = client.post("/api/v1/auth/register", json=user_data)
        assert response.status_code == 422
    
    def test_user_login_success(self, client: TestClient, test_user: User):
        """Test successful user login"""
        login_data = {
            "username": test_user.username,
            "password": "TestPassword4$7!"
        }
        
        response = client.post("/api/v1/auth/login", json=login_data)
        assert response.status_code == 200
        
        data = response.json()
        assert data["user"]["username"] == test_user.username
        assert "tokens" in data
        assert "access_token" in data["tokens"]
        assert "refresh_token" in data["tokens"]
    
    def test_user_login_invalid_credentials(self, client: TestClient, test_user: User):
        """Test login with invalid credentials"""
        login_data = {
            "username": test_user.username,
            "password": "wrongpassword"
        }
        
        response = client.post("/api/v1/auth/login", json=login_data)
        assert response.status_code == 401
        assert "Invalid username or password" in response.json()["message"]
    
    def test_user_login_nonexistent_user(self, client: TestClient):
        """Test login with nonexistent user"""
        login_data = {
            "username": "nonexistent",
            "password": "password"
        }
        
        response = client.post("/api/v1/auth/login", json=login_data)
        assert response.status_code == 401
        assert "Invalid username or password" in response.json()["message"]
    
    def test_get_current_user(self, client: TestClient, auth_headers: dict):
        """Test getting current user profile"""
        response = client.get("/api/v1/auth/me", headers=auth_headers)
        assert response.status_code == 200
        
        data = response.json()
        assert "username" in data
        assert "email" in data
        assert "is_active" in data
    
    def test_get_current_user_unauthorized(self, client: TestClient):
        """Test getting current user without authentication"""
        response = client.get("/api/v1/auth/me")
        assert response.status_code == 401
    
    def test_logout(self, client: TestClient, auth_headers: dict):
        """Test user logout"""
        response = client.post("/api/v1/auth/logout", headers=auth_headers)
        assert response.status_code == 200
        
        data = response.json()
        assert "message" in data
        assert "revoked_sessions" in data
    
    def test_token_refresh(self, client: TestClient, test_user: User):
        """Test token refresh"""
        # First login to get tokens
        login_data = {
            "username": test_user.username,
            "password": "TestPassword4$7!"
        }
        
        login_response = client.post("/api/v1/auth/login", json=login_data)
        assert login_response.status_code == 200
        
        tokens = login_response.json()["tokens"]
        refresh_token = tokens["refresh_token"]
        
        # Refresh token
        refresh_data = {"refresh_token": refresh_token}
        response = client.post("/api/v1/auth/refresh", json=refresh_data)
        assert response.status_code == 200
        
        data = response.json()
        assert "access_token" in data
        assert "expires_in" in data
    
    def test_token_refresh_invalid_token(self, client: TestClient):
        """Test token refresh with invalid token"""
        refresh_data = {"refresh_token": "invalid_token"}
        response = client.post("/api/v1/auth/refresh", json=refresh_data)
        assert response.status_code == 401


class TestPasswordSecurity:
    """Test password security features"""
    
    def test_password_validation_requirements(self, client: TestClient):
        """Test password validation requirements"""
        test_cases = [
            ("short", "Password must be at least"),
            ("nouppercase4$7!", "uppercase letter"),
            ("NOLOWERCASE4$7!", "lowercase letter"),
            ("NoNumbers!", "number"),
            ("NoSpecialChars4$7", "special character"),
            ("password4$7!", "common patterns")
        ]
        
        for password, expected_error in test_cases:
            user_data = {
                "username": f"user_{password}",
                "email": f"{password}@example.com",
                "password": password,
                "confirm_password": password
            }
            
            response = client.post("/api/v1/auth/register", json=user_data)
            assert response.status_code == 422
    
    def test_account_lockout(self, client: TestClient, test_user: User, db_session: Session):
        """Test account lockout after failed attempts"""
        login_data = {
            "username": test_user.username,
            "password": "wrongpassword"
        }
        
        # Make 5 failed login attempts
        for _ in range(5):
            response = client.post("/api/v1/auth/login", json=login_data)
            assert response.status_code == 401
        
        # 6th attempt should result in account lock
        response = client.post("/api/v1/auth/login", json=login_data)
        assert response.status_code == 423
        assert "locked" in response.json()["message"].lower()


class TestSecurityHeaders:
    """Test security headers and middleware"""
    
    def test_security_headers_present(self, client: TestClient):
        """Test that security headers are present"""
        response = client.get("/health")
        
        assert "X-Content-Type-Options" in response.headers
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        
        assert "X-Frame-Options" in response.headers
        assert response.headers["X-Frame-Options"] == "DENY"
        
        assert "X-XSS-Protection" in response.headers
        assert response.headers["X-XSS-Protection"] == "1; mode=block"
    
    def test_server_header_removed(self, client: TestClient):
        """Test that server header is removed"""
        response = client.get("/health")
        assert "server" not in response.headers
