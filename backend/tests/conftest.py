"""
Pytest configuration and fixtures for Vulnity-KP Backend tests
"""

import pytest
import asyncio
from typing import Generator
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.config.database import get_db, Base
from app.models.user import User


# Test database setup
SQLALCHEMY_DATABASE_URL = "sqlite:///./test_vulnity_kp.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)

TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    """Override database dependency for testing"""
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()


# Override the dependency
app.dependency_overrides[get_db] = override_get_db


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="function")
def db_session():
    """Create a fresh database session for each test"""
    # Create tables
    Base.metadata.create_all(bind=engine)
    
    # Create session
    session = TestingSessionLocal()
    
    try:
        yield session
    finally:
        session.close()
        # Drop tables after test
        Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(db_session) -> Generator:
    """Create a test client"""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def test_user(db_session) -> User:
    """Create a test user"""
    user = User(
        username="testuser",
        email="test@example.com",
        full_name="Test User"
    )
    user.set_password("TestPassword4$7!")
    
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    
    return user


@pytest.fixture
def test_superuser(db_session) -> User:
    """Create a test superuser"""
    user = User(
        username="admin",
        email="admin@example.com",
        full_name="Admin User",
        is_superuser=True
    )
    user.set_password("AdminPassword4$7!")
    
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    
    return user


@pytest.fixture
def auth_headers(client: TestClient, test_user: User) -> dict:
    """Get authentication headers for test user"""
    login_data = {
        "username": test_user.username,
        "password": "TestPassword4$7!"
    }
    
    response = client.post("/api/v1/auth/login", json=login_data)
    assert response.status_code == 200
    
    token_data = response.json()
    access_token = token_data["tokens"]["access_token"]
    
    return {"Authorization": f"Bearer {access_token}"}


@pytest.fixture
def admin_headers(client: TestClient, test_superuser: User) -> dict:
    """Get authentication headers for admin user"""
    login_data = {
        "username": test_superuser.username,
        "password": "AdminPassword4$7!"
    }
    
    response = client.post("/api/v1/auth/login", json=login_data)
    assert response.status_code == 200
    
    token_data = response.json()
    access_token = token_data["tokens"]["access_token"]
    
    return {"Authorization": f"Bearer {access_token}"}
