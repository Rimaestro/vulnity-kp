"""
User models for authentication and authorization
Enhanced security based on DVWA analysis findings
"""

from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy import Column, String, Boolean, DateTime, Text, Integer, ForeignKey
from sqlalchemy.orm import relationship
from passlib.context import CryptContext

from .database import BaseModel, SoftDeleteMixin


# Password hashing context with secure algorithms
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=12  # Higher rounds for better security
)


class User(BaseModel, SoftDeleteMixin):
    """
    User model with enhanced security features
    Based on DVWA analysis findings for secure authentication
    """
    
    __tablename__ = "users"
    
    # Basic user information
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    full_name = Column(String(255), nullable=True)
    
    # Password and security
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    is_superuser = Column(Boolean, default=False, nullable=False)
    
    # Account security features
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    account_locked_until = Column(DateTime, nullable=True)
    password_changed_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    must_change_password = Column(Boolean, default=False, nullable=False)
    
    # Two-factor authentication
    two_factor_enabled = Column(Boolean, default=False, nullable=False)
    two_factor_secret = Column(String(32), nullable=True)
    
    # Session management
    last_login_at = Column(DateTime, nullable=True)
    last_login_ip = Column(String(45), nullable=True)  # IPv6 support
    
    # Relationships
    sessions = relationship("UserSession", back_populates="user", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="user", cascade="all, delete-orphan", lazy="dynamic")
    
    def set_password(self, password: str) -> None:
        """Set user password with secure hashing"""
        self.hashed_password = pwd_context.hash(password)
        self.password_changed_at = datetime.utcnow()
        self.must_change_password = False
        self.failed_login_attempts = 0
        self.account_locked_until = None
    
    def verify_password(self, password: str) -> bool:
        """Verify password against stored hash"""
        if self.is_account_locked():
            return False
        
        is_valid = pwd_context.verify(password, self.hashed_password)
        
        if not is_valid:
            self.failed_login_attempts += 1
            if self.failed_login_attempts >= 5:  # Lock after 5 failed attempts
                self.account_locked_until = datetime.utcnow() + timedelta(minutes=30)
        else:
            self.failed_login_attempts = 0
            self.account_locked_until = None
            self.last_login_at = datetime.utcnow()
        
        return is_valid
    
    def is_account_locked(self) -> bool:
        """Check if account is currently locked"""
        if self.account_locked_until is None:
            return False
        return datetime.utcnow() < self.account_locked_until
    
    def needs_password_change(self) -> bool:
        """Check if user needs to change password"""
        if self.must_change_password:
            return True
        
        # Force password change after 90 days
        password_age = datetime.utcnow() - self.password_changed_at
        return password_age.days > 90
    
    def unlock_account(self) -> None:
        """Unlock user account (admin function)"""
        self.failed_login_attempts = 0
        self.account_locked_until = None
    
    def __repr__(self):
        return f"<User(username='{self.username}', email='{self.email}')>"


class UserSession(BaseModel):
    """
    User session model for secure session management
    Enhanced based on DVWA session security analysis
    """
    
    __tablename__ = "user_sessions"
    
    # Session identification
    session_token = Column(String(255), unique=True, index=True, nullable=False)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    
    # Session metadata
    ip_address = Column(String(45), nullable=False)  # IPv6 support
    user_agent = Column(Text, nullable=True)
    
    # Session lifecycle
    expires_at = Column(DateTime, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    revoked_at = Column(DateTime, nullable=True)
    
    # Security flags
    is_refresh_token = Column(Boolean, default=False, nullable=False)
    
    # Relationships
    user = relationship("User", back_populates="sessions")
    
    def is_expired(self) -> bool:
        """Check if session is expired"""
        return datetime.utcnow() > self.expires_at
    
    def is_valid(self) -> bool:
        """Check if session is valid and active"""
        return (
            self.is_active and 
            not self.is_expired() and 
            self.revoked_at is None
        )
    
    def revoke(self) -> None:
        """Revoke session"""
        self.is_active = False
        self.revoked_at = datetime.utcnow()
    
    def extend_expiry(self, minutes: int = 30) -> None:
        """Extend session expiry time"""
        self.expires_at = datetime.utcnow() + timedelta(minutes=minutes)
    
    def __repr__(self):
        return f"<UserSession(user_id={self.user_id}, expires_at='{self.expires_at}')>"
