"""
Authentication schemas for request/response validation
Pydantic models for secure API data validation
"""

from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, EmailStr, field_validator, Field, ConfigDict, ValidationInfo
import re

from app.config.settings import settings


class UserLogin(BaseModel):
    """User login request schema"""
    username: str = Field(..., min_length=3, max_length=50, description="Username or email")
    password: str = Field(..., min_length=1, description="User password")
    remember_me: bool = Field(default=False, description="Remember login session")
    
    @field_validator('username')
    @classmethod
    def validate_username(cls, v: str) -> str:
        # Remove whitespace
        v = v.strip()
        if not v:
            raise ValueError('Username cannot be empty')

        # Check for basic injection patterns
        dangerous_patterns = ['<', '>', '"', "'", '&', 'script', 'javascript:', 'data:']
        for pattern in dangerous_patterns:
            if pattern.lower() in v.lower():
                raise ValueError('Username contains invalid characters')

        return v


class UserRegister(BaseModel):
    """User registration request schema"""
    username: str = Field(..., min_length=3, max_length=50, description="Unique username")
    email: EmailStr = Field(..., description="Valid email address")
    password: str = Field(..., min_length=settings.PASSWORD_MIN_LENGTH, description="Strong password")
    confirm_password: str = Field(..., description="Password confirmation")
    full_name: Optional[str] = Field(None, max_length=255, description="Full name")
    
    @field_validator('username')
    @classmethod
    def validate_username(cls, v: str) -> str:
        v = v.strip().lower()

        # Username format validation
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError('Username can only contain letters, numbers, underscores, and hyphens')

        # Reserved usernames
        reserved = ['admin', 'root', 'administrator', 'system', 'api', 'www', 'mail', 'ftp']
        if v in reserved:
            raise ValueError('Username is reserved')

        return v
    
    @field_validator('password')
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        from app.utils.security import PasswordValidator

        validation_result = PasswordValidator.validate_password(v)
        if not validation_result['is_valid']:
            raise ValueError(f"Password validation failed: {', '.join(validation_result['errors'])}")

        return v
    
    @field_validator('confirm_password')
    @classmethod
    def passwords_match(cls, v: str, info: ValidationInfo) -> str:
        if hasattr(info, 'data') and 'password' in info.data and v != info.data['password']:
            raise ValueError('Passwords do not match')
        return v
    
    @field_validator('full_name')
    @classmethod
    def validate_full_name(cls, v: Optional[str]) -> Optional[str]:
        if v:
            v = v.strip()
            # Basic XSS prevention
            if re.search(r'[<>"\']', v):
                raise ValueError('Full name contains invalid characters')
        return v


class PasswordChange(BaseModel):
    """Password change request schema"""
    current_password: str = Field(..., description="Current password")
    new_password: str = Field(..., min_length=settings.PASSWORD_MIN_LENGTH, description="New password")
    confirm_password: str = Field(..., description="New password confirmation")
    
    @field_validator('new_password')
    @classmethod
    def validate_new_password(cls, v: str) -> str:
        from app.utils.security import PasswordValidator

        validation_result = PasswordValidator.validate_password(v)
        if not validation_result['is_valid']:
            raise ValueError(f"Password validation failed: {', '.join(validation_result['errors'])}")

        return v
    
    @field_validator('confirm_password')
    @classmethod
    def passwords_match(cls, v: str, info: ValidationInfo) -> str:
        if hasattr(info, 'data') and 'new_password' in info.data and v != info.data['new_password']:
            raise ValueError('Passwords do not match')
        return v


class PasswordReset(BaseModel):
    """Password reset request schema"""
    email: EmailStr = Field(..., description="Email address for password reset")


class PasswordResetConfirm(BaseModel):
    """Password reset confirmation schema"""
    token: str = Field(..., description="Password reset token")
    new_password: str = Field(..., min_length=settings.PASSWORD_MIN_LENGTH, description="New password")
    confirm_password: str = Field(..., description="New password confirmation")
    
    @field_validator('new_password')
    @classmethod
    def validate_new_password(cls, v: str) -> str:
        from app.utils.security import PasswordValidator

        validation_result = PasswordValidator.validate_password(v)
        if not validation_result['is_valid']:
            raise ValueError(f"Password validation failed: {', '.join(validation_result['errors'])}")

        return v
    
    @field_validator('confirm_password')
    @classmethod
    def passwords_match(cls, v: str, info: ValidationInfo) -> str:
        if hasattr(info, 'data') and 'new_password' in info.data and v != info.data['new_password']:
            raise ValueError('Passwords do not match')
        return v


class TokenResponse(BaseModel):
    """Token response schema"""
    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="JWT refresh token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(..., description="Token expiration time in seconds")


class TokenRefresh(BaseModel):
    """Token refresh request schema"""
    refresh_token: str = Field(..., description="Valid refresh token")


class UserProfile(BaseModel):
    """User profile response schema"""
    id: int
    username: str
    email: str
    full_name: Optional[str]
    is_active: bool
    is_superuser: bool
    created_at: datetime
    last_login_at: Optional[datetime]
    two_factor_enabled: bool
    must_change_password: bool
    
    model_config = ConfigDict(from_attributes=True)


class UserSessionResponse(BaseModel):
    """User session response schema"""
    id: int
    ip_address: str
    user_agent: Optional[str]
    created_at: datetime
    expires_at: datetime
    is_active: bool

    model_config = ConfigDict(from_attributes=True)


class AuthResponse(BaseModel):
    """Authentication response schema"""
    user: UserProfile
    tokens: TokenResponse
    message: str = Field(default="Authentication successful")


class LogoutResponse(BaseModel):
    """Logout response schema"""
    message: str = Field(default="Logout successful")
    revoked_sessions: int = Field(default=0, description="Number of revoked sessions")


class ValidationError(BaseModel):
    """Validation error response schema"""
    field: str
    message: str


class ErrorResponse(BaseModel):
    """Generic error response schema"""
    error: str
    message: str
    details: Optional[List[ValidationError]] = None
