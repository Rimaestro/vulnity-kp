"""
Security utilities for authentication and authorization
JWT token management and password validation based on DVWA analysis
"""

import secrets
import string
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from jose import JWTError, jwt
from passlib.context import CryptContext
import re

from app.config.settings import settings
from app.config.logging import security_logger


# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class PasswordValidator:
    """
    Password validation based on DVWA security analysis
    Implements strong password requirements
    """
    
    @staticmethod
    def validate_password(password: str) -> Dict[str, Any]:
        """
        Validate password against security requirements
        Returns validation result with detailed feedback
        """
        errors = []
        
        # Length check
        if len(password) < settings.PASSWORD_MIN_LENGTH:
            errors.append(f"Password must be at least {settings.PASSWORD_MIN_LENGTH} characters long")
        
        # Uppercase check
        if settings.PASSWORD_REQUIRE_UPPERCASE and not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
        
        # Lowercase check
        if settings.PASSWORD_REQUIRE_LOWERCASE and not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")
        
        # Numbers check
        if settings.PASSWORD_REQUIRE_NUMBERS and not re.search(r'\d', password):
            errors.append("Password must contain at least one number")
        
        # Special characters check
        if settings.PASSWORD_REQUIRE_SPECIAL and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("Password must contain at least one special character")
        
        # Common password patterns (basic check)
        common_patterns = [
            r'123456', r'password', r'admin', r'qwerty', r'abc123',
            r'letmein', r'welcome', r'monkey', r'dragon'
        ]
        
        for pattern in common_patterns:
            if re.search(pattern, password.lower()):
                errors.append("Password contains common patterns and is not secure")
                break
        

        
        return {
            "is_valid": len(errors) == 0,
            "errors": errors,
            "strength": _calculate_password_strength(password)
        }


def _calculate_password_strength(password: str) -> str:
    """Calculate password strength score"""
    score = 0
    
    # Length bonus
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    if len(password) >= 16:
        score += 1
    
    # Character variety bonus
    if re.search(r'[a-z]', password):
        score += 1
    if re.search(r'[A-Z]', password):
        score += 1
    if re.search(r'\d', password):
        score += 1
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 1
    
    # Complexity bonus
    if len(set(password)) > len(password) * 0.7:  # Character diversity
        score += 1
    
    if score <= 3:
        return "weak"
    elif score <= 5:
        return "medium"
    elif score <= 7:
        return "strong"
    else:
        return "very_strong"


class JWTManager:
    """JWT token management with enhanced security"""
    
    @staticmethod
    def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        """Create JWT access token"""
        to_encode = data.copy()
        
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        
        to_encode.update({
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "access"
        })
        
        encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
        
        security_logger.info(f"Access token created for user: {data.get('sub', 'unknown')}")
        
        return encoded_jwt
    
    @staticmethod
    def create_refresh_token(data: Dict[str, Any]) -> str:
        """Create JWT refresh token"""
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        
        to_encode.update({
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "refresh"
        })
        
        encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
        
        security_logger.info(f"Refresh token created for user: {data.get('sub', 'unknown')}")
        
        return encoded_jwt
    
    @staticmethod
    def verify_token(token: str, token_type: str = "access") -> Optional[Dict[str, Any]]:
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
            
            # Verify token type
            if payload.get("type") != token_type:
                security_logger.warning(f"Invalid token type. Expected: {token_type}, Got: {payload.get('type')}")
                return None
            
            # Verify expiration
            exp = payload.get("exp")
            if exp is None or datetime.fromtimestamp(exp) < datetime.utcnow():
                security_logger.warning("Token has expired")
                return None
            
            return payload
            
        except JWTError as e:
            security_logger.warning(f"JWT verification failed: {str(e)}")
            return None
    
    @staticmethod
    def get_token_payload(token: str) -> Optional[Dict[str, Any]]:
        """Get token payload without verification (for debugging)"""
        try:
            return jwt.get_unverified_claims(token)
        except JWTError:
            return None


def generate_secure_token(length: int = 32) -> str:
    """Generate cryptographically secure random token"""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def hash_password(password: str) -> str:
    """Hash password using bcrypt"""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash"""
    return pwd_context.verify(plain_password, hashed_password)


def is_safe_url(url: str, allowed_hosts: Optional[list] = None) -> bool:
    """
    Check if URL is safe for redirects
    Prevents open redirect vulnerabilities
    """
    if not url:
        return False
    
    # Block javascript: and data: URLs
    if url.lower().startswith(('javascript:', 'data:', 'vbscript:')):
        return False
    
    # Allow relative URLs
    if url.startswith('/') and not url.startswith('//'):
        return True
    
    # Check allowed hosts if provided
    if allowed_hosts:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return parsed.netloc in allowed_hosts
    
    return False
