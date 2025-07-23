"""
Authentication API endpoints
Secure login, logout, registration, and token management
"""

from datetime import datetime, timedelta
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from app.config.database import get_db
from app.config.settings import settings
from app.config.logging import auth_logger, security_logger
from app.models.user import User, UserSession
from app.schemas.auth import (
    UserLogin, UserRegister, PasswordChange, TokenResponse,
    AuthResponse, LogoutResponse, UserProfile, TokenRefresh, UserSessionResponse
)
from app.utils.security import JWTManager, generate_secure_token
from app.api.dependencies import (
    get_current_active_user, get_client_ip, get_user_agent, 
    auth_rate_limit
)


router = APIRouter(prefix="/auth", tags=["authentication"])


@router.post("/login", response_model=AuthResponse, dependencies=[Depends(auth_rate_limit)])
async def login(
    user_credentials: UserLogin,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    User login with enhanced security
    Based on DVWA analysis findings for secure authentication
    """
    
    client_ip = get_client_ip(request)
    user_agent = get_user_agent(request)
    
    # Log login attempt
    auth_logger.info(f"Login attempt for user: {user_credentials.username} from {client_ip}")
    
    # Find user by username or email
    user = db.query(User).filter(
        (User.username == user_credentials.username.lower()) |
        (User.email == user_credentials.username.lower())
    ).first()
    
    if not user:
        security_logger.warning(f"Login attempt for non-existent user: {user_credentials.username} from {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )
    
    # Check if account is locked
    if user.is_account_locked():
        security_logger.warning(f"Login attempt for locked account: {user.username} from {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="Account is temporarily locked due to multiple failed login attempts"
        )
    
    # Verify password
    if not user.verify_password(user_credentials.password):
        security_logger.warning(f"Failed login attempt for user: {user.username} from {client_ip}")
        db.commit()  # Save failed attempt count
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )
    
    # Check if user is active
    if not user.is_active:
        security_logger.warning(f"Login attempt for inactive user: {user.username} from {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is inactive"
        )
    
    # Create user session
    session_expires = datetime.utcnow() + timedelta(
        days=settings.REFRESH_TOKEN_EXPIRE_DAYS if user_credentials.remember_me 
        else 1
    )
    
    user_session = UserSession(
        session_token=generate_secure_token(64),
        user_id=user.id,
        ip_address=client_ip,
        user_agent=user_agent,
        expires_at=session_expires
    )
    
    db.add(user_session)
    db.commit()
    db.refresh(user_session)
    
    # Update user login info
    user.last_login_at = datetime.utcnow()
    user.last_login_ip = client_ip
    db.commit()
    
    # Create JWT tokens
    token_data = {
        "sub": user.username,
        "user_id": user.id,
        "session_id": user_session.id
    }
    
    access_token = JWTManager.create_access_token(token_data)
    refresh_token = JWTManager.create_refresh_token(token_data)
    
    # Log successful login
    auth_logger.info(f"Successful login for user: {user.username} from {client_ip}")
    
    return AuthResponse(
        user=UserProfile.model_validate(user),
        tokens=TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        ),
        message="Login successful"
    )


@router.post("/register", response_model=AuthResponse, dependencies=[Depends(auth_rate_limit)])
async def register(
    user_data: UserRegister,
    request: Request,
    db: Session = Depends(get_db)
):
    """User registration with validation"""
    
    client_ip = get_client_ip(request)
    
    # Log registration attempt
    auth_logger.info(f"Registration attempt for user: {user_data.username} from {client_ip}")
    
    # Check if user already exists
    existing_user = db.query(User).filter(
        (User.username == user_data.username.lower()) |
        (User.email == user_data.email.lower())
    ).first()
    
    if existing_user:
        if existing_user.username == user_data.username.lower():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Username already registered"
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email already registered"
            )
    
    # Create new user
    try:
        new_user = User(
            username=user_data.username.lower(),
            email=user_data.email.lower(),
            full_name=user_data.full_name
        )
        new_user.set_password(user_data.password)
        
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        
        # Log successful registration
        auth_logger.info(f"User registered successfully: {new_user.username}")
        
        # Auto-login after registration
        user_agent = get_user_agent(request)
        session_expires = datetime.utcnow() + timedelta(days=1)
        
        user_session = UserSession(
            session_token=generate_secure_token(64),
            user_id=new_user.id,
            ip_address=client_ip,
            user_agent=user_agent,
            expires_at=session_expires
        )
        
        db.add(user_session)
        db.commit()
        db.refresh(user_session)
        
        # Create JWT tokens
        token_data = {
            "sub": new_user.username,
            "user_id": new_user.id,
            "session_id": user_session.id
        }
        
        access_token = JWTManager.create_access_token(token_data)
        refresh_token = JWTManager.create_refresh_token(token_data)
        
        return AuthResponse(
            user=UserProfile.model_validate(new_user),
            tokens=TokenResponse(
                access_token=access_token,
                refresh_token=refresh_token,
                expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
            ),
            message="Registration successful"
        )
        
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User with this username or email already exists"
        )


@router.post("/logout", response_model=LogoutResponse)
async def logout(
    request: Request,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """User logout with session cleanup"""
    
    client_ip = get_client_ip(request)
    
    # Revoke all active sessions for the user
    active_sessions = db.query(UserSession).filter(
        UserSession.user_id == current_user.id,
        UserSession.is_active == True
    ).all()
    
    revoked_count = 0
    for session in active_sessions:
        session.revoke()
        revoked_count += 1
    
    db.commit()
    
    # Log logout
    auth_logger.info(f"User logged out: {current_user.username} from {client_ip}")
    
    return LogoutResponse(
        message="Logout successful",
        revoked_sessions=revoked_count
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    token_data: TokenRefresh,
    request: Request,
    db: Session = Depends(get_db)
):
    """Refresh access token using refresh token"""
    
    client_ip = get_client_ip(request)
    
    # Verify refresh token
    payload = JWTManager.verify_token(token_data.refresh_token, "refresh")
    if not payload:
        security_logger.warning(f"Invalid refresh token attempt from {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token"
        )
    
    # Get user and session
    username = payload.get("sub")
    session_id = payload.get("session_id")
    
    user = db.query(User).filter(User.username == username).first()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive"
        )
    
    # Validate session
    if session_id:
        session = db.query(UserSession).filter(
            UserSession.id == session_id,
            UserSession.user_id == user.id
        ).first()
        
        if not session or not session.is_valid():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session expired or invalid"
            )
        
        # Extend session expiry
        session.extend_expiry(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        db.commit()
    
    # Create new access token
    new_token_data = {
        "sub": user.username,
        "user_id": user.id,
        "session_id": session_id
    }

    access_token = JWTManager.create_access_token(new_token_data)
    
    auth_logger.info(f"Token refreshed for user: {user.username}")
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=token_data.refresh_token,  # Return same refresh token
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )


@router.get("/me", response_model=UserProfile)
async def get_current_user_profile(
    current_user: User = Depends(get_current_active_user)
):
    """Get current user profile"""
    return UserProfile.model_validate(current_user)


@router.get("/sessions", response_model=List[UserSessionResponse])
async def get_user_sessions(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get user's active sessions"""
    sessions = db.query(UserSession).filter(
        UserSession.user_id == current_user.id,
        UserSession.is_active == True
    ).all()

    return [UserSessionResponse.model_validate(session) for session in sessions]
