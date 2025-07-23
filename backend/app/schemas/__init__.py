# Schemas package for Vulnity-KP Backend

from .auth import (
    UserLogin, UserRegister, PasswordChange, TokenResponse,
    AuthResponse, LogoutResponse, UserProfile, TokenRefresh, UserSessionResponse
)
from .scan import (
    ScanRequest, ScanResponse, ScanListResponse, ScanDetailResponse,
    ScanStatusUpdate, ScanStatsResponse, ScanCancelRequest, ScanExportRequest
)
from .vulnerability import (
    VulnerabilityResponse, VulnerabilityDetailResponse, VulnerabilityListResponse,
    VulnerabilityUpdateRequest, VulnerabilityStatsResponse, VulnerabilityFilterRequest,
    VulnerabilityExportRequest
)

__all__ = [
    # Auth schemas
    "UserLogin",
    "UserRegister",
    "PasswordChange",
    "TokenResponse",
    "AuthResponse",
    "LogoutResponse",
    "UserProfile",
    "TokenRefresh",
    "UserSessionResponse",

    # Scan schemas
    "ScanRequest",
    "ScanResponse",
    "ScanListResponse",
    "ScanDetailResponse",
    "ScanStatusUpdate",
    "ScanStatsResponse",
    "ScanCancelRequest",
    "ScanExportRequest",

    # Vulnerability schemas
    "VulnerabilityResponse",
    "VulnerabilityDetailResponse",
    "VulnerabilityListResponse",
    "VulnerabilityUpdateRequest",
    "VulnerabilityStatsResponse",
    "VulnerabilityFilterRequest",
    "VulnerabilityExportRequest"
]
