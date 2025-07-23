"""
Scan schemas for request/response validation
Pydantic models for vulnerability scanning API data validation
Based on existing auth.py patterns and DVWA analysis findings
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, field_validator, ConfigDict, HttpUrl
import re
from urllib.parse import urlparse

from app.models.scan import ScanStatus, ScanType


class ScanRequest(BaseModel):
    """Scan request schema following auth.py patterns"""
    target_url: str = Field(..., min_length=1, max_length=2048, description="Target URL to scan")
    scan_name: Optional[str] = Field(None, max_length=255, description="Optional scan name")
    description: Optional[str] = Field(None, max_length=1000, description="Scan description")
    scan_types: List[str] = Field(..., min_length=1, description="List of scan types to perform")
    max_depth: int = Field(default=3, ge=1, le=10, description="Maximum crawling depth")
    max_requests: int = Field(default=1000, ge=1, le=10000, description="Maximum number of requests")
    request_delay: float = Field(default=1.0, ge=0.1, le=10.0, description="Delay between requests in seconds")
    
    @field_validator('target_url')
    @classmethod
    def validate_target_url(cls, v: str) -> str:
        """Validate target URL following security patterns from auth.py"""
        from app.config.settings import get_settings

        v = v.strip()
        if not v:
            raise ValueError('Target URL cannot be empty')

        # Basic URL format validation
        try:
            parsed = urlparse(v)
            if not parsed.scheme or not parsed.netloc:
                raise ValueError('Invalid URL format')

            # Only allow HTTP and HTTPS
            if parsed.scheme.lower() not in ['http', 'https']:
                raise ValueError('Only HTTP and HTTPS protocols are allowed')

            # Security checks - prevent SSRF (but allow localhost in development)
            settings = get_settings()

            # Allow localhost/internal networks in development environment
            if settings.ENVIRONMENT.lower() in ['development', 'dev', 'testing', 'test']:
                # In development, allow localhost for DVWA testing
                host = parsed.netloc.split(':')[0].lower()
                if host in ['localhost', '127.0.0.1'] and '/dvwa/' in v.lower():
                    # Allow DVWA testing in development
                    return v

            # Production security checks - prevent SSRF
            forbidden_hosts = [
                'localhost', '127.0.0.1', '0.0.0.0', '::1',
                '10.', '172.16.', '172.17.', '172.18.', '172.19.',
                '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
                '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
                '172.30.', '172.31.', '192.168.'
            ]

            host = parsed.netloc.split(':')[0].lower()
            for forbidden in forbidden_hosts:
                if host.startswith(forbidden):
                    raise ValueError('Target URL points to internal/private network')

        except Exception as e:
            if isinstance(e, ValueError):
                raise e
            raise ValueError('Invalid URL format')

        return v
    
    @field_validator('scan_types')
    @classmethod
    def validate_scan_types(cls, v: List[str]) -> List[str]:
        """Validate scan types"""
        if not v:
            raise ValueError('At least one scan type must be specified')
        
        valid_types = [scan_type.value for scan_type in ScanType]
        for scan_type in v:
            if scan_type not in valid_types:
                raise ValueError(f'Invalid scan type: {scan_type}. Valid types: {valid_types}')
        
        return v
    
    @field_validator('scan_name')
    @classmethod
    def validate_scan_name(cls, v: Optional[str]) -> Optional[str]:
        """Validate scan name following auth.py security patterns"""
        if v is None:
            return v
        
        v = v.strip()
        if not v:
            return None
        
        # Check for dangerous patterns
        dangerous_patterns = ['<', '>', '"', "'", '&', 'script', 'javascript:', 'data:']
        for pattern in dangerous_patterns:
            if pattern.lower() in v.lower():
                raise ValueError('Scan name contains invalid characters')
        
        return v


class ScanResponse(BaseModel):
    """Scan response schema following auth.py patterns"""
    model_config = ConfigDict(from_attributes=True)
    
    scan_id: int = Field(..., description="Unique scan identifier")
    target_url: str = Field(..., description="Target URL being scanned")
    scan_name: Optional[str] = Field(None, description="Scan name")
    status: str = Field(..., description="Current scan status")
    progress: int = Field(..., description="Scan progress percentage")
    current_phase: Optional[str] = Field(None, description="Current scanning phase")
    started_at: Optional[datetime] = Field(None, description="Scan start time")
    estimated_completion: Optional[datetime] = Field(None, description="Estimated completion time")
    message: str = Field(default="Scan initiated successfully", description="Response message")


class ScanListResponse(BaseModel):
    """Scan list item response schema"""
    model_config = ConfigDict(from_attributes=True)
    
    id: int = Field(..., description="Scan ID")
    target_url: str = Field(..., description="Target URL")
    scan_name: Optional[str] = Field(None, description="Scan name")
    status: str = Field(..., description="Scan status")
    progress: int = Field(..., description="Progress percentage")
    total_vulnerabilities: int = Field(..., description="Total vulnerabilities found")
    critical_count: int = Field(..., description="Critical vulnerabilities count")
    high_count: int = Field(..., description="High risk vulnerabilities count")
    created_at: datetime = Field(..., description="Scan creation time")
    started_at: Optional[datetime] = Field(None, description="Scan start time")
    completed_at: Optional[datetime] = Field(None, description="Scan completion time")


class ScanDetailResponse(BaseModel):
    """Detailed scan response schema"""
    model_config = ConfigDict(from_attributes=True)
    
    id: int = Field(..., description="Scan ID")
    target_url: str = Field(..., description="Target URL")
    scan_name: Optional[str] = Field(None, description="Scan name")
    description: Optional[str] = Field(None, description="Scan description")
    status: str = Field(..., description="Scan status")
    progress: int = Field(..., description="Progress percentage")
    current_phase: Optional[str] = Field(None, description="Current scanning phase")
    
    # Configuration
    scan_types: List[str] = Field(..., description="Scan types performed")
    max_depth: int = Field(..., description="Maximum crawling depth")
    max_requests: int = Field(..., description="Maximum requests")
    request_delay: float = Field(..., description="Request delay")
    
    # Timing
    created_at: datetime = Field(..., description="Creation time")
    started_at: Optional[datetime] = Field(None, description="Start time")
    completed_at: Optional[datetime] = Field(None, description="Completion time")
    estimated_completion: Optional[datetime] = Field(None, description="Estimated completion")
    
    # Results summary
    total_vulnerabilities: int = Field(..., description="Total vulnerabilities")
    critical_count: int = Field(..., description="Critical vulnerabilities")
    high_count: int = Field(..., description="High risk vulnerabilities")
    medium_count: int = Field(..., description="Medium risk vulnerabilities")
    low_count: int = Field(..., description="Low risk vulnerabilities")
    
    # Error information
    error_message: Optional[str] = Field(None, description="Error message if failed")


class ScanStatusUpdate(BaseModel):
    """Schema for updating scan status"""
    status: str = Field(..., description="New scan status")
    progress: Optional[int] = Field(None, ge=0, le=100, description="Progress percentage")
    current_phase: Optional[str] = Field(None, description="Current phase")
    error_message: Optional[str] = Field(None, description="Error message")
    
    @field_validator('status')
    @classmethod
    def validate_status(cls, v: str) -> str:
        """Validate scan status"""
        valid_statuses = [status.value for status in ScanStatus]
        if v not in valid_statuses:
            raise ValueError(f'Invalid status: {v}. Valid statuses: {valid_statuses}')
        return v


class ScanStatsResponse(BaseModel):
    """Scan statistics response schema"""
    total_scans: int = Field(..., description="Total number of scans")
    running_scans: int = Field(..., description="Currently running scans")
    completed_scans: int = Field(..., description="Completed scans")
    failed_scans: int = Field(..., description="Failed scans")
    total_vulnerabilities: int = Field(..., description="Total vulnerabilities found")
    critical_vulnerabilities: int = Field(..., description="Critical vulnerabilities")
    high_vulnerabilities: int = Field(..., description="High risk vulnerabilities")


class ScanCancelRequest(BaseModel):
    """Schema for cancelling a scan"""
    reason: Optional[str] = Field(None, max_length=500, description="Cancellation reason")


class ScanExportRequest(BaseModel):
    """Schema for exporting scan results"""
    format: str = Field(..., description="Export format (json, csv, pdf)")
    include_evidence: bool = Field(default=True, description="Include vulnerability evidence")
    
    @field_validator('format')
    @classmethod
    def validate_format(cls, v: str) -> str:
        """Validate export format"""
        valid_formats = ['json', 'csv', 'pdf']
        if v.lower() not in valid_formats:
            raise ValueError(f'Invalid format: {v}. Valid formats: {valid_formats}')
        return v.lower()
