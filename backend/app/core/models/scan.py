"""
Scan Models - Pydantic schemas dan SQLAlchemy models untuk scanning
"""

from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, ForeignKey, JSON
from sqlalchemy.orm import relationship
from app.config.database import Base
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum

# Base is imported from database config


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanType(str, Enum):
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    FULL_SCAN = "full_scan"


# SQLAlchemy Models
class Scan(Base):
    __tablename__ = "scans"
    
    id = Column(Integer, primary_key=True, index=True)
    target_url = Column(String(500), nullable=False)
    scan_type = Column(String(50), nullable=False, default=ScanType.SQL_INJECTION)
    status = Column(String(20), nullable=False, default=ScanStatus.PENDING)
    
    # Authentication credentials (encrypted)
    username = Column(String(255), nullable=True)
    password = Column(String(255), nullable=True)
    
    # Scan metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    
    # Results
    results = Column(JSON, nullable=True)
    summary = Column(JSON, nullable=True)
    error_message = Column(Text, nullable=True)
    
    # Progress tracking
    progress = Column(Integer, default=0)  # 0-100
    current_step = Column(String(255), nullable=True)
    
    # User relationship
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    user = relationship("User", back_populates="scans")


# Pydantic Schemas
class ScanCreate(BaseModel):
    target_url: str = Field(..., min_length=1, max_length=500)
    scan_type: ScanType = ScanType.SQL_INJECTION
    username: Optional[str] = None
    password: Optional[str] = None


class ScanUpdate(BaseModel):
    status: Optional[ScanStatus] = None
    progress: Optional[int] = Field(None, ge=0, le=100)
    current_step: Optional[str] = None
    results: Optional[Dict[str, Any]] = None
    summary: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


class VulnerabilityResponse(BaseModel):
    type: str
    severity: str
    payload: str
    confidence: float
    extracted_data: List[str] = []
    error_disclosure: List[str] = []
    response_time: Optional[float] = None
    details: Dict[str, Any] = {}


class ScanSummaryResponse(BaseModel):
    total_vulnerabilities: int
    severity_breakdown: Dict[str, int]
    injection_types_found: Dict[str, int]
    success_rate: float
    total_payloads_tested: int
    scan_duration: float


class ScanResponse(BaseModel):
    id: int
    target_url: str
    scan_type: ScanType
    status: ScanStatus
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    progress: int = 0
    current_step: Optional[str] = None
    vulnerabilities: List[VulnerabilityResponse] = []
    summary: Optional[ScanSummaryResponse] = None
    error_message: Optional[str] = None
    user_id: int
    
    class Config:
        from_attributes = True


class ScanProgressResponse(BaseModel):
    scan_id: int
    status: ScanStatus
    progress: int
    current_step: str
    message: str
    vulnerabilities_found: int
    
    class Config:
        from_attributes = True
