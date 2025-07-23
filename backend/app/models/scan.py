"""
Scan models for vulnerability scanning functionality
Based on DVWA analysis findings and existing codebase patterns
"""

import enum
from datetime import datetime
from typing import Optional, List
from sqlalchemy import Column, String, Text, Integer, ForeignKey, Enum, Float, JSON, DateTime
from sqlalchemy.orm import relationship

from .database import BaseModel, SoftDeleteMixin


class ScanStatus(enum.Enum):
    """Scan status enumeration"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanType(enum.Enum):
    """Scan type enumeration"""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    CSRF = "csrf"
    DIRECTORY_TRAVERSAL = "directory_traversal"
    FULL_SCAN = "full_scan"


class Scan(BaseModel, SoftDeleteMixin):
    """
    Scan model for storing vulnerability scan information
    Following existing User model patterns and DVWA analysis findings
    """
    
    __tablename__ = "scans"
    
    # Basic scan information
    target_url = Column(String(2048), nullable=False, index=True)
    scan_name = Column(String(255), nullable=True)
    description = Column(Text, nullable=True)
    
    # Scan configuration
    scan_types = Column(JSON, nullable=False)  # List of scan types to perform
    max_depth = Column(Integer, default=3, nullable=False)
    max_requests = Column(Integer, default=1000, nullable=False)
    request_delay = Column(Float, default=1.0, nullable=False)  # Delay between requests in seconds
    
    # Scan status and progress
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING, nullable=False, index=True)
    progress = Column(Integer, default=0, nullable=False)  # Progress percentage (0-100)
    current_phase = Column(String(100), nullable=True)  # Current scanning phase
    
    # Timing information
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    estimated_completion = Column(DateTime, nullable=True)
    
    # Results summary
    total_vulnerabilities = Column(Integer, default=0, nullable=False)
    critical_count = Column(Integer, default=0, nullable=False)
    high_count = Column(Integer, default=0, nullable=False)
    medium_count = Column(Integer, default=0, nullable=False)
    low_count = Column(Integer, default=0, nullable=False)
    
    # Error information
    error_message = Column(Text, nullable=True)
    error_details = Column(JSON, nullable=True)
    
    # User relationship (following existing pattern)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    user = relationship("User", back_populates="scans")
    
    # Vulnerabilities relationship
    vulnerabilities = relationship(
        "Vulnerability", 
        back_populates="scan",
        cascade="all, delete-orphan",
        lazy="dynamic"  # For efficient counting and pagination
    )
    
    def __repr__(self):
        return f"<Scan(id={self.id}, target_url='{self.target_url}', status='{self.status.value}')>"
    
    def is_running(self) -> bool:
        """Check if scan is currently running"""
        return self.status == ScanStatus.RUNNING
    
    def is_completed(self) -> bool:
        """Check if scan is completed"""
        return self.status == ScanStatus.COMPLETED
    
    def is_failed(self) -> bool:
        """Check if scan failed"""
        return self.status == ScanStatus.FAILED
    
    def get_duration(self) -> Optional[float]:
        """Get scan duration in seconds"""
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        elif self.started_at:
            return (datetime.utcnow() - self.started_at).total_seconds()
        return None
    
    def update_vulnerability_counts(self):
        """Update vulnerability count summary"""
        from .vulnerability import VulnerabilityRisk
        
        # Reset counts
        self.total_vulnerabilities = 0
        self.critical_count = 0
        self.high_count = 0
        self.medium_count = 0
        self.low_count = 0
        
        # Count vulnerabilities by risk level
        for vuln in self.vulnerabilities:
            self.total_vulnerabilities += 1
            if vuln.risk == VulnerabilityRisk.CRITICAL:
                self.critical_count += 1
            elif vuln.risk == VulnerabilityRisk.HIGH:
                self.high_count += 1
            elif vuln.risk == VulnerabilityRisk.MEDIUM:
                self.medium_count += 1
            elif vuln.risk == VulnerabilityRisk.LOW:
                self.low_count += 1
    
    def to_dict(self):
        """Convert scan to dictionary with additional computed fields"""
        data = super().to_dict()
        data.update({
            'duration': self.get_duration(),
            'is_running': self.is_running(),
            'is_completed': self.is_completed(),
            'is_failed': self.is_failed(),
            'vulnerability_summary': {
                'total': self.total_vulnerabilities,
                'critical': self.critical_count,
                'high': self.high_count,
                'medium': self.medium_count,
                'low': self.low_count
            }
        })
        return data
