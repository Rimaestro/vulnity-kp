"""
Simple Scan Service - Demo Mode
"""

import logging
from datetime import datetime
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session

from app.core.models.scan import (
    Scan, ScanCreate, ScanResponse, ScanStatus
)

logger = logging.getLogger(__name__)


class ScanService:
    def __init__(self, db: Session):
        self.db = db
    
    async def create_scan(self, scan_data: ScanCreate, user_id: int) -> ScanResponse:
        """Membuat scan baru"""
        try:
            # Create scan record
            db_scan = Scan(
                target_url=scan_data.target_url,
                scan_type=scan_data.scan_type,
                username=scan_data.username,
                password=scan_data.password,
                user_id=user_id,
                status=ScanStatus.PENDING,
                current_step="Initializing scan..."
            )
            
            self.db.add(db_scan)
            self.db.commit()
            self.db.refresh(db_scan)
            
            logger.info(f"Created scan {db_scan.id} for user {user_id}")
            
            return self._scan_to_response(db_scan)
            
        except Exception as e:
            logger.error(f"Error creating scan: {str(e)}")
            self.db.rollback()
            raise
    
    async def get_scan_by_id(self, scan_id: int, user_id: int) -> Optional[ScanResponse]:
        """Mendapatkan scan berdasarkan ID"""
        try:
            scan = self.db.query(Scan).filter(
                and_(Scan.id == scan_id, Scan.user_id == user_id)
            ).first()

            if not scan:
                return None

            return self._scan_to_response(scan)

        except Exception as e:
            logger.error(f"Error getting scan {scan_id}: {str(e)}")
            raise

    async def get_scan_by_id_demo(self, scan_id: int) -> Optional[ScanResponse]:
        """Mendapatkan scan berdasarkan ID untuk demo mode (tanpa user restriction)"""
        try:
            scan = self.db.query(Scan).filter(Scan.id == scan_id).first()

            if not scan:
                return None

            return self._scan_to_response(scan)

        except Exception as e:
            logger.error(f"Error getting scan {scan_id}: {str(e)}")
            raise
    
    async def get_user_scans(self, user_id: int, skip: int = 0, limit: int = 100, 
                           status: Optional[ScanStatus] = None) -> List[ScanResponse]:
        """Mendapatkan daftar scan user"""
        try:
            query = self.db.query(Scan).filter(Scan.user_id == user_id)
            
            if status:
                query = query.filter(Scan.status == status)
            
            scans = query.offset(skip).limit(limit).all()
            
            return [self._scan_to_response(scan) for scan in scans]
            
        except Exception as e:
            logger.error(f"Error getting user scans: {str(e)}")
            raise
    
    async def update_scan(self, scan_id: int, scan_update: ScanUpdate) -> Optional[ScanResponse]:
        """Update scan data"""
        try:
            scan = self.db.query(Scan).filter(Scan.id == scan_id).first()
            if not scan:
                return None
            
            # Update fields
            for field, value in scan_update.dict(exclude_unset=True).items():
                setattr(scan, field, value)
            
            self.db.commit()
            self.db.refresh(scan)
            
            return self._scan_to_response(scan)
            
        except Exception as e:
            logger.error(f"Error updating scan {scan_id}: {str(e)}")
            self.db.rollback()
            raise
    
    async def execute_scan(self, scan_id: int):
        """Execute scan in background"""
        try:
            # Get scan from database
            scan = self.db.query(Scan).filter(Scan.id == scan_id).first()
            if not scan:
                logger.error(f"Scan {scan_id} not found")
                return
            
            # Update status to running
            await self.update_scan(scan_id, ScanUpdate(
                status=ScanStatus.RUNNING,
                started_at=datetime.utcnow(),
                progress=10,
                current_step="Initializing scanner..."
            ))
            
            # Initialize scanner
            scanner = VulnityScanner(scan.target_url)
            
            # Update progress
            await self.update_scan(scan_id, ScanUpdate(
                progress=20,
                current_step="Authenticating..."
            ))
            
            # Authenticate if credentials provided
            auth_success = True
            if scan.username and scan.password:
                auth_success = scanner.authenticate(scan.username, scan.password)
            
            if not auth_success:
                await self.update_scan(scan_id, ScanUpdate(
                    status=ScanStatus.FAILED,
                    error_message="Authentication failed",
                    completed_at=datetime.utcnow()
                ))
                return
            
            # Update progress
            await self.update_scan(scan_id, ScanUpdate(
                progress=40,
                current_step="Starting vulnerability scan..."
            ))
            
            # Perform scan
            scan_results = scanner.perform_full_scan(scan.username, scan.password)
            
            # Update progress
            await self.update_scan(scan_id, ScanUpdate(
                progress=80,
                current_step="Processing results..."
            ))
            
            # Process results
            vulnerabilities = self._process_scan_results(scan_results)
            summary = self._generate_summary(scan_results)
            
            # Complete scan
            await self.update_scan(scan_id, ScanUpdate(
                status=ScanStatus.COMPLETED,
                progress=100,
                current_step="Scan completed",
                results=scan_results,
                summary=summary,
                completed_at=datetime.utcnow()
            ))
            
            logger.info(f"Scan {scan_id} completed successfully")
            
        except Exception as e:
            logger.error(f"Error executing scan {scan_id}: {str(e)}")
            await self.update_scan(scan_id, ScanUpdate(
                status=ScanStatus.FAILED,
                error_message=str(e),
                completed_at=datetime.utcnow()
            ))
    
    def _scan_to_response(self, scan: Scan) -> ScanResponse:
        """Convert Scan model to ScanResponse"""
        vulnerabilities = []
        summary = None
        
        if scan.results:
            vulnerabilities = self._extract_vulnerabilities(scan.results)
        
        if scan.summary:
            summary = ScanSummaryResponse(**scan.summary)
        
        return ScanResponse(
            id=scan.id,
            target_url=scan.target_url,
            scan_type=scan.scan_type,
            status=scan.status,
            created_at=scan.created_at,
            started_at=scan.started_at,
            completed_at=scan.completed_at,
            progress=scan.progress,
            current_step=scan.current_step,
            vulnerabilities=vulnerabilities,
            summary=summary,
            error_message=scan.error_message,
            user_id=scan.user_id
        )
    
    def _extract_vulnerabilities(self, results: Dict[str, Any]) -> List[VulnerabilityResponse]:
        """Extract vulnerabilities from scan results"""
        vulnerabilities = []
        
        if "sql_injection" in results:
            sql_results = results["sql_injection"]
            for url, url_results in sql_results.items():
                if isinstance(url_results, list):
                    for vuln in url_results:
                        if vuln.get("vulnerable", False):
                            vulnerabilities.append(VulnerabilityResponse(
                                type=vuln.get("injection_type", "unknown"),
                                severity=vuln.get("severity", "low"),
                                payload=vuln.get("payload", ""),
                                confidence=vuln.get("confidence", 0.0),
                                extracted_data=vuln.get("extracted_data", []),
                                error_disclosure=vuln.get("error_disclosure", []),
                                response_time=vuln.get("response_time"),
                                details=vuln.get("details", {})
                            ))
        
        return vulnerabilities
    
    def _process_scan_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Process and normalize scan results"""
        return results
    
    def _generate_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate scan summary"""
        if "overall_summary" in results:
            return results["overall_summary"]
        
        return {
            "total_vulnerabilities": 0,
            "severity_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "injection_types_found": {},
            "success_rate": 0.0,
            "total_payloads_tested": 0,
            "scan_duration": 0.0
        }
