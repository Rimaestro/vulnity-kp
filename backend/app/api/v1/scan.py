"""
Scan API endpoints for vulnerability scanning functionality
Following existing auth.py patterns and DVWA analysis findings
"""

from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request, BackgroundTasks, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc, asc

from app.config.database import get_db
from app.config.logging import get_logger
from app.api.dependencies import get_current_user, api_rate_limit, get_client_ip
from app.models.user import User
from app.models.scan import Scan, ScanStatus, ScanType
from app.schemas.scan import (
    ScanRequest, ScanResponse, ScanListResponse, ScanDetailResponse,
    ScanStatusUpdate, ScanStatsResponse, ScanCancelRequest
)

# Setup logging following existing pattern
scanner_logger = get_logger("scanner")
security_logger = get_logger("security")

# Create router following auth.py pattern
router = APIRouter(prefix="/scan", tags=["scanning"])


@router.post("/start", response_model=ScanResponse, dependencies=[Depends(api_rate_limit)])
async def start_scan(
    scan_request: ScanRequest,
    background_tasks: BackgroundTasks,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Start a new vulnerability scan
    Following existing auth.py security patterns
    """
    
    client_ip = get_client_ip(request)
    
    # Log scan initiation
    scanner_logger.info(f"Scan request from user: {current_user.username} for URL: {scan_request.target_url} from {client_ip}")
    
    # Check if user has any running scans (limit concurrent scans)
    running_scans = db.query(Scan).filter(
        Scan.user_id == current_user.id,
        Scan.status == ScanStatus.RUNNING,
        Scan.is_deleted == False
    ).count()
    
    if running_scans >= 3:  # Limit to 3 concurrent scans per user
        scanner_logger.warning(f"User {current_user.username} exceeded concurrent scan limit")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Maximum number of concurrent scans reached. Please wait for existing scans to complete."
        )
    
    # Create scan record
    scan = Scan(
        target_url=scan_request.target_url,
        scan_name=scan_request.scan_name,
        description=scan_request.description,
        scan_types=scan_request.scan_types,
        max_depth=scan_request.max_depth,
        max_requests=scan_request.max_requests,
        request_delay=scan_request.request_delay,
        status=ScanStatus.PENDING,
        user_id=current_user.id
    )
    
    db.add(scan)
    db.commit()
    db.refresh(scan)
    
    # Start background scanning task
    background_tasks.add_task(
        execute_vulnerability_scan,
        scan.id,
        scan_request.target_url,
        scan_request.scan_types,
        db
    )
    
    scanner_logger.info(f"Scan {scan.id} initiated for user: {current_user.username}")
    
    return ScanResponse(
        scan_id=scan.id,
        target_url=scan.target_url,
        scan_name=scan.scan_name,
        status=scan.status.value,
        progress=scan.progress,
        current_phase=scan.current_phase,
        started_at=scan.started_at,
        estimated_completion=scan.estimated_completion,
        message="Scan initiated successfully"
    )


@router.get("/", response_model=List[ScanListResponse])
async def list_scans(
    request: Request,
    skip: int = Query(0, ge=0, description="Number of scans to skip"),
    limit: int = Query(50, ge=1, le=100, description="Number of scans to return"),
    status_filter: Optional[str] = Query(None, description="Filter by scan status"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    List user's scans with pagination and filtering
    Following existing auth.py patterns
    """
    
    client_ip = get_client_ip(request)
    scanner_logger.info(f"Scan list request from user: {current_user.username} from {client_ip}")
    
    # Build query
    query = db.query(Scan).filter(
        Scan.user_id == current_user.id,
        Scan.is_deleted == False
    )
    
    # Apply status filter if provided
    if status_filter:
        try:
            status_enum = ScanStatus(status_filter)
            query = query.filter(Scan.status == status_enum)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid status filter: {status_filter}"
            )
    
    # Apply pagination and ordering
    scans = query.order_by(desc(Scan.created_at)).offset(skip).limit(limit).all()
    
    return [ScanListResponse.model_validate(scan) for scan in scans]


@router.get("/{scan_id}", response_model=ScanDetailResponse)
async def get_scan_detail(
    scan_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get detailed scan information
    Following existing auth.py security patterns
    """
    
    client_ip = get_client_ip(request)
    
    # Get scan with ownership check
    scan = db.query(Scan).filter(
        Scan.id == scan_id,
        Scan.user_id == current_user.id,
        Scan.is_deleted == False
    ).first()
    
    if not scan:
        scanner_logger.warning(f"Unauthorized scan access attempt by {current_user.username} for scan {scan_id} from {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    scanner_logger.info(f"Scan detail request for {scan_id} by user: {current_user.username}")
    
    return ScanDetailResponse.model_validate(scan)


@router.patch("/{scan_id}/status", response_model=ScanResponse)
async def update_scan_status(
    scan_id: int,
    status_update: ScanStatusUpdate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Update scan status (for internal use or admin)
    Following existing auth.py patterns
    """
    
    client_ip = get_client_ip(request)
    
    # Get scan with ownership check
    scan = db.query(Scan).filter(
        Scan.id == scan_id,
        Scan.user_id == current_user.id,
        Scan.is_deleted == False
    ).first()
    
    if not scan:
        scanner_logger.warning(f"Unauthorized scan status update attempt by {current_user.username} for scan {scan_id}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    # Update scan status
    old_status = scan.status.value
    scan.status = ScanStatus(status_update.status)
    
    if status_update.progress is not None:
        scan.progress = status_update.progress
    
    if status_update.current_phase is not None:
        scan.current_phase = status_update.current_phase
    
    if status_update.error_message is not None:
        scan.error_message = status_update.error_message
    
    # Set completion time if scan is completed
    if scan.status == ScanStatus.COMPLETED and not scan.completed_at:
        scan.completed_at = datetime.utcnow()
    
    db.commit()
    db.refresh(scan)
    
    scanner_logger.info(f"Scan {scan_id} status updated from {old_status} to {scan.status.value} by user: {current_user.username}")
    
    return ScanResponse(
        scan_id=scan.id,
        target_url=scan.target_url,
        scan_name=scan.scan_name,
        status=scan.status.value,
        progress=scan.progress,
        current_phase=scan.current_phase,
        started_at=scan.started_at,
        estimated_completion=scan.estimated_completion,
        message="Scan status updated successfully"
    )


@router.post("/{scan_id}/cancel", response_model=ScanResponse)
async def cancel_scan(
    scan_id: int,
    cancel_request: ScanCancelRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Cancel a running scan
    Following existing auth.py security patterns
    """
    
    client_ip = get_client_ip(request)
    
    # Get scan with ownership check
    scan = db.query(Scan).filter(
        Scan.id == scan_id,
        Scan.user_id == current_user.id,
        Scan.is_deleted == False
    ).first()
    
    if not scan:
        scanner_logger.warning(f"Unauthorized scan cancellation attempt by {current_user.username} for scan {scan_id}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    # Check if scan can be cancelled
    if scan.status not in [ScanStatus.PENDING, ScanStatus.RUNNING]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot cancel scan with status: {scan.status.value}"
        )
    
    # Cancel scan
    scan.status = ScanStatus.CANCELLED
    scan.completed_at = datetime.utcnow()
    scan.error_message = cancel_request.reason or "Scan cancelled by user"
    
    db.commit()
    db.refresh(scan)
    
    scanner_logger.info(f"Scan {scan_id} cancelled by user: {current_user.username}")
    
    return ScanResponse(
        scan_id=scan.id,
        target_url=scan.target_url,
        scan_name=scan.scan_name,
        status=scan.status.value,
        progress=scan.progress,
        current_phase=scan.current_phase,
        started_at=scan.started_at,
        estimated_completion=scan.estimated_completion,
        message="Scan cancelled successfully"
    )


async def execute_vulnerability_scan(scan_id: int, target_url: str, scan_types: List[str], db: Session):
    """
    Background task to execute vulnerability scan
    Integrated with concrete SQL injection scanner implementation
    """

    scan = None
    try:
        # Update scan status to running
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            scanner_logger.error(f"Scan {scan_id} not found for background task")
            return

        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.utcnow()
        scan.current_phase = "Initializing scan"
        scan.progress = 10
        db.commit()

        scanner_logger.info(f"Background scan task started for scan {scan_id}")

        # Import scanners here to avoid circular imports
        from app.services.scanner import SQLInjectionScanner
        from app.services.scanner.xss_scanner import XSSScanner
        from app.models.vulnerability import Vulnerability, VulnerabilityType, VulnerabilityRisk, VulnerabilityStatus

        total_vulnerabilities = 0
        vulnerability_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }

        # Process each scan type
        for i, scan_type in enumerate(scan_types):
            try:
                # Update progress
                progress = 20 + (i * 60 // len(scan_types))
                scan.progress = progress
                scan.current_phase = f"Scanning for {scan_type}"
                db.commit()

                scanner_logger.info(f"Starting {scan_type} scan for {target_url}")

                # Execute appropriate scanner based on scan type
                scanner = None
                scan_results = None

                if scan_type == ScanType.SQL_INJECTION.value:
                    scanner = SQLInjectionScanner()
                    scan_results = await scanner.scan(target_url)
                elif scan_type == ScanType.XSS.value:
                    scanner = XSSScanner()
                    scan_results = await scanner.scan(target_url)
                else:
                    scanner_logger.warning(f"Unsupported scan type: {scan_type}")
                    continue

                # Process scan results
                if scan_results and 'vulnerabilities' in scan_results:
                    for vuln_data in scan_results['vulnerabilities']:
                        # Create vulnerability record
                        vulnerability = Vulnerability(
                            title=vuln_data['title'],
                            description=vuln_data['description'],
                            vulnerability_type=VulnerabilityType(vuln_data['vulnerability_type']),
                            risk=VulnerabilityRisk(vuln_data['risk']),
                            status=VulnerabilityStatus.OPEN,
                            endpoint=vuln_data['endpoint'],
                            parameter=vuln_data['parameter'],
                            method=vuln_data['method'],
                            payload=vuln_data['payload'],
                            confidence=vuln_data['confidence'],
                            evidence=vuln_data['evidence'],
                            request_data=vuln_data['request_data'],
                            response_data=vuln_data['response_data'],
                            scan_id=scan_id
                        )

                        db.add(vulnerability)
                        total_vulnerabilities += 1

                        # Count by risk level
                        risk_level = vuln_data['risk']
                        if risk_level == VulnerabilityRisk.CRITICAL.value:
                            vulnerability_counts['critical'] += 1
                        elif risk_level == VulnerabilityRisk.HIGH.value:
                            vulnerability_counts['high'] += 1
                        elif risk_level == VulnerabilityRisk.MEDIUM.value:
                            vulnerability_counts['medium'] += 1
                        elif risk_level == VulnerabilityRisk.LOW.value:
                            vulnerability_counts['low'] += 1

                        scanner_logger.info(f"Created vulnerability: {vuln_data['title']}")

                # Cleanup scanner resources
                if scanner:
                    await scanner.cleanup()

            except Exception as scan_type_error:
                scanner_logger.error(f"Error scanning {scan_type}: {str(scan_type_error)}")
                continue

        # Update scan completion
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.utcnow()
        scan.progress = 100
        scan.current_phase = "Scan completed"

        # Update vulnerability counts
        scan.total_vulnerabilities = total_vulnerabilities
        scan.critical_count = vulnerability_counts['critical']
        scan.high_count = vulnerability_counts['high']
        scan.medium_count = vulnerability_counts['medium']
        scan.low_count = vulnerability_counts['low']

        db.commit()

        scanner_logger.info(
            f"Background scan task completed for scan {scan_id}. "
            f"Found {total_vulnerabilities} vulnerabilities"
        )

    except Exception as e:
        scanner_logger.error(f"Error in background scan task for scan {scan_id}: {str(e)}")
        if scan:
            scan.status = ScanStatus.FAILED
            scan.completed_at = datetime.utcnow()
            scan.error_message = str(e)
            scan.progress = 0
            scan.current_phase = "Scan failed"
            db.commit()


@router.get("/stats/summary", response_model=ScanStatsResponse)
async def get_scan_stats(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get scan statistics for current user
    Following existing auth.py patterns
    """
    
    # Get user's scans
    user_scans = db.query(Scan).filter(
        Scan.user_id == current_user.id,
        Scan.is_deleted == False
    )
    
    total_scans = user_scans.count()
    running_scans = user_scans.filter(Scan.status == ScanStatus.RUNNING).count()
    completed_scans = user_scans.filter(Scan.status == ScanStatus.COMPLETED).count()
    failed_scans = user_scans.filter(Scan.status == ScanStatus.FAILED).count()
    
    # Calculate vulnerability stats
    total_vulnerabilities = sum(scan.total_vulnerabilities for scan in user_scans.all())
    critical_vulnerabilities = sum(scan.critical_count for scan in user_scans.all())
    high_vulnerabilities = sum(scan.high_count for scan in user_scans.all())
    
    return ScanStatsResponse(
        total_scans=total_scans,
        running_scans=running_scans,
        completed_scans=completed_scans,
        failed_scans=failed_scans,
        total_vulnerabilities=total_vulnerabilities,
        critical_vulnerabilities=critical_vulnerabilities,
        high_vulnerabilities=high_vulnerabilities
    )
