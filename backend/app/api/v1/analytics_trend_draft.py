# Draft endpoint untuk data tren analytics
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from typing import List, Dict, Any
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.models.user import User
from app.config.database import get_db
from app.api.dependencies import get_current_user

router = APIRouter()


from sqlalchemy import func, extract, case

@router.get("/vulnerability/stats/trend")
def get_vulnerability_trend(
    months: int = Query(6, description="Number of months to include"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Calculate the start date for the trend window
    now = datetime.utcnow()
    start_date = (now.replace(day=1, hour=0, minute=0, second=0, microsecond=0) - timedelta(days=months*31)).replace(day=1)

    # Query vulnerabilities for the current user, grouped by year, month, and risk
    q = (
        db.query(
            extract('year', Vulnerability.created_at).label('year'),
            extract('month', Vulnerability.created_at).label('month'),
            Vulnerability.risk,
            func.count(Vulnerability.id).label('count')
        )
        .join(Scan, Vulnerability.scan_id == Scan.id)
        .filter(
            Scan.user_id == current_user.id,
            Vulnerability.created_at >= start_date
        )
        .group_by('year', 'month', Vulnerability.risk)
        .order_by('year', 'month')
    )

    # Build a dict {(year, month): {risk: count}}
    trend_dict = {}
    for row in q:
        ym = (int(row.year), int(row.month))
        if ym not in trend_dict:
            trend_dict[ym] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        risk = row.risk.value if hasattr(row.risk, 'value') else str(row.risk)
        if risk in trend_dict[ym]:
            trend_dict[ym][risk] = row.count

    # Convert to list of dicts sorted by year, month
    trend = []
    for (year, month) in sorted(trend_dict.keys()):
        trend.append({
            "month": f"{year:04d}-{month:02d}",
            **trend_dict[(year, month)]
        })

    return {"trend": trend}


@router.get("/scan/stats/trend")
def get_scan_trend(
    weeks: int = Query(8, description="Number of weeks to include"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Calculate the start date for the trend window
    now = datetime.utcnow()
    start_date = now - timedelta(weeks=weeks)

    # Query scans for the current user, grouped by year, week
    from sqlalchemy import extract, func
    scan_q = (
        db.query(
            extract('year', Scan.started_at).label('year'),
            extract('week', Scan.started_at).label('week'),
            func.count(Scan.id).label('scans'),
            func.coalesce(func.sum(Scan.total_vulnerabilities), 0).label('vulnerabilities')
        )
        .filter(
            Scan.user_id == current_user.id,
            Scan.started_at != None,
            Scan.started_at >= start_date
        )
        .group_by('year', 'week')
        .order_by('year', 'week')
    )

    # Build a dict {(year, week): {scans, vulnerabilities}}
    trend_dict = {}
    for row in scan_q:
        yw = (int(row.year), int(row.week))
        trend_dict[yw] = {"scans": row.scans, "vulnerabilities": row.vulnerabilities}

    # Convert to list of dicts sorted by year, week
    trend = []
    for (year, week) in sorted(trend_dict.keys()):
        trend.append({
            "week": f"{year:04d}-W{week:02d}",
            **trend_dict[(year, week)]
        })

    return {"trend": trend}


@router.get("/fixrate/stats/trend")
def get_fixrate_trend(
    months: int = Query(6, description="Number of months to include"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Calculate the start date for the trend window
    now = datetime.utcnow()
    start_date = (now.replace(day=1, hour=0, minute=0, second=0, microsecond=0) - timedelta(days=months*31)).replace(day=1)

    from sqlalchemy import extract, func, case
    from app.models.vulnerability import VulnerabilityStatus
    # Query vulnerabilities for the current user, grouped by year, month
    q = (
        db.query(
            extract('year', Vulnerability.created_at).label('year'),
            extract('month', Vulnerability.created_at).label('month'),
            func.count(Vulnerability.id).label('total'),
            func.sum(case((Vulnerability.status == VulnerabilityStatus.FIXED, 1), else_=0)).label('fixed')
        )
        .join(Scan, Vulnerability.scan_id == Scan.id)
        .filter(
            Scan.user_id == current_user.id,
            Vulnerability.created_at >= start_date
        )
        .group_by('year', 'month')
        .order_by('year', 'month')
    )

    # Build a dict {(year, month): {fixed, total}}
    trend_dict = {}
    for row in q:
        ym = (int(row.year), int(row.month))
        trend_dict[ym] = {"fixed": int(row.fixed), "total": int(row.total)}

    # Convert to list of dicts sorted by year, month
    trend = []
    for (year, month) in sorted(trend_dict.keys()):
        trend.append({
            "month": f"{year:04d}-{month:02d}",
            **trend_dict[(year, month)]
        })

    return {"trend": trend}

# Contoh response JSON:
# /vulnerability/stats/trend
# { "trend": [ { "month": "2025-01", "critical": 2, "high": 5, "medium": 3, "low": 1 }, ... ] }
# /scan/stats/trend
# { "trend": [ { "week": "2025-W01", "scans": 10, "vulnerabilities": 7 }, ... ] }
# /fixrate/stats/trend
# { "trend": [ { "month": "2025-01", "fixed": 8, "total": 28 }, ... ] }
