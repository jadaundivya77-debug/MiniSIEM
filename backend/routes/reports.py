"""
Reporting & Compliance Export API Routes for MiniSIEM X
Generates executive summaries and formats downloadable CSV reports.
"""
from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.services.report_service import ReportService

router = APIRouter(prefix="/api/reports", tags=["Reports"])

@router.get("/summary")
def get_report_summary(db: Session = Depends(get_db)):
    """Returns high-level SOC analytics, KPI metrics, and security recommendations."""
    return ReportService.generate_summary(db)

@router.get("/export")
def export_alerts_csv(db: Session = Depends(get_db)):
    """Generates and downloads a CSV export of all detected security alerts."""
    csv_data = ReportService.export_alerts_csv(db)
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=minisiemx_alerts_export.csv"}
    )

