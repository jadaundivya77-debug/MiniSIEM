"""
Asset Inventory & Risk Posture Routes for MiniSIEM X
Manage corporate assets, view transparent risk score calculations, and trigger risk recalculations.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

from backend.database import get_db
from backend.models import Asset
from backend.schemas import AssetResponse, AssetCreate
from backend.services.risk_service import calculate_asset_risk
from backend.utils.helpers import safe_json_dumps

router = APIRouter(prefix="/api/assets", tags=["Assets"])

@router.get("", response_model=List[AssetResponse])
def get_assets(db: Session = Depends(get_db)):
    """Returns all assets ordered by risk score descending."""
    return db.query(Asset).order_by(Asset.risk_score.desc()).all()

@router.post("", response_model=AssetResponse)
def create_asset(data: AssetCreate, db: Session = Depends(get_db)):
    """Registers a new asset into the inventory and calculates baseline risk."""
    existing = db.query(Asset).filter(Asset.name == data.name).first()
    if existing:
        raise HTTPException(status_code=400, detail="Asset with this name already exists")

    asset = Asset(
        name=data.name,
        hostname=data.hostname,
        ip_address=data.ip_address,
        os_type=data.os_type,
        asset_type=data.asset_type.upper(),
        criticality=data.criticality.upper()
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)

    # Calculate initial risk
    score, level, factors = calculate_asset_risk(asset, db)
    asset.risk_score = score
    asset.risk_level = level
    asset.risk_factors_json = safe_json_dumps(factors)
    db.commit()
    db.refresh(asset)
    return asset

@router.get("/{id}", response_model=AssetResponse)
def get_asset_by_id(id: int, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.id == id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset

@router.post("/{id}/recalculate", response_model=AssetResponse)
def recalculate_asset_risk(id: int, db: Session = Depends(get_db)):
    """Forces an explainable re-computation of the asset's risk score."""
    asset = db.query(Asset).filter(Asset.id == id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    score, level, factors = calculate_asset_risk(asset, db)
    asset.risk_score = score
    asset.risk_level = level
    asset.risk_factors_json = safe_json_dumps(factors)
    db.commit()
    db.refresh(asset)
    return asset

