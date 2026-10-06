from typing import List
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.auth import get_current_user
from app.db.database import get_db
from app.models.entities import NetworkLog, SecurityAlert, User
from app.schemas.detection import NetworkLogCreate, DetectionAnalysisResult, AlertResponse
from app.services.detection_engine import analyze_log

router = APIRouter(tags=["Threat Detection Engine"])


@router.post("/analyze", response_model=DetectionAnalysisResult)
def analyze_network_traffic(payload: NetworkLogCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    log_entry = NetworkLog(
        src_ip=str(payload.src_ip), dst_ip=str(payload.dst_ip), src_port=payload.src_port, dst_port=payload.dst_port,
        protocol=payload.protocol.upper(), bytes_sent=payload.bytes_sent, bytes_received=payload.bytes_received,
        packet_count=payload.packet_count,
    )
    db.add(log_entry)
    db.flush()

    threats = analyze_log(log_entry)
    created = []
    for threat in threats:
        alert = SecurityAlert(
            log_id=log_entry.id, user_id=current_user.id, alert_type=threat["alert_type"], severity=threat["severity"],
            confidence_score=threat["confidence_score"], summary=threat["summary"], status="OPEN",
        )
        db.add(alert)
        created.append(alert)

    db.commit()
    for alert in created:
        db.refresh(alert)

    return DetectionAnalysisResult(log_id=log_entry.id, threat_detected=bool(created), triggered_alerts=created)


@router.get("/alerts", response_model=List[AlertResponse])
def get_security_alerts(limit: int = Query(50, ge=1, le=500), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    alerts = db.query(SecurityAlert).order_by(SecurityAlert.created_at.desc()).limit(limit).all()
    return alerts
