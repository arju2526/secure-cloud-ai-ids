from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress
from app.models.entities import AlertSeverity


class NetworkLogCreate(BaseModel):
    src_ip: IPvAnyAddress
    dst_ip: IPvAnyAddress
    src_port: int = Field(..., ge=0, le=65535)
    dst_port: int = Field(..., ge=0, le=65535)
    protocol: str = Field("TCP", min_length=1, max_length=16)
    bytes_sent: int = Field(0, ge=0)
    bytes_received: int = Field(0, ge=0)
    packet_count: int = Field(1, ge=1)


class AlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    alert_type: str
    severity: AlertSeverity
    confidence_score: float
    summary: str
    status: str
    created_at: datetime
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None


class DetectionAnalysisResult(BaseModel):
    log_id: int
    threat_detected: bool
    triggered_alerts: List[AlertResponse]
