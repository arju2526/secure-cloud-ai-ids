import enum
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Enum, DateTime, ForeignKey, Text, Float
from sqlalchemy.orm import relationship
from app.db.database import Base
from app.schemas.auth import UserRole


class AlertSeverity(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), default=UserRole.ANALYST, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    alerts = relationship("SecurityAlert", back_populates="assigned_user")


class NetworkLog(Base):
    __tablename__ = "network_logs"

    id = Column(Integer, primary_key=True, index=True)
    src_ip = Column(String(45), index=True, nullable=False)
    dst_ip = Column(String(45), index=True, nullable=False)
    src_port = Column(Integer, nullable=False)
    dst_port = Column(Integer, nullable=False)
    protocol = Column(String(16), nullable=False)
    bytes_sent = Column(Integer, default=0, nullable=False)
    bytes_received = Column(Integer, default=0, nullable=False)
    packet_count = Column(Integer, default=1, nullable=False)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    alerts = relationship("SecurityAlert", back_populates="network_log", cascade="all, delete-orphan")


class SecurityAlert(Base):
    __tablename__ = "security_alerts"

    id = Column(Integer, primary_key=True, index=True)
    log_id = Column(Integer, ForeignKey("network_logs.id"), nullable=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    alert_type = Column(String(120), nullable=False)
    severity = Column(Enum(AlertSeverity), default=AlertSeverity.MEDIUM, nullable=False)
    confidence_score = Column(Float, default=0.0, nullable=False)
    summary = Column(Text, nullable=False)
    status = Column(String(20), default="OPEN", nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    network_log = relationship("NetworkLog", back_populates="alerts")
    assigned_user = relationship("User", back_populates="alerts")

    @property
    def src_ip(self):
        return self.network_log.src_ip if self.network_log else None

    @property
    def dst_ip(self):
        return self.network_log.dst_ip if self.network_log else None

    @property
    def src_port(self):
        return self.network_log.src_port if self.network_log else None

    @property
    def dst_port(self):
        return self.network_log.dst_port if self.network_log else None

    @property
    def protocol(self):
        return self.network_log.protocol if self.network_log else None
