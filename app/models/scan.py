import enum
from datetime import datetime
from sqlalchemy import String, DateTime, Enum, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database import Base

class ScanType(str, enum.Enum):
    SAST = "sast"
    DAST = "dast"
    BOTH = "both"

class ScanStatus(str, enum.Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    COMPLETED = "completed"
    FAILED    = "failed"

class Scan(Base):
    __tablename__ = "scans"

    id:           Mapped[int]        = mapped_column(primary_key=True, autoincrement=True)
    user_id:      Mapped[int]        = mapped_column(ForeignKey("users.id"), nullable=False)
    apk_name:     Mapped[str]        = mapped_column(String(256), nullable=False)
    apk_path:     Mapped[str]        = mapped_column(String(512), nullable=False)
    package_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    scan_type:    Mapped[ScanType]   = mapped_column(Enum(ScanType), nullable=False)
    status:       Mapped[ScanStatus] = mapped_column(Enum(ScanStatus), default=ScanStatus.PENDING)
    error_msg:    Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at:   Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at:   Mapped[datetime]   = mapped_column(DateTime, default=datetime.utcnow)

    user     = relationship("User",    back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    reports  = relationship("Report",  back_populates="scan",  cascade="all, delete-orphan")

    @property
    def duration_seconds(self) -> int | None:
        if self.started_at and self.completed_at:
            return int((self.completed_at - self.started_at).total_seconds())
        return None

    def to_dict(self) -> dict:
        return {
            "id":             self.id,
            "user_id":        self.user_id,
            "apk_name":       self.apk_name,
            "package_name":   self.package_name,
            "scan_type":      self.scan_type.value,
            "status":         self.status.value,
            "error_msg":      self.error_msg,
            "started_at":     self.started_at.isoformat()   if self.started_at   else None,
            "completed_at":   self.completed_at.isoformat() if self.completed_at else None,
            "created_at":     self.created_at.isoformat(),
            "duration_sec":   self.duration_seconds,
            "findings_count": len(self.findings) if self.findings else 0,
        }