from datetime import datetime
from sqlalchemy import String, DateTime, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database import Base

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id:         Mapped[int]        = mapped_column(primary_key=True, autoincrement=True)
    user_id:    Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    action:     Mapped[str]        = mapped_column(String(128), nullable=False)
    details:    Mapped[str | None] = mapped_column(Text, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(256), nullable=True)
    timestamp:  Mapped[datetime]   = mapped_column(DateTime, default=datetime.utcnow, index=True)

    user = relationship("User", back_populates="audit_logs")

    def to_dict(self) -> dict:
        return {
            "id":         self.id,
            "user_id":    self.user_id,
            "action":     self.action,
            "details":    self.details,
            "ip_address": self.ip_address,
            "timestamp":  self.timestamp.isoformat(),
        }