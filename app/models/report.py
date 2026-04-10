import enum
from datetime import datetime
from sqlalchemy import String, DateTime, Enum, ForeignKey, Integer
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database import Base

class ReportFormat(str, enum.Enum):
    PDF  = "pdf"
    DOCX = "docx"

class Report(Base):
    __tablename__ = "reports"

    id:              Mapped[int]          = mapped_column(primary_key=True, autoincrement=True)
    scan_id:         Mapped[int]          = mapped_column(ForeignKey("scans.id"), nullable=False)
    generated_by:    Mapped[int]          = mapped_column(ForeignKey("users.id"), nullable=False)
    format:          Mapped[ReportFormat] = mapped_column(Enum(ReportFormat), nullable=False)
    file_path:       Mapped[str]          = mapped_column(String(512), nullable=False)
    file_size_bytes: Mapped[int]          = mapped_column(Integer, default=0)
    generated_at:    Mapped[datetime]     = mapped_column(DateTime, default=datetime.utcnow)

    scan              = relationship("Scan", back_populates="reports")
    generated_by_user = relationship("User", back_populates="reports")

    def to_dict(self) -> dict:
        return {
            "id":              self.id,
            "scan_id":         self.scan_id,
            "generated_by":    self.generated_by,
            "format":          self.format.value,
            "file_path":       self.file_path,
            "file_size_bytes": self.file_size_bytes,
            "generated_at":    self.generated_at.isoformat(),
        }