import enum
from datetime import datetime
from sqlalchemy import String, Float, DateTime, Enum, ForeignKey, Text, Integer
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database import Base


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


# CVSS score ranges per severity (CVSS v3.1)
SEVERITY_CVSS_RANGE = {
    Severity.CRITICAL: (9.0, 10.0),
    Severity.HIGH:     (7.0, 8.9),
    Severity.MEDIUM:   (4.0, 6.9),
    Severity.LOW:      (0.1, 3.9),
    Severity.INFO:     (0.0, 0.0),
}


class Finding(Base):
    __tablename__ = "findings"

    id:               Mapped[int]      = mapped_column(primary_key=True, autoincrement=True)
    scan_id:          Mapped[int]      = mapped_column(ForeignKey("scans.id"), nullable=False)

    # Classification
    title:            Mapped[str]      = mapped_column(String(512), nullable=False)
    description:      Mapped[str]      = mapped_column(Text, nullable=False)
    severity:         Mapped[Severity] = mapped_column(Enum(Severity), nullable=False)
    scan_source:      Mapped[str]      = mapped_column(String(16), nullable=False)  # "sast" or "dast"

    # Standards mapping
    cvss_score:       Mapped[float | None]  = mapped_column(Float, nullable=True)    # 0.0–10.0
    cvss_vector:      Mapped[str | None]    = mapped_column(String(256), nullable=True)  # CVSS:3.1/AV:N/...
    cwe_id:           Mapped[str | None]    = mapped_column(String(32), nullable=True)   # CWE-312
    owasp_mobile:     Mapped[str | None]    = mapped_column(String(64), nullable=True)   # M1:2024
    masvs_id:         Mapped[str | None]    = mapped_column(String(64), nullable=True)   # MASVS-STORAGE-1
    pci_dss_req:      Mapped[str | None]    = mapped_column(String(64), nullable=True)   # 6.2.4

    # Evidence
    file_path:        Mapped[str | None]    = mapped_column(String(512), nullable=True)  # for SAST
    line_number:      Mapped[int | None]    = mapped_column(Integer, nullable=True)      # for SAST
    code_snippet:     Mapped[str | None]    = mapped_column(Text, nullable=True)         # for SAST
    frida_output:     Mapped[str | None]    = mapped_column(Text, nullable=True)         # for DAST
    network_capture:  Mapped[str | None]    = mapped_column(Text, nullable=True)         # for DAST

    # Recommendation
    recommendation:   Mapped[str]      = mapped_column(Text, nullable=False)
    references:       Mapped[str | None]    = mapped_column(Text, nullable=True)  # JSON list of URLs

    created_at:       Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Relationships
    scan = relationship("Scan", back_populates="findings")

    def to_dict(self) -> dict:
        return {
            "id":             self.id,
            "scan_id":        self.scan_id,
            "title":          self.title,
            "description":    self.description,
            "severity":       self.severity.value,
            "scan_source":    self.scan_source,
            "cvss_score":     self.cvss_score,
            "cvss_vector":    self.cvss_vector,
            "cwe_id":         self.cwe_id,
            "owasp_mobile":   self.owasp_mobile,
            "masvs_id":       self.masvs_id,
            "pci_dss_req":    self.pci_dss_req,
            "file_path":      self.file_path,
            "line_number":    self.line_number,
            "code_snippet":   self.code_snippet,
            "frida_output":   self.frida_output,
            "network_capture": self.network_capture,
            "recommendation": self.recommendation,
            "references":     self.references,
            "created_at":     self.created_at.isoformat(),
        }

    def __repr__(self) -> str:
        return f"<Finding id={self.id} severity={self.severity.value} title={self.title[:40]!r}>"
