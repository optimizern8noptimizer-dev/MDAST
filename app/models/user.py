import enum
from datetime import datetime
from sqlalchemy import String, Boolean, DateTime, Enum
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database import Base


class UserRole(str, enum.Enum):
    ADMIN     = "admin"      # управление пользователями, все права
    SPECIALIST = "specialist" # запуск сканов, просмотр своих результатов
    AUDITOR   = "auditor"    # только просмотр всех отчётов и истории


class User(Base):
    __tablename__ = "users"

    id:           Mapped[int]      = mapped_column(primary_key=True, autoincrement=True)
    username:     Mapped[str]      = mapped_column(String(64), unique=True, nullable=False)
    email:        Mapped[str]      = mapped_column(String(256), unique=True, nullable=False)
    password_hash: Mapped[str]     = mapped_column(String(256), nullable=False)
    role:         Mapped[UserRole] = mapped_column(Enum(UserRole), nullable=False, default=UserRole.SPECIALIST)
    is_active:    Mapped[bool]     = mapped_column(Boolean, default=True)
    created_at:   Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_login:   Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # Relationships
    scans      = relationship("Scan",     back_populates="user", lazy="select")
    reports    = relationship("Report",   back_populates="generated_by_user", lazy="select")
    audit_logs = relationship("AuditLog", back_populates="user", lazy="select")

    def to_dict(self) -> dict:
        return {
            "id":         self.id,
            "username":   self.username,
            "email":      self.email,
            "role":       self.role.value,
            "is_active":  self.is_active,
            "created_at": self.created_at.isoformat(),
            "last_login": self.last_login.isoformat() if self.last_login else None,
        }

    def __repr__(self) -> str:
        return f"<User id={self.id} username={self.username!r} role={self.role.value}>"
