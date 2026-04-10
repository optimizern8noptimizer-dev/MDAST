from datetime import datetime
from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database import Base


class UploadedApk(Base):
    __tablename__ = 'uploaded_apks'

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), nullable=False, index=True)
    original_name: Mapped[str] = mapped_column(String(256), nullable=False)
    stored_name: Mapped[str] = mapped_column(String(256), nullable=False, unique=True)
    file_path: Mapped[str] = mapped_column(String(512), nullable=False, unique=True)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)

    user = relationship('User')

    def to_dict(self) -> dict:
        return {
            'id': self.id,
            'original_name': self.original_name,
            'stored_name': self.stored_name,
            'size_bytes': self.size_bytes,
            'sha256': self.sha256,
            'created_at': self.created_at.isoformat(),
        }
