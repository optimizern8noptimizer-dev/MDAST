import os
import secrets
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / '.env')


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {'1', 'true', 'yes', 'on'}


class Config:
    APP_NAME = 'MASP'
    VERSION = '2.0.0'
    HOST = os.getenv('HOST', '127.0.0.1')
    PORT = int(os.getenv('PORT', '5000'))
    DEBUG = _env_bool('DEBUG', False)
    TESTING = False

    DATABASE_URL = os.getenv('DATABASE_URL', f'sqlite:///{BASE_DIR / "data" / "masp.db"}')
    SECRET_KEY = os.getenv('SECRET_KEY') or secrets.token_urlsafe(48)
    JWT_ALGORITHM = os.getenv('JWT_ALGORITHM', 'HS256')
    JWT_EXPIRY_HOURS = int(os.getenv('JWT_EXPIRY_HOURS', '8'))

    DATA_DIR = Path(os.getenv('DATA_DIR', str(BASE_DIR / 'data')))
    UPLOAD_FOLDER = DATA_DIR / 'uploads'
    REPORTS_FOLDER = DATA_DIR / 'reports'
    LOGS_FOLDER = DATA_DIR / 'logs'
    MAX_CONTENT_LENGTH = int(os.getenv('MAX_CONTENT_LENGTH', str(200 * 1024 * 1024)))
    ALLOWED_EXTENSIONS = {'apk'}
    FRIDA_TIMEOUT_SECONDS = int(os.getenv('FRIDA_TIMEOUT_SECONDS', '300'))
    QUEUE_POLL_SECONDS = int(os.getenv('QUEUE_POLL_SECONDS', '3'))

    DEFAULT_ADMIN_USERNAME = os.getenv('DEFAULT_ADMIN_USERNAME', 'admin')
    DEFAULT_ADMIN_EMAIL = os.getenv('DEFAULT_ADMIN_EMAIL', 'admin@masp.local')
    DEFAULT_ADMIN_PASSWORD = os.getenv('DEFAULT_ADMIN_PASSWORD', 'AdminPass123!')

    @classmethod
    def ensure_directories(cls) -> None:
        for path in (cls.DATA_DIR, cls.UPLOAD_FOLDER, cls.REPORTS_FOLDER, cls.LOGS_FOLDER):
            Path(path).mkdir(parents=True, exist_ok=True)

    @classmethod
    def validate(cls) -> list[str]:
        issues: list[str] = []
        if cls.JWT_EXPIRY_HOURS < 1:
            issues.append('JWT_EXPIRY_HOURS must be >= 1')
        if len(cls.SECRET_KEY) < 32:
            issues.append('SECRET_KEY must be at least 32 characters long')
        if not str(cls.DATABASE_URL).startswith('sqlite:///'):
            issues.append('This archive is prepared for SQLite local mode only')
        return issues


class DevelopmentConfig(Config):
    DEBUG = _env_bool('DEBUG', True)


class ProductionConfig(Config):
    DEBUG = False


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig,
}
