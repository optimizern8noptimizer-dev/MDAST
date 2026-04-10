#!/usr/bin/env python3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from app.config import Config
from app.database import SessionLocal, init_db
from app.models.audit_log import AuditLog
from app.models.user import User, UserRole
from app.services.auth_service import hash_password


def create_directories():
    Config.ensure_directories()
    for path in [Config.DATA_DIR, Config.UPLOAD_FOLDER, Config.REPORTS_FOLDER, Config.LOGS_FOLDER]:
        print(f'  [+] Directory ready: {path}')


def create_admin(db, username: str, email: str, password: str) -> User:
    existing = db.query(User).filter(User.username == username).first()
    if existing:
        print(f"  [!] Admin '{username}' already exists — skipping.")
        return existing
    admin = User(username=username, email=email, password_hash=hash_password(password), role=UserRole.ADMIN, is_active=True)
    db.add(admin)
    db.flush()
    db.add(AuditLog(user_id=None, action='system.init', details=f'{{"created_admin": "{username}"}}', ip_address='127.0.0.1'))
    db.commit()
    print(f"  [+] Admin created: username='{username}' role=admin")
    return admin


def main():
    print('\n=== MASP — Database Initialization ===\n')
    print('[1/3] Creating directories...')
    create_directories()
    print('\n[2/3] Creating database tables...')
    init_db()
    print('  [+] Database schema ready')
    print('\n[3/3] Creating default admin user...')
    username = Config.DEFAULT_ADMIN_USERNAME
    email = Config.DEFAULT_ADMIN_EMAIL
    password = Config.DEFAULT_ADMIN_PASSWORD
    if len(password) < 12:
        raise SystemExit('DEFAULT_ADMIN_PASSWORD must be at least 12 characters long')
    db = SessionLocal()
    try:
        create_admin(db, username, email, password)
    finally:
        db.close()
    print('\n=== Initialization complete ===')
    print(f'  DB:    {Config.DATA_DIR / "masp.db"}')
    print(f'  Login: {username} / {password}')
    print("  Next step: run 'python run.py'")


if __name__ == '__main__':
    main()
