from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import bcrypt
import jwt

from app.config import Config
from app.database import SessionLocal
from app.models.revoked_token import RevokedToken


def hash_password(plain_password: str) -> str:
    return bcrypt.hashpw(plain_password.encode('utf-8'), bcrypt.gensalt(rounds=12)).decode('utf-8')


def verify_password(plain_password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed.encode('utf-8'))
    except Exception:
        return False


def create_token(user_id: int, username: str, role: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        'sub': str(user_id),
        'username': username,
        'role': role,
        'jti': uuid4().hex,
        'iat': now,
        'exp': now + timedelta(hours=Config.JWT_EXPIRY_HOURS),
    }
    return jwt.encode(payload, Config.SECRET_KEY, algorithm=Config.JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    return jwt.decode(token, Config.SECRET_KEY, algorithms=[Config.JWT_ALGORITHM])


def revoke_token(jti: str, exp_ts: int | float | None) -> None:
    if not jti or exp_ts is None:
        return
    expires_at = datetime.fromtimestamp(exp_ts, tz=timezone.utc)
    db = SessionLocal()
    try:
        existing = db.query(RevokedToken).filter(RevokedToken.jti == jti).first()
        if not existing:
            db.add(RevokedToken(jti=jti, expires_at=expires_at))
            db.commit()
    finally:
        db.close()


def is_token_revoked(jti: str) -> bool:
    if not jti:
        return True
    db = SessionLocal()
    try:
        return db.query(RevokedToken).filter(RevokedToken.jti == jti).first() is not None
    finally:
        db.close()


def cleanup_revoked_tokens() -> None:
    db = SessionLocal()
    now = datetime.now(timezone.utc)
    try:
        db.query(RevokedToken).filter(RevokedToken.expires_at < now).delete()
        db.commit()
    finally:
        db.close()
