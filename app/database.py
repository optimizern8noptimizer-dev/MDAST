from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Generator

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.orm import DeclarativeBase, scoped_session, sessionmaker

from app.config import Config


class Base(DeclarativeBase):
    pass


_engine = None
_SessionFactory = None


CORE_SCHEMA_PATCHES: dict[str, list[tuple[str, str]]] = {
    'scans': [
        ('queued_at', 'ALTER TABLE scans ADD COLUMN queued_at DATETIME'),
    ],
}


def get_engine():
    global _engine
    if _engine is None:
        Config.ensure_directories()
        connect_args = {'check_same_thread': False} if str(Config.DATABASE_URL).startswith('sqlite:///') else {}
        _engine = create_engine(Config.DATABASE_URL, connect_args=connect_args, future=True, pool_pre_ping=True)

        if str(Config.DATABASE_URL).startswith('sqlite:///'):
            @event.listens_for(_engine, 'connect')
            def _set_sqlite_pragma(dbapi_conn, _):
                cursor = dbapi_conn.cursor()
                cursor.execute('PRAGMA journal_mode=WAL')
                cursor.execute('PRAGMA foreign_keys=ON')
                cursor.close()
    return _engine


def get_session_factory():
    global _SessionFactory
    if _SessionFactory is None:
        _SessionFactory = scoped_session(sessionmaker(bind=get_engine(), autoflush=False, autocommit=False, expire_on_commit=False, future=True))
    return _SessionFactory


SessionLocal = get_session_factory()


def get_db() -> Generator:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _apply_sqlite_schema_patches() -> None:
    if not str(Config.DATABASE_URL).startswith('sqlite:///'):
        return
    db_path = str(Config.DATABASE_URL).replace('sqlite:///', '', 1)
    if not Path(db_path).exists():
        return
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        for table, patches in CORE_SCHEMA_PATCHES.items():
            cur.execute(f"PRAGMA table_info({table})")
            columns = {row[1] for row in cur.fetchall()}
            for column_name, ddl in patches:
                if column_name not in columns:
                    cur.execute(ddl)
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    from app.models import user, scan, finding, report, audit_log, uploaded_apk, revoked_token  # noqa

    engine = get_engine()
    Base.metadata.create_all(bind=engine)
    _apply_sqlite_schema_patches()


def healthcheck() -> dict:
    engine = get_engine()
    result = {'database': 'unknown', 'details': None}
    try:
        with engine.connect() as conn:
            conn.execute(text('SELECT 1'))
        result['database'] = 'ok'
    except Exception as exc:
        result['database'] = 'failed'
        result['details'] = str(exc)
    return result
