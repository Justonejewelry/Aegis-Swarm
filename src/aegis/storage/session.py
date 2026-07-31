"""Async SQLAlchemy engine — Postgres preferred, SQLite fallback for offline ops."""
from __future__ import annotations

import logging
import os
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

logger = logging.getLogger(__name__)

_DEFAULT_PG = "postgresql+asyncpg://aegis:aegis_dev_only@localhost:5432/aegis"

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None
_initialized = False
DATABASE_URL: str = ""


def _resolve_url() -> str:
    explicit = os.getenv("AEGIS_DATABASE_URL")
    if explicit:
        return explicit
    mode = os.getenv("AEGIS_DB_MODE", "sqlite").lower()
    if mode == "postgres":
        return _DEFAULT_PG
    sqlite_path = Path(os.getenv("AEGIS_SQLITE_PATH", "/tmp/aegis.db"))
    sqlite_path.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite+aiosqlite:///{sqlite_path}"


def get_engine() -> AsyncEngine:
    global _engine, _session_factory, DATABASE_URL
    if _engine is None:
        DATABASE_URL = _resolve_url()
        kwargs: dict = {
            "echo": os.getenv("AEGIS_SQL_ECHO", "").lower() in {"1", "true", "yes"},
        }
        if DATABASE_URL.startswith("sqlite"):
            kwargs["connect_args"] = {"check_same_thread": False}
        else:
            kwargs["pool_pre_ping"] = True
            kwargs["pool_size"] = 5
            kwargs["max_overflow"] = 10
        _engine = create_async_engine(DATABASE_URL, **kwargs)
        _session_factory = async_sessionmaker(
            _engine, class_=AsyncSession, expire_on_commit=False, autoflush=False
        )
        logger.info("engine created %s", DATABASE_URL)
    return _engine


def _sessions() -> async_sessionmaker[AsyncSession]:
    get_engine()
    assert _session_factory is not None
    return _session_factory


async def init_db() -> str:
    global _initialized
    eng = get_engine()
    from aegis.storage.models import Base

    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.exec_driver_sql(
            """
            CREATE TABLE IF NOT EXISTS evidence_chain (
              evidence_id TEXT PRIMARY KEY,
              engagement_id TEXT NOT NULL,
              label TEXT NOT NULL,
              content_hash TEXT NOT NULL,
              algo TEXT NOT NULL DEFAULT 'sha256',
              source TEXT,
              media_type TEXT,
              size_bytes INTEGER,
              collected_by TEXT,
              prev_hash TEXT,
              chain_hash TEXT NOT NULL,
              created_at TEXT,
              meta TEXT DEFAULT '{}'
            )
            """
        )
    _initialized = True
    backend = "sqlite" if DATABASE_URL.startswith("sqlite") else "postgres"
    logger.info("storage ready backend=%s", backend)
    return backend


@asynccontextmanager
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    global _initialized
    if not _initialized:
        await init_db()
    session = _sessions()()
    try:
        yield session
        await session.commit()
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with get_session() as session:
        yield session
