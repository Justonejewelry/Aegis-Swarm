"""Async SQLAlchemy engine and session factory for AEGIS."""
from __future__ import annotations

import os
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

DATABASE_URL = os.getenv(
    "AEGIS_DATABASE_URL",
    "postgresql+asyncpg://aegis:aegis_dev_only@localhost:5432/aegis",
)

engine = create_async_engine(
    DATABASE_URL,
    echo=os.getenv("AEGIS_SQL_ECHO", "").lower() in {"1", "true", "yes"},
    pool_pre_ping=True,
    pool_size=5,
    max_overflow=10,
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


@asynccontextmanager
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    session = AsyncSessionLocal()
    try:
        yield session
        await session.commit()
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency."""
    async with get_session() as session:
        yield session
