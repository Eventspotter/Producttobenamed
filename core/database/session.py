"""Async SQLAlchemy engine, session factory, and schema initialization."""

from __future__ import annotations

from typing import AsyncGenerator

from sqlalchemy import event, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from core.config import DATABASE_URL, DEFAULT_OWNER_ID, DEFAULT_OWNER_NAME
from core.security.crypto import hash_identifier
from .models import Base, UserAccount

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_async_engine(DATABASE_URL, echo=False, connect_args=connect_args)

if DATABASE_URL.startswith("sqlite"):
    @event.listens_for(engine.sync_engine, "connect")
    def _set_sqlite_pragma(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON;")
        cursor.close()

AsyncSessionLocal = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)


async def init_db() -> None:
    """Creates tables and ensures default local vault owner exists."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as session:
        existing = await session.execute(select(UserAccount).where(UserAccount.id == DEFAULT_OWNER_ID))
        if existing.scalar_one_or_none() is None:
            session.add(
                UserAccount(
                    id=DEFAULT_OWNER_ID,
                    display_name=DEFAULT_OWNER_NAME,
                    email_hash=hash_identifier("owner@local.vault"),
                )
            )
            await session.commit()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        yield session
