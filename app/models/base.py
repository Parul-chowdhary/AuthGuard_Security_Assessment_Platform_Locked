"""
AuthGuard SQLAlchemy Database Engine & Declarative Base
=======================================================
Database connection abstraction supporting SQLite and PostgreSQL.
"""

from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from app.config import settings

# Engine configuration with thread safety for SQLite
connect_args = {"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    echo=settings.DB_ECHO,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency for thread-safe database sessions with automatic rollback on error."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create all registered database tables (for local development & tests)."""
    Base.metadata.create_all(bind=engine)
