"""
Database configuration.

Uses SQLite by default so the whole platform runs with zero external
services. To use PostgreSQL in production (e.g. on Render/Supabase as
described in the project spec), just set the DATABASE_URL environment
variable, e.g.:

    export DATABASE_URL="postgresql://user:pass@host:5432/sentinelx"

SQLAlchemy handles both transparently -- no code changes needed.
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./sentinelx.db")

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
