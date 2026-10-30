"""Durable data models for CLCA production control plane (P2.1).

SQLAlchemy models for runs, audit events, and policy versions.  Uses SQLite
by default for development/pilot; swap the DATABASE_URL for PostgreSQL in
production per roadmap section 3.1.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum as PyEnum
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class RunStatus(str, PyEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    TIMED_OUT = "TIMED_OUT"


class Decision(str, PyEnum):
    PASS = "PASS"
    WARN = "WARN"
    BLOCK = "BLOCK"
    INCOMPLETE = "INCOMPLETE"


class AnalysisRun(Base):
    """Durable run record.  Replaces the in-memory _RUNS dict."""

    __tablename__ = "analysis_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    run_id: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    scenario_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    status: Mapped[RunStatus] = mapped_column(Enum(RunStatus), default=RunStatus.QUEUED, nullable=False)
    decision: Mapped[Decision | None] = mapped_column(Enum(Decision), nullable=True)
    repository: Mapped[str] = mapped_column(String(256), nullable=False)
    base_revision: Mapped[str] = mapped_column(String(64), nullable=False)
    head_revision: Mapped[str] = mapped_column(String(64), nullable=False)
    diff_digest: Mapped[str] = mapped_column(String(128), nullable=False)
    bundle_digest: Mapped[str | None] = mapped_column(String(128), nullable=True)
    policy_id: Mapped[str] = mapped_column(String(128), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    demo_only: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    events: Mapped[list["RunEvent"]] = relationship(
        "RunEvent", back_populates="run", cascade="all, delete-orphan"
    )
    artifacts: Mapped[list["ArtifactRecord"]] = relationship(
        "ArtifactRecord", back_populates="run", cascade="all, delete-orphan"
    )


class RunEventType(str, PyEnum):
    CREATED = "CREATED"
    STARTED = "STARTED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    TIMED_OUT = "TIMED_OUT"


class RunEvent(Base):
    """Immutable audit event for a run lifecycle transition."""

    __tablename__ = "run_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    run_id: Mapped[str] = mapped_column(
        String(128), ForeignKey("analysis_runs.run_id", ondelete="CASCADE"), index=True, nullable=False
    )
    event_type: Mapped[RunEventType] = mapped_column(Enum(RunEventType), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    run: Mapped["AnalysisRun"] = relationship("AnalysisRun", back_populates="events")


class ArtifactRecord(Base):
    """Pointer to a durable artifact (bundle, report, graph) in object storage."""

    __tablename__ = "artifact_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    run_id: Mapped[str] = mapped_column(
        String(128), ForeignKey("analysis_runs.run_id", ondelete="CASCADE"), index=True, nullable=False
    )
    artifact_type: Mapped[str] = mapped_column(String(64), nullable=False)  # bundle | report | graph | evidence
    uri: Mapped[str] = mapped_column(String(512), nullable=False)
    sha256: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    run: Mapped["AnalysisRun"] = relationship("AnalysisRun", back_populates="artifacts")


class PolicyVersion(Base):
    """Versioned policy/catalog/command catalog records."""

    __tablename__ = "policy_versions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    policy_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_digest: Mapped[str] = mapped_column(String(128), nullable=False)
    catalog_digest: Mapped[str | None] = mapped_column(String(128), nullable=True)
    command_digest: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


# ---------------------------------------------------------------------------
# Engine / session factory
# ---------------------------------------------------------------------------

import os as _os

DATABASE_URL = _os.environ.get("CLCA_DATABASE_URL", "sqlite:///./clca.db")

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def create_db_and_tables() -> None:
    """Create all tables.  In production use Alembic migrations instead."""
    Base.metadata.create_all(bind=engine)


def get_db():
    """Yield a SQLAlchemy session (FastAPI dependency)."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
