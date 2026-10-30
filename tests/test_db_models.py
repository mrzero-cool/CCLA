"""Tests for durable data models (P2.1)."""
from __future__ import annotations

import tempfile
import os
from pathlib import Path

from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker

from clca.db.models import (
    AnalysisRun,
    Base,
    Decision,
    RunEvent,
    RunEventType,
    RunStatus,
    SessionLocal,
    create_db_and_tables,
    engine,
)


def test_tables_created():
    """All expected tables exist in the database."""
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    expected = {"analysis_runs", "run_events", "artifact_records", "policy_versions"}
    assert expected.issubset(tables), f"Missing tables: {expected - tables}"


def test_create_run_and_events(tmp_path):
    """Create a run, add events, verify persistence using a temp database."""
    db_path = tmp_path / "test.db"
    db_url = f"sqlite:///{db_path}"
    test_engine = create_engine(db_url, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=test_engine)
    TestSession = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    db = TestSession()
    try:
        run = AnalysisRun(
            run_id="run-test-1",
            scenario_id="safe_code_change",
            status=RunStatus.QUEUED,
            repository="demo/repo",
            base_revision="a" * 40,
            head_revision="b" * 40,
            diff_digest="sha256:deadbeef",
            policy_id="default-pr-policy",
            policy_version="0.2.0",
        )
        db.add(run)
        db.commit()

        event = RunEvent(
            run_id="run-test-1",
            event_type=RunEventType.STARTED,
            detail={"reason": "test"},
        )
        db.add(event)
        db.commit()

        # Query back
        found = db.query(AnalysisRun).filter_by(run_id="run-test-1").first()
        assert found is not None
        assert found.scenario_id == "safe_code_change"
        assert found.status == RunStatus.QUEUED
        assert len(found.events) == 1
        assert found.events[0].event_type == RunEventType.STARTED
    finally:
        db.close()


def test_run_status_and_decision_enums():
    assert RunStatus.QUEUED == "QUEUED"
    assert RunStatus.RUNNING == "RUNNING"
    assert RunStatus.SUCCEEDED == "SUCCEEDED"
    assert RunStatus.FAILED == "FAILED"
    assert Decision.PASS == "PASS"
    assert Decision.BLOCK == "BLOCK"
    assert Decision.INCOMPLETE == "INCOMPLETE"


def test_create_db_and_tables_idempotent():
    create_db_and_tables()  # should not raise
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    assert "analysis_runs" in tables
