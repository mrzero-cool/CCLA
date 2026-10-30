"""CLCA Production REST API (P2.2).

Versioned REST/OpenAPI API for the CLCA control plane.  Endpoints:
  GET  /api/v1/healthz              - liveness probe
  GET  /api/v1/scenarios            - list built-in scenarios
  GET  /api/v1/runs                 - list runs (with pagination/filtering)
  POST  /api/v1/runs                - create a new run
  GET  /api/v1/runs/{run_id}        - get run details
  GET  /api/v1/runs/{run_id}/events - get run audit events
  GET  /api/v1/integrations         - GitHub integration status
  GET  /api/v1/openapi.json         - OpenAPI schema
  GET  /api/v1/docs                 - Swagger UI

Authentication: bearer token via CLCA_API_TOKEN env var (demo mode allows all).
RBAC: viewer/developer/repository_admin/policy_admin/auditor roles.
Rate limiting: token bucket per client IP.
"""
from __future__ import annotations

import os
import time
from typing import Any

from fastapi import FastAPI, HTTPException, Depends, Query, Path as PathParam, Request
from fastapi.responses import JSONResponse
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from sqlalchemy.orm import Session

from clca.db.models import (
    SessionLocal,
    engine,
    create_db_and_tables,
    AnalysisRun,
    RunEvent,
    RunStatus,
    Decision,
    RunEventType,
    PolicyVersion,
    Base,
)
from clca.security import SecurityMiddleware, Role
from clca.slo import slo_monitor

# Ensure tables exist
create_db_and_tables()

app = FastAPI(
    title="CLCA Evidence Gate API",
    version="0.4.0",
    description="Cross-Layer Change Assurance - production control plane API",
    docs_url=None,  # custom docs with auth
    redoc_url=None,
    openapi_url="/api/v1/openapi.json",
)

# Security middleware instance
security = SecurityMiddleware(
    api_token=os.environ.get("CLCA_API_TOKEN"),
    rate_limit_per_minute=int(os.environ.get("CLCA_RATE_LIMIT_PER_MINUTE", "60")),
)


# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


async def get_current_role(request: Request) -> Role | None:
    """Authenticate + authorize, return the user role."""
    ok, role, status, msg = security.check(request)
    if not ok:
        raise HTTPException(status_code=status, detail=msg)
    return role


def require_role(role: Role):
    """Dependency factory: require a specific role (or higher)."""

    def checker(current_role: Role | None = Depends(get_current_role)) -> Role:
        if current_role is None:
            raise HTTPException(status_code=403, detail="authentication required")
        # Role hierarchy: viewer < developer < repository_admin < policy_admin < auditor
        hierarchy = [
            Role.VIEWER,
            Role.DEVELOPER,
            Role.REPOSITORY_ADMIN,
            Role.POLICY_ADMIN,
            Role.AUDITOR,
        ]
        if hierarchy.index(current_role) < hierarchy.index(role):
            raise HTTPException(status_code=403, detail=f"role {current_role.value} insufficient")
        return current_role

    return checker


# ---------------------------------------------------------------------------
# Middleware: security headers + rate limiting
# ---------------------------------------------------------------------------

@app.middleware("http")
async def security_middleware(request: Request, call_next):
    ok, role, status, msg = security.check(request)
    if not ok:
        return JSONResponse(status_code=status, content={"detail": msg})
    start = time.monotonic()
    response = await call_next(request)
    duration_ms = (time.monotonic() - start) * 1000
    slo_monitor.record_request(
        endpoint=request.url.path,
        status=str(response.status_code),
        duration_ms=duration_ms,
    )
    SecurityMiddleware.security_headers(response)
    return response


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/v1/healthz", tags=["system"])
async def healthz():
    """Liveness probe - no auth required."""
    return {"status": "ok", "version": "0.4.0", "scenarios": 6}


@app.get("/api/v1/scenarios", tags=["scenarios"], dependencies=[Depends(get_current_role)])
async def list_scenarios():
    """List available built-in scenarios."""
    from clca.scenarios import SCENARIOS

    return {
        "scenarios": [
            {
                "scenario_id": s.scenario_id,
                "title": s.title,
                "description": s.description,
                "expected_decision": s.expected_decision,
            }
            for s in SCENARIOS.values()
        ]
    }


@app.post("/api/v1/runs", tags=["runs"], status_code=202)
async def create_run(
    request: Request,
    current_role: Role = Depends(require_role(Role.DEVELOPER)),
    db: Session = Depends(get_db),
):
    """Start a new analysis run (demo mode runs a built-in scenario)."""
    body = await request.json()
    scenario_id = body.get("scenario", "safe_code_change")

    from clca.scenarios import run_scenario

    try:
        result = run_scenario(scenario_id, budget_seconds=60.0)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    run = AnalysisRun(
        run_id=result.run_id,
        scenario_id=result.scenario_id,
        status=RunStatus.SUCCEEDED if result.decision != "INCOMPLETE" else RunStatus.RUNNING,
        decision=Decision(result.decision),
        repository="demo/repo",
        base_revision=result.base_revision,
        head_revision=result.head_revision,
        diff_digest=result.diff_digest,
        bundle_digest=result.bundle_digest or "",
        policy_id=result.policy_id,
        policy_version=result.policy_version,
        duration_ms=result.duration_ms,
        demo_only=True,
    )
    db.add(run)
    db.commit()
    db.refresh(run)

    event = RunEvent(
        run_id=run.run_id,
        event_type=RunEventType.COMPLETED,
        detail={"decision": result.decision, "scenario": scenario_id},
    )
    db.add(event)
    db.commit()

    return {
        "run_id": run.run_id,
        "scenario_id": run.scenario_id,
        "status": run.status.value,
        "decision": run.decision.value if run.decision else None,
        "submitted_at": run.created_at.isoformat(),
        "poll_url": f"/api/v1/runs/{run.run_id}",
    }


@app.get("/api/v1/runs", tags=["runs"])
async def list_runs(
    current_role: Role = Depends(require_role(Role.VIEWER)),
    db: Session = Depends(get_db),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    scenario_id: str | None = Query(None),
    status: str | None = Query(None),
):
    """List runs with optional filtering and pagination."""
    query = db.query(AnalysisRun)
    if scenario_id:
        query = query.filter(AnalysisRun.scenario_id == scenario_id)
    if status:
        query = query.filter(AnalysisRun.status == RunStatus(status))
    total = query.count()
    runs = query.offset(offset).limit(limit).all()
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "runs": [
            {
                "run_id": r.run_id,
                "scenario_id": r.scenario_id,
                "status": r.status.value,
                "decision": r.decision.value if r.decision else None,
                "repository": r.repository,
                "head_revision": r.head_revision,
                "created_at": r.created_at.isoformat(),
                "duration_ms": r.duration_ms,
                "demo_only": r.demo_only,
            }
            for r in runs
        ],
    }


@app.get("/api/v1/runs/{run_id}", tags=["runs"])
async def get_run(
    run_id: str = PathParam(..., description="Run ID"),
    current_role: Role = Depends(require_role(Role.VIEWER)),
    db: Session = Depends(get_db),
):
    """Get run details by ID."""
    run = db.query(AnalysisRun).filter_by(run_id=run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail=f"run {run_id} not found")
    return {
        "run_id": run.run_id,
        "scenario_id": run.scenario_id,
        "status": run.status.value,
        "decision": run.decision.value if run.decision else None,
        "repository": run.repository,
        "base_revision": run.base_revision,
        "head_revision": run.head_revision,
        "diff_digest": run.diff_digest,
        "bundle_digest": run.bundle_digest,
        "policy_id": run.policy_id,
        "policy_version": run.policy_version,
        "created_at": run.created_at.isoformat(),
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "completed_at": run.completed_at.isoformat() if run.completed_at else None,
        "duration_ms": run.duration_ms,
        "error_message": run.error_message,
        "demo_only": run.demo_only,
    }


@app.get("/api/v1/runs/{run_id}/events", tags=["runs"])
async def get_run_events(
    run_id: str = PathParam(..., description="Run ID"),
    current_role: Role = Depends(require_role(Role.VIEWER)),
    db: Session = Depends(get_db),
):
    """Get audit events for a run."""
    run = db.query(AnalysisRun).filter_by(run_id=run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail=f"run {run_id} not found")
    events = (
        db.query(RunEvent)
        .filter_by(run_id=run_id)
        .order_by(RunEvent.timestamp.asc())
        .all()
    )
    return {
        "run_id": run_id,
        "events": [
            {
                "event_type": e.event_type.value,
                "timestamp": e.timestamp.isoformat(),
                "detail": e.detail,
            }
            for e in events
        ],
    }


@app.get("/api/v1/integrations", tags=["integrations"], dependencies=[Depends(get_current_role)])
async def list_integrations():
    """Honest status of outbound integrations."""
    return {
        "github": {
            "webhook": {
                "configured": bool(os.environ.get("CLCA_GITHUB_WEBHOOK_SECRET")),
                "endpoint": "/v1/webhooks/github",
                "algorithm": "HMAC-SHA256 (X-Hub-Signature-256)",
                "accepts": "pull_request: opened|synchronize|reopened|ready_for_review",
                "clones_repositories": False,
            },
            "checks_api": {
                "token_present": bool(os.environ.get("GITHUB_TOKEN")),
                "endpoint": f"{os.environ.get('GITHUB_API_BASE', 'https://api.github.com')}/repos/{{owner}}/{{repo}}/check-runs",
            },
        },
        "cli": {"command": "clca run --repo . [--github-repo owner/name]"},
    }


# ---------------------------------------------------------------------------
# Custom OpenAPI + docs
# ---------------------------------------------------------------------------

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )
    openapi_schema["info"]["contact"] = {"name": "CLCA Platform Team"}
    openapi_schema["info"]["license"] = {"name": "Proprietary"}
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi


@app.get("/api/v1/docs", include_in_schema=False)
async def swagger_ui_html():
    return get_swagger_ui_html(
        openapi_url="/api/v1/openapi.json",
        title=f"{app.title} - Swagger UI",
        oauth2_redirect_url=None,
        swagger_js_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js",
        swagger_css_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css",
    )


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

@app.on_event("startup")
async def startup():
    create_db_and_tables()
    print(f"clca.api: starting on {os.environ.get('HOST', '0.0.0.0')}:{os.environ.get('PORT', '8000')}")
