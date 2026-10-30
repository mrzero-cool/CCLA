"""OpenTelemetry observability for CLCA (P2.3).

Provides correlated traces, metrics, and structured logs for every run:
webhook/intake → snapshot → adapter extraction → graph traversal → planner
→ each check → bundle creation → evidence verification → GitHub reporting.

Usage:
    from clca.observability import init_observability, get_tracer, get_meter

    init_observability(service_name="clca-control-plane")
    tracer = get_tracer()
    with tracer.start_as_current_span("run.verify") as span:
        span.set_attribute("run.id", run_id)
        ...
"""
from __future__ import annotations

import logging
import os
from typing import Any

from opentelemetry import metrics, trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.trace import Status, StatusCode

logger = logging.getLogger("clca.observability")

_tracer: Any | None = None
_meter: Any | None = None
_initialized: bool = False


def init_observability(
    service_name: str = "clca-control-plane",
    service_version: str = "0.4.0",
    otlp_endpoint: str | None = None,
    enable_console: bool = True,
) -> None:
    """Initialize OpenTelemetry tracing and metrics.

    Reads OTEL_EXPORTER_OTLP_ENDPOINT from env if otlp_endpoint not given.
    If no OTLP endpoint is configured, spans/metrics are still created but
    not exported (no-op exporters), so the code works without a collector.
    """
    global _tracer, _meter, _initialized

    if _initialized:
        return

    otlp_endpoint = otlp_endpoint or os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")

    resource = Resource.create(
        {
            "service.name": service_name,
            "service.version": service_version,
            "service.instance.id": os.environ.get("HOSTNAME", "unknown"),
        }
    )

    # ---- Tracing ----
    trace_provider = TracerProvider(resource=resource)
    if otlp_endpoint:
        otlp_exporter = OTLPSpanExporter(endpoint=otlp_endpoint)
        trace_provider.add_span_processor(BatchSpanProcessor(otlp_exporter))
        logger.info("OTLP trace exporter configured: %s", otlp_endpoint)
    else:
        logger.info("No OTLP endpoint configured; traces recorded but not exported")

    trace.set_tracer_provider(trace_provider)
    _tracer = trace.get_tracer(service_name, service_version)

    # ---- Metrics ----
    metric_reader = None
    if otlp_endpoint:
        metric_exporter = OTLPMetricExporter(endpoint=otlp_endpoint)
        metric_reader = PeriodicExportingMetricReader(metric_exporter)
        logger.info("OTLP metric exporter configured: %s", otlp_endpoint)

    meter_provider = MeterProvider(resource=resource, metric_readers=[metric_reader] if metric_reader else [])
    metrics.set_meter_provider(meter_provider)
    _meter = metrics.get_meter(service_name, service_version)

    _initialized = True
    logger.info("Observability initialized: service=%s version=%s", service_name, service_version)


def get_tracer() -> Any:
    """Get the OpenTelemetry tracer. Returns a no-op tracer if not initialized."""
    if _tracer is None:
        # Return a no-op tracer so code using it doesn't crash before init
        from opentelemetry.trace import NoOpTracer

        return NoOpTracer()
    return _tracer


def get_meter() -> Any:
    """Get the OpenTelemetry meter. Returns a no-op meter if not initialized."""
    if _meter is None:
        from opentelemetry.metrics import NoOpMeter

        return NoOpMeter()
    return _meter


def create_span(name: str, attributes: dict[str, Any] | None = None) -> Any:
    """Start a span with optional attributes. Context manager compatible."""
    tracer = get_tracer()
    span = tracer.start_span(name)
    if attributes:
        for key, value in attributes.items():
            span.set_attribute(key, value)
    return span


def set_span_status(span: Any, status: str = "ok", message: str | None = None) -> None:
    """Set span status to ok or error."""
    if status == "error":
        span.set_status(Status(StatusCode.ERROR, message or ""))
    else:
        span.set_status(Status(StatusCode.OK))


# ---------------------------------------------------------------------------
# Common span attribute keys (consistent naming across the codebase)
# ---------------------------------------------------------------------------

class SpanAttrs:
    RUN_ID = "run.id"
    SCENARIO_ID = "scenario.id"
    REPOSITORY = "repository"
    BASE_REVISION = "base.revision"
    HEAD_REVISION = "head.revision"
    DECISION = "clca.decision"
    CHECK_ID = "check.id"
    CHECK_STATUS = "check.status"
    CHECK_EXIT_CODE = "check.exit_code"
    CHECK_DURATION_MS = "check.duration_ms"
    ADAPTER_NAME = "adapter.name"
    POLICY_ID = "policy.id"
    POLICY_VERSION = "policy.version"
    BUNDLE_DIGEST = "bundle.digest"
    MANDATORY_CHECKS_TOTAL = "mandatory.checks.total"
    MANDATORY_CHECKS_SATISFIED = "mandatory.checks.satisfied"
    COVERAGE_GAPS = "coverage.gaps"
    BLOCKING_GAPS = "coverage.gaps.blocking"
    BUDGET_SECONDS = "budget.seconds"
